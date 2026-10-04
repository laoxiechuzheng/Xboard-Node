package main

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const syntheticTaskSource = `package task

import (
	"context"
)

type semaphore struct {
	wait <-chan struct{}
}

func (s semaphore) Wait() <-chan struct{} { return s.wait }

func Run(ctx context.Context, tasks ...func() error) error {
	wait := make(chan struct{})
	close(wait)
	s := semaphore{wait: wait}
	results := make(chan error, len(tasks))
	for _, task := range tasks {
		<-s.Wait()
		go func(f func() error) {
			err := f()
			results <- err
		}(task)
	}
	for range tasks {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-results:
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Other task helpers must remain unchanged.
func OnSuccess(ctx context.Context, f func() error) error {
	return f()
}
`

const syntheticOutboundSource = `package outbound

import (
	"context"
)

func Process(ctx context.Context) {
	newCtx, newCancel := context.WithCancel(context.Background())
	defer newCancel()
	_ = newCtx
	// context.WithCancel(context.Background()) must not be patched in a comment.
	_ = "context.WithCancel(context.Background())"
}
`

func TestPatchTaskSourceRegistersBeforeLaunchAndDefersFinish(t *testing.T) {
	patched, err := patchTaskSource([]byte(syntheticTaskSource))
	if err != nil {
		t.Fatalf("patchTaskSource: %v", err)
	}
	file := parseSource(t, patched)
	var run *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "Run" {
			run = fn
		}
	}
	if run == nil || !strings.Contains(string(patched), `ctx.Value("xboard.node.shared-reality.tasks")`) {
		t.Fatal("Run must read the shared REALITY task observer from its context")
	}
	var launch *ast.GoStmt
	startedBeforeLaunch := false
	for _, stmt := range run.Body.List {
		loop, ok := stmt.(*ast.RangeStmt)
		if !ok {
			continue
		}
		for _, bodyStmt := range loop.Body.List {
			if goStmt, ok := bodyStmt.(*ast.GoStmt); ok {
				launch = goStmt
				break
			}
			if hasMethodCall(bodyStmt, "TaskStarted") {
				startedBeforeLaunch = true
			}
		}
		if launch != nil {
			break
		}
	}
	if launch == nil || !startedBeforeLaunch {
		t.Fatal("TaskStarted must run synchronously before the task goroutine launch")
	}
	fn, ok := launch.Call.Fun.(*ast.FuncLit)
	if !ok || len(fn.Body.List) == 0 {
		t.Fatal("task launch must keep its function body")
	}
	deferredFinish := false
	ast.Inspect(fn.Body.List[0], func(node ast.Node) bool {
		if stmt, ok := node.(*ast.DeferStmt); ok && hasMethodCall(stmt, "TaskFinished") {
			deferredFinish = true
		}
		return true
	})
	if !deferredFinish {
		t.Fatal("the first goroutine statement must defer TaskFinished when an observer is present")
	}
	otherFunctions := syntheticTaskSource[strings.Index(syntheticTaskSource, "// Other task helpers"):]
	if !strings.Contains(string(patched), otherFunctions) {
		t.Fatal("patch changed unrelated task functions")
	}
}

func TestPatchTaskSourceRejectsMissingOrDuplicateNeedle(t *testing.T) {
	needle := "for _, task := range tasks {\n\t\t<-s.Wait()\n\t\tgo func(f func() error) {\n\t\t\terr := f()"
	tests := map[string]string{
		"missing":   strings.Replace(syntheticTaskSource, "<-s.Wait()", "<-s.Wait();", 1),
		"duplicate": syntheticTaskSource + "\n/*\n" + needle + "\n*/\n",
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := patchTaskSource([]byte(source)); err == nil {
				t.Fatal("source drift must fail instead of guessing a task.Run rewrite")
			}
		})
	}
}

func TestPatchTaskSourceGeneratedContextAndObserverBehavior(t *testing.T) {
	patched, err := patchTaskSource([]byte(syntheticTaskSource))
	if err != nil {
		t.Fatalf("patchTaskSource: %v", err)
	}
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "go.mod"), []byte("module overlayfixture\n\ngo 1.26\n"))
	writeFixture(t, filepath.Join(dir, "task.go"), patched)
	writeFixture(t, filepath.Join(dir, "task_test.go"), []byte(generatedTaskBehaviorTests))
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "test", "-count=1", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=", "GOTOOLCHAIN=local")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated task behavior failed: %v\n%s", err, output)
	}
}

const generatedTaskBehaviorTests = `package task

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDetachContextKeepsOnlyObserver(t *testing.T) {
	const key = "xboard.node.shared-reality.tasks"
	marker := &struct{}{}
	base := context.WithValue(context.Background(), "unrelated", "must not survive")
	base = context.WithValue(base, key, marker)
	ctx, cancel := context.WithDeadline(base, time.Unix(0, 0))
	defer cancel()
	got := DetachContext(ctx)
	if got.Value(key) != marker || got.Value("unrelated") != nil {
		t.Fatal("detached context must preserve exactly the observer key")
	}
	if _, ok := got.Deadline(); ok || got.Done() != nil || got.Err() != nil {
		t.Fatal("detached context must not inherit cancellation or deadline")
	}
	if got := DetachContext(context.WithValue(ctx, key, nil)); got != context.Background() {
		t.Fatal("a nil observer must keep the original Background context behavior")
	}
}

type observer struct {
	started atomic.Int64
	finished atomic.Int64
	done chan struct{}
}

func (o *observer) TaskStarted() { o.started.Add(1) }
func (o *observer) TaskFinished() {
	o.finished.Add(1)
	close(o.done)
}

func TestRunPreservesCancellationAndCompletesObserverLater(t *testing.T) {
	obs := &observer{done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), "xboard.node.shared-reality.tasks", obs))
	defer cancel()
	entered := make(chan struct{})
	resume := make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(resume) })
	result := make(chan error, 1)
	go func() {
		result <- Run(ctx, func() error {
			if obs.started.Load() != 1 {
				return errors.New("task body ran before observer registration")
			}
			close(entered)
			<-resume
			return nil
		})
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("task did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run must preserve early cancellation return")
	}
	if obs.finished.Load() != 0 {
		t.Fatal("observer finished before the blocked task exited")
	}
	release.Do(func() { close(resume) })
	select {
	case <-obs.done:
	case <-time.After(5 * time.Second):
		t.Fatal("observer did not finish after the task exited")
	}
	if obs.started.Load() != 1 || obs.finished.Load() != 1 {
		t.Fatal("observer callbacks must balance exactly once")
	}
}

func TestRunWithoutObserverKeepsErrorBehavior(t *testing.T) {
	want := errors.New("native task error")
	if got := Run(context.Background(), func() error { return want }); got != want {
		t.Fatalf("Run error = %v, want the original task error", got)
	}
	if err := Run(context.Background(), func() error { return nil }); err != nil {
		t.Fatalf("ordinary Run: %v", err)
	}
}
`

func TestPatchOutboundSourceRetainsObserverAndAddsImport(t *testing.T) {
	tests := map[string]string{
		"add_import":      syntheticOutboundSource,
		"existing_import": strings.Replace(syntheticOutboundSource, "\t\"context\"\n", "\t\"context\"\n\t\"github.com/xtls/xray-core/common/task\"\n", 1),
		"discard_cancel":  strings.Replace(syntheticOutboundSource, "newCtx, newCancel := context.WithCancel(context.Background())\n\tdefer newCancel()\n\t_ = newCtx", "ctx, _ = context.WithCancel(context.Background())\n\t_ = ctx", 1),
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			patched, err := patchOutboundSource([]byte(source))
			if err != nil {
				t.Fatalf("patchOutboundSource: %v", err)
			}
			file := parseSource(t, patched)
			imports := 0
			for _, spec := range file.Imports {
				if spec.Path.Value == `"github.com/xtls/xray-core/common/task"` {
					imports++
				}
			}
			if imports != 1 {
				t.Fatalf("task imports = %d, want exactly one", imports)
			}
			calls := 0
			ast.Inspect(file, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok || !isSelector(call.Fun, "context", "WithCancel") {
					return true
				}
				calls++
				if len(call.Args) != 1 {
					t.Fatal("WithCancel argument changed unexpectedly")
				}
				detached, ok := call.Args[0].(*ast.CallExpr)
				if !ok || !isSelector(detached.Fun, "task", "DetachContext") || len(detached.Args) != 1 {
					t.Fatal("outbound WithCancel must detach while preserving the observer")
				}
				if ctx, ok := detached.Args[0].(*ast.Ident); !ok || ctx.Name != "ctx" {
					t.Fatal("DetachContext must use the outbound ctx")
				}
				return true
			})
			if calls != 1 {
				t.Fatalf("patched cancellation calls = %d, want 1", calls)
			}
			if !strings.Contains(string(patched), `// context.WithCancel(context.Background()) must not be patched in a comment.`) || !strings.Contains(string(patched), `"context.WithCancel(context.Background())"`) {
				t.Fatal("patch changed a comment or a string literal")
			}
		})
	}
}

func TestPatchOutboundSourceRejectsDriftAndAmbiguousImports(t *testing.T) {
	tests := map[string]string{
		"no_actual_call":         strings.Replace(syntheticOutboundSource, "context.WithCancel(context.Background())", "context.WithCancel(ctx)", 1),
		"multiple_import_blocks": strings.Replace(syntheticOutboundSource, ")\n\nfunc Process", ")\nimport (\n\t\"errors\"\n)\n\nfunc Process", 1),
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := patchOutboundSource([]byte(source)); err == nil {
				t.Fatal("unsafe outbound source shape must be rejected")
			}
		})
	}
}

func TestReplacementDirUsesPinnedReplacement(t *testing.T) {
	dir := t.TempDir()
	source := moduleFixture(t, dir, "v1.260327.0-laoxie.1")
	got, err := replacementDir(source)
	if err != nil {
		t.Fatalf("replacementDir: %v", err)
	}
	if got != dir {
		t.Fatalf("module directory = %q, want replacement directory %q", got, dir)
	}
}

func TestReplacementDirRejectsUnlockedDependency(t *testing.T) {
	dir := t.TempDir()
	tests := map[string][]byte{
		"wrong_version":      moduleFixture(t, dir, "v1.260327.0-laoxie.2"),
		"relative_directory": moduleFixture(t, "relative/module", "v1.260327.0-laoxie.1"),
		"no_replacement":     []byte(`{"Path":"github.com/xtls/xray-core","Version":"v1.260327.0"}`),
		"invalid_json":       []byte("{"),
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := replacementDir(source); err == nil {
				t.Fatal("unlocked or invalid module information must be rejected")
			}
		})
	}
}

func TestGenerateOverlayKeepsDependencyUntouchedAndSkipsTun(t *testing.T) {
	project := t.TempDir()
	dependency := t.TempDir()
	originals := dependencyFixture(t, dependency)
	manifestPath, err := generateOverlay(project, dependency)
	if err != nil {
		t.Fatalf("generateOverlay: %v", err)
	}
	wantPath := filepath.Join(project, ".xray-task-overlay", "overlay.json")
	if manifestPath != wantPath {
		t.Fatalf("overlay path = %q, want %q", manifestPath, wantPath)
	}
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var overlay struct {
		Replace map[string]string
	}
	if err := json.Unmarshal(manifest, &overlay); err != nil {
		t.Fatal(err)
	}
	if len(overlay.Replace) != 12 {
		t.Fatalf("overlay mappings = %d, want task plus 11 outbound files", len(overlay.Replace))
	}
	for source, original := range originals {
		current, err := os.ReadFile(source)
		if err != nil || !bytes.Equal(current, original) {
			t.Fatalf("dependency source was modified: %s, err=%v", source, err)
		}
		mapped, ok := overlay.Replace[source]
		if source == filepath.Join(dependency, "proxy", "tun", "inbound.go") {
			if ok {
				t.Fatal("tun inbound background goroutines must not be overlaid")
			}
			continue
		}
		if !ok || !filepath.IsAbs(source) || !filepath.IsAbs(mapped) {
			t.Fatalf("mapping must use absolute source and generated paths: %q => %q", source, mapped)
		}
		rel, err := filepath.Rel(filepath.Join(project, ".xray-task-overlay"), mapped)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			t.Fatalf("generated file escaped overlay directory: %q", mapped)
		}
		generated, err := os.ReadFile(mapped)
		if err != nil || bytes.Equal(generated, original) {
			t.Fatalf("mapping lacks a patched generated source: %q, err=%v", mapped, err)
		}
		parseSource(t, generated)
	}
	taskSource := filepath.Join(dependency, "common", "task", "task.go")
	if overlay.Replace[taskSource] != filepath.Join(project, ".xray-task-overlay", "task.go") {
		t.Fatal("common/task/task.go must map to the generated task.go")
	}
	if _, err := generateOverlay(project, dependency); err != nil {
		t.Fatalf("repeat generation: %v", err)
	}
	repeated, err := os.ReadFile(manifestPath)
	if err != nil || !bytes.Equal(repeated, manifest) {
		t.Fatal("overlay generation must be repeatable from unchanged dependency sources")
	}
}

func TestGenerateOverlayRejectsDriftBeforePublishingManifest(t *testing.T) {
	project := t.TempDir()
	dependency := t.TempDir()
	dependencyFixture(t, dependency)
	writeFixture(t, filepath.Join(dependency, "common", "task", "task.go"), []byte("package task\n"))
	if _, err := generateOverlay(project, dependency); err == nil {
		t.Fatal("drifted task source must reject overlay generation")
	}
	if _, err := os.Stat(filepath.Join(project, ".xray-task-overlay", "overlay.json")); !os.IsNotExist(err) {
		t.Fatalf("failed generation must not publish an overlay manifest: %v", err)
	}
}

func TestPrepareBuildModuleStagesLockedSourceWithoutChangingProject(t *testing.T) {
	project, dependency := t.TempDir(), t.TempDir()
	module := []byte("module fixture\n\ngo 1.26\n\nrequire github.com/xtls/xray-core v1.260327.0\n\nreplace github.com/xtls/xray-core => github.com/laoxiechuzheng/Xray-core v1.260327.0-laoxie.1\n")
	sum := []byte("github.com/example/module v1.0.0 h1:fixture\n")
	writeFixture(t, filepath.Join(project, "go.mod"), module)
	writeFixture(t, filepath.Join(project, "go.sum"), sum)
	writeFixture(t, filepath.Join(dependency, "common", "task", "task.go"), []byte(syntheticTaskSource))
	shadow, err := prepareBuildModule(project, dependency)
	if err != nil {
		t.Fatalf("stage build module: %v", err)
	}
	root := filepath.Join(project, ".xray-task-overlay")
	rel, err := filepath.Rel(root, shadow)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || !filepath.IsAbs(shadow) {
		t.Fatalf("shadow source escaped output directory: %q", shadow)
	}
	for _, name := range []string{"go.mod", "go.sum"} {
		original, readErr := os.ReadFile(filepath.Join(project, name))
		want := module
		if name == "go.sum" {
			want = sum
		}
		if readErr != nil || !bytes.Equal(original, want) {
			t.Fatalf("project %s changed: %v", name, readErr)
		}
	}
	for _, dir := range []string{dependency, shadow} {
		copied, err := os.ReadFile(filepath.Join(dir, "common", "task", "task.go"))
		if err != nil || !bytes.Equal(copied, []byte(syntheticTaskSource)) {
			t.Fatalf("original or shadow source changed: %s, err=%v", dir, err)
		}
	}
	generatedSum, err := os.ReadFile(filepath.Join(root, "build.sum"))
	if err != nil || !bytes.Equal(generatedSum, sum) {
		t.Fatalf("generated sum does not preserve pins: %v", err)
	}
	cmd := exec.Command("go", "mod", "edit", "-modfile="+filepath.Join(root, "build.mod"), "-json")
	cmd.Dir = project
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("read generated module: %v", err)
	}
	var generated struct {
		Replace []struct {
			Old struct{ Path, Version string }
			New struct{ Path, Version string }
		}
	}
	if err := json.Unmarshal(output, &generated); err != nil || len(generated.Replace) != 1 || generated.Replace[0].Old.Path != xrayModulePath || generated.Replace[0].New.Path != shadow || generated.Replace[0].New.Version != "" {
		t.Fatalf("generated module does not select the shadow source: %s, err=%v", output, err)
	}
	second, err := prepareBuildModule(project, dependency)
	if err != nil || second == shadow {
		t.Fatalf("repeat staging must produce a fresh source snapshot: %q, err=%v", second, err)
	}
}

func dependencyFixture(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{
		"common/task/task.go":  []byte(syntheticTaskSource),
		"proxy/tun/inbound.go": []byte(syntheticOutboundSource),
	}
	for _, path := range []string{
		"proxy/freedom/outbound.go", "proxy/vless/outbound/outbound.go",
		"proxy/vmess/outbound/outbound.go", "proxy/trojan/outbound.go",
		"proxy/shadowsocks/outbound.go", "proxy/http/outbound.go",
		"proxy/socks/outbound.go", "proxy/hysteria/outbound.go",
		"proxy/wireguard/outbound.go", "proxy/dns/outbound.go",
		"proxy/shadowsocks_2022/outbound.go",
	} {
		files[path] = []byte(syntheticOutboundSource)
	}
	originals := make(map[string][]byte, len(files))
	for relative, source := range files {
		path := filepath.Join(dir, filepath.FromSlash(relative))
		writeFixture(t, path, source)
		originals[path] = source
	}
	return originals
}

func moduleFixture(t *testing.T, dir, version string) []byte {
	t.Helper()
	info := map[string]any{
		"Path": "github.com/xtls/xray-core", "Version": "v1.260327.0", "Dir": "must-not-use-original-dir",
		"Replace": map[string]string{
			"Path": "github.com/laoxiechuzheng/Xray-core", "Version": version, "Dir": dir,
		},
	}
	source, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func parseSource(t *testing.T, source []byte) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, parser.ParseComments)
	if err != nil {
		t.Fatalf("invalid generated Go source: %v", err)
	}
	return file
}

func isSelector(expr ast.Expr, name, method string) bool {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != method {
		return false
	}
	ident, ok := selector.X.(*ast.Ident)
	return ok && ident.Name == name
}

func hasMethodCall(node ast.Node, method string) bool {
	found := false
	ast.Inspect(node, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == method {
				found = true
			}
		}
		return true
	})
	return found
}

func writeFixture(t *testing.T, path string, source []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, source, 0644); err != nil {
		t.Fatal(err)
	}
}
