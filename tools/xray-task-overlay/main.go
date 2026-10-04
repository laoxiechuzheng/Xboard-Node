package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const (
	xrayModulePath         = "github.com/xtls/xray-core"
	xrayReplacementPath    = "github.com/laoxiechuzheng/Xray-core"
	xrayReplacementVersion = "v1.260327.0-laoxie.1"
	taskImportPath         = "github.com/xtls/xray-core/common/task"
	taskLaunchNeedle       = "for _, task := range tasks {\n\t\t<-s.Wait()\n\t\tgo func(f func() error) {\n\t\t\terr := f()"
	backgroundCancelNeedle = "context.WithCancel(context.Background())"
)

var outboundDirectories = []string{
	"proxy/freedom",
	"proxy/vless/outbound",
	"proxy/vmess/outbound",
	"proxy/trojan",
	"proxy/shadowsocks",
	"proxy/http",
	"proxy/socks",
	"proxy/hysteria",
	"proxy/wireguard",
	"proxy/dns",
	"proxy/shadowsocks_2022",
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "xray-task-overlay: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	projectDir, err := os.Getwd()
	if err != nil {
		return err
	}
	cmd := exec.Command("go", "list", "-mod=readonly", "-m", "-json", xrayModulePath)
	cmd.Dir = projectDir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	moduleJSON, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("resolve Xray module: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	dependencyDir, err := replacementDir(moduleJSON)
	if err != nil {
		return err
	}
	dependencyDir, err = prepareBuildModule(projectDir, dependencyDir)
	if err != nil {
		return err
	}
	manifestPath, err := generateOverlay(projectDir, dependencyDir)
	if err != nil {
		return err
	}
	fmt.Println(manifestPath)
	return nil
}

func prepareBuildModule(projectDir, dependencyDir string) (string, error) {
	projectDir, err := filepath.Abs(projectDir)
	if err != nil {
		return "", err
	}
	outputDir := filepath.Join(projectDir, ".xray-task-overlay")
	if err := os.Mkdir(outputDir, 0755); err != nil && !os.IsExist(err) {
		return "", err
	}
	info, err := os.Lstat(outputDir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("overlay output must be a regular directory: %s", outputDir)
	}
	// Go 1.26 rejects overlays beneath GOMODCACHE. Stage the locked source
	// and use a derived modfile without changing project pins or the cache.
	shadow, err := os.MkdirTemp(outputDir, "source-")
	if err != nil {
		return "", err
	}
	if err := os.CopyFS(shadow, os.DirFS(dependencyDir)); err != nil {
		return "", fmt.Errorf("stage locked Xray source: %w", err)
	}
	for _, pair := range [][2]string{{"go.mod", "build.mod"}, {"go.sum", "build.sum"}} {
		data, err := os.ReadFile(filepath.Join(projectDir, pair[0]))
		if err != nil {
			return "", err
		}
		if err := writeOverlayFile(filepath.Join(outputDir, pair[1]), data); err != nil {
			return "", err
		}
	}
	cmd := exec.Command("go", "mod", "edit", "-modfile="+filepath.Join(outputDir, "build.mod"), "-replace="+xrayModulePath+"="+shadow)
	cmd.Dir = projectDir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=")
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("prepare Xray build modfile: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return shadow, nil
}

func patchTaskSource(source []byte) ([]byte, error) {
	if count := bytes.Count(source, []byte(taskLaunchNeedle)); count != 1 {
		return nil, fmt.Errorf("task.Run launch needle must occur exactly once, got %d", count)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "task.go", source, 0)
	if err != nil {
		return nil, err
	}
	var run *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Name.Name == "DetachContext" {
			return nil, fmt.Errorf("task source already declares DetachContext")
		}
		if fn.Name.Name == "Run" {
			if run != nil {
				return nil, fmt.Errorf("task source has multiple Run declarations")
			}
			run = fn
		}
	}
	if file.Name.Name != "task" || run == nil || run.Body == nil || len(run.Type.Params.List) == 0 || len(run.Type.Params.List[0].Names) != 1 || run.Type.Params.List[0].Names[0].Name != "ctx" {
		return nil, fmt.Errorf("task.Run context signature does not match the pinned source")
	}
	bodyStart := fset.Position(run.Body.Lbrace).Offset + 1
	bodyEnd := fset.Position(run.Body.Rbrace).Offset
	needleStart := bytes.Index(source, []byte(taskLaunchNeedle))
	if needleStart < bodyStart || needleStart+len(taskLaunchNeedle) > bodyEnd {
		return nil, fmt.Errorf("task launch needle is outside task.Run")
	}
	observer := "\n\tobserver, _ := ctx.Value(\"xboard.node.shared-reality.tasks\").(interface {\n\t\tTaskStarted()\n\t\tTaskFinished()\n\t})\n"
	launch := "for _, task := range tasks {\n\t\t<-s.Wait()\n\t\tif observer != nil {\n\t\t\tobserver.TaskStarted()\n\t\t}\n\t\tgo func(f func() error) {\n\t\t\tif observer != nil {\n\t\t\t\tdefer observer.TaskFinished()\n\t\t\t}\n\t\t\terr := f()"
	detach := "\nfunc DetachContext(ctx context.Context) context.Context {\n\tbase := context.Background()\n\tif value := ctx.Value(\"xboard.node.shared-reality.tasks\"); value != nil {\n\t\treturn context.WithValue(base, \"xboard.node.shared-reality.tasks\", value)\n\t}\n\treturn base\n}\n"
	return applySourceEdits(source, []sourceEdit{
		{start: bodyStart, end: bodyStart, text: observer},
		{start: needleStart, end: needleStart + len(taskLaunchNeedle), text: launch},
		{start: len(source), end: len(source), text: detach},
	})
}

func patchOutboundSource(source []byte) ([]byte, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "outbound.go", source, 0)
	if err != nil {
		return nil, err
	}
	var imports *ast.GenDecl
	for _, decl := range file.Decls {
		if decl, ok := decl.(*ast.GenDecl); ok && decl.Tok == token.IMPORT {
			if imports != nil {
				return nil, fmt.Errorf("outbound source must have exactly one import block")
			}
			imports = decl
		}
	}
	if imports == nil || !imports.Lparen.IsValid() {
		return nil, fmt.Errorf("outbound source must have exactly one import block")
	}
	taskName := "task"
	hasTaskImport := false
	for _, spec := range file.Imports {
		if spec.Path.Value != fmt.Sprintf("%q", taskImportPath) {
			continue
		}
		if hasTaskImport {
			return nil, fmt.Errorf("outbound source has duplicate task imports")
		}
		hasTaskImport = true
		if spec.Name != nil {
			if spec.Name.Name == "." || spec.Name.Name == "_" {
				return nil, fmt.Errorf("outbound task import cannot be dot or blank")
			}
			taskName = spec.Name.Name
		}
	}
	calls := backgroundCancelCalls(file)
	if len(calls) == 0 {
		return nil, fmt.Errorf("outbound source has no pinned background cancellation call")
	}
	edits := make([]sourceEdit, 0, len(calls)+1)
	for _, call := range calls {
		start := fset.Position(call.Pos()).Offset
		end := fset.Position(call.End()).Offset
		if string(source[start:end]) != backgroundCancelNeedle {
			return nil, fmt.Errorf("outbound cancellation call does not match the pinned source")
		}
		edits = append(edits, sourceEdit{
			start: start, end: end,
			text: "context.WithCancel(" + taskName + ".DetachContext(ctx))",
		})
	}
	if !hasTaskImport {
		offset := fset.Position(imports.Rparen).Offset
		edits = append(edits, sourceEdit{start: offset, end: offset, text: "\n\t\"" + taskImportPath + "\"\n"})
	}
	return applySourceEdits(source, edits)
}

func replacementDir(moduleJSON []byte) (string, error) {
	var module struct {
		Path    string
		Replace *struct {
			Path    string
			Version string
			Dir     string
		}
	}
	if err := json.Unmarshal(moduleJSON, &module); err != nil {
		return "", fmt.Errorf("decode Xray module: %w", err)
	}
	if module.Path != xrayModulePath || module.Replace == nil {
		return "", fmt.Errorf("Xray must use the pinned replacement module")
	}
	if module.Replace.Path != xrayReplacementPath || module.Replace.Version != xrayReplacementVersion {
		return "", fmt.Errorf("Xray replacement must be %s@%s", xrayReplacementPath, xrayReplacementVersion)
	}
	if !filepath.IsAbs(module.Replace.Dir) {
		return "", fmt.Errorf("Xray replacement source directory must be absolute")
	}
	return filepath.Clean(module.Replace.Dir), nil
}

func generateOverlay(projectDir, dependencyDir string) (string, error) {
	projectDir, err := filepath.Abs(projectDir)
	if err != nil {
		return "", err
	}
	dependencyDir, err = filepath.Abs(dependencyDir)
	if err != nil {
		return "", err
	}
	taskPath := filepath.Join(dependencyDir, "common", "task", "task.go")
	source, err := os.ReadFile(taskPath)
	if err != nil {
		return "", err
	}
	patched, err := patchTaskSource(source)
	if err != nil {
		return "", fmt.Errorf("%s: %w", taskPath, err)
	}
	type generatedFile struct {
		source string
		name   string
		data   []byte
	}
	files := []generatedFile{{source: taskPath, name: "task.go", data: patched}}
	for _, relativeDir := range outboundDirectories {
		dir := filepath.Join(dependencyDir, filepath.FromSlash(relativeDir))
		entries, err := os.ReadDir(dir)
		if err != nil {
			return "", err
		}
		matched := 0
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			source, err := os.ReadFile(path)
			if err != nil {
				return "", err
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
			if err != nil {
				return "", err
			}
			if len(backgroundCancelCalls(file)) == 0 {
				continue
			}
			patched, err := patchOutboundSource(source)
			if err != nil {
				return "", fmt.Errorf("%s: %w", path, err)
			}
			name := fmt.Sprintf("outbound-%02d-%s", len(files), entry.Name())
			files = append(files, generatedFile{source: path, name: name, data: patched})
			matched++
		}
		if matched == 0 {
			return "", fmt.Errorf("%s has no pinned outbound cancellation call", relativeDir)
		}
	}

	// Validate all dependency sources before writing generated files or the manifest.
	outputDir := filepath.Join(projectDir, ".xray-task-overlay")
	if err := os.Mkdir(outputDir, 0755); err != nil && !os.IsExist(err) {
		return "", err
	}
	info, err := os.Lstat(outputDir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("overlay output must be a regular directory: %s", outputDir)
	}
	overlay := struct {
		Replace map[string]string
	}{Replace: make(map[string]string, len(files))}
	for _, file := range files {
		path := filepath.Join(outputDir, file.name)
		if err := writeOverlayFile(path, file.data); err != nil {
			return "", err
		}
		overlay.Replace[file.source] = path
	}
	manifest, err := json.MarshalIndent(overlay, "", "  ")
	if err != nil {
		return "", err
	}
	manifestPath := filepath.Join(outputDir, "overlay.json")
	if err := writeOverlayFile(manifestPath, append(manifest, '\n')); err != nil {
		return "", err
	}
	return manifestPath, nil
}

func backgroundCancelCalls(file *ast.File) []*ast.CallExpr {
	var calls []*ast.CallExpr
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || !selectorIs(call.Fun, "context", "WithCancel") || len(call.Args) != 1 {
			return true
		}
		background, ok := call.Args[0].(*ast.CallExpr)
		if ok && selectorIs(background.Fun, "context", "Background") && len(background.Args) == 0 {
			calls = append(calls, call)
		}
		return true
	})
	return calls
}

func selectorIs(expr ast.Expr, name, method string) bool {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != method {
		return false
	}
	ident, ok := selector.X.(*ast.Ident)
	return ok && ident.Name == name
}

type sourceEdit struct {
	start int
	end   int
	text  string
}

func applySourceEdits(source []byte, edits []sourceEdit) ([]byte, error) {
	sort.Slice(edits, func(i, j int) bool { return edits[i].start < edits[j].start })
	var output bytes.Buffer
	cursor := 0
	for _, edit := range edits {
		if edit.start < cursor || edit.end < edit.start || edit.end > len(source) {
			return nil, fmt.Errorf("overlapping or invalid source edit")
		}
		output.Write(source[cursor:edit.start])
		output.WriteString(edit.text)
		cursor = edit.end
	}
	output.Write(source[cursor:])
	patched := output.Bytes()
	if _, err := parser.ParseFile(token.NewFileSet(), "generated.go", patched, 0); err != nil {
		return nil, fmt.Errorf("invalid generated source: %w", err)
	}
	return patched, nil
}

func writeOverlayFile(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".overlay-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Chmod(0644); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
