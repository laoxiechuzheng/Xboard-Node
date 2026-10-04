package xray

import (
	"fmt"
	"sync"
	"time"

	xrayCore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
)

type sharedRealityGeneration struct {
	instance   *xrayCore.Instance
	dispatcher *LimitDispatcher
	runtime    *sharedRealityRuntime
	users      map[int]struct{}
	closeOnce  sync.Once
}

func (x *Xray) sharedUserIDsLocked() map[int]struct{} {
	if x.sharedStatsUsers == nil {
		x.sharedStatsUsers = make(map[int]struct{})
	}
	for _, user := range x.users {
		x.sharedStatsUsers[user.ID] = struct{}{}
	}
	ids := make(map[int]struct{}, len(x.sharedStatsUsers))
	for id := range x.sharedStatsUsers {
		ids[id] = struct{}{}
	}
	return ids
}

func (x *Xray) collectSharedRealityStatsLocked(instance *xrayCore.Instance, users map[int]struct{}) {
	if instance == nil {
		return
	}
	manager, ok := instance.GetFeature(stats.ManagerType()).(stats.Manager)
	if !ok {
		return
	}
	for id := range users {
		cumulative := x.cumTraffic[id]
		for i, direction := range []string{"uplink", "downlink"} {
			counter := manager.GetCounter(fmt.Sprintf("user>>>%s>>>traffic>>>%s", userEmail(id), direction))
			if counter != nil {
				cumulative[i] += counter.Set(0)
			}
		}
		if cumulative[0] > 0 || cumulative[1] > 0 {
			x.cumTraffic[id] = cumulative
		}
	}
}

func (x *Xray) aggregateSharedRealityStatsLocked() map[int][2]int64 {
	x.collectSharedRealityStatsLocked(x.instance, x.sharedUserIDsLocked())
	for _, generation := range x.sharedRetired {
		x.collectSharedRealityStatsLocked(generation.instance, generation.users)
	}
	traffic := make(map[int][2]int64, len(x.cumTraffic))
	for id, total := range x.cumTraffic {
		traffic[id] = total
	}
	return traffic
}

func (x *Xray) retireSharedReality(generation *sharedRealityGeneration) {
	if generation.runtime != nil {
		generation.runtime.wait(5 * time.Minute)
	} else if generation.dispatcher != nil {
		drainConns(generation.dispatcher, 5*time.Minute)
	}
	x.finishSharedRealityGeneration(generation)
}

func (x *Xray) finishSharedRealityGeneration(generation *sharedRealityGeneration) {
	generation.closeOnce.Do(func() {
		if generation.runtime != nil {
			generation.runtime.disableAndCloseConnections()
			// Copy tasks may publish their tail after Process returns. Do not
			// discard the stats manager until every native task has finished.
			generation.runtime.wait(0)
		} else if generation.dispatcher != nil {
			drainConns(generation.dispatcher, drainTimeout)
		}
		// Read final counters before Instance.Close clears the stats manager.
		x.mu.Lock()
		x.collectSharedRealityStatsLocked(generation.instance, generation.users)
		for i, candidate := range x.sharedRetired {
			if candidate == generation {
				x.sharedRetired = append(x.sharedRetired[:i], x.sharedRetired[i+1:]...)
				break
			}
		}
		x.mu.Unlock()
		generation.instance.Close()
		if generation.dispatcher != nil {
			generation.dispatcher.ResetConns()
		}
	})
}

func (x *Xray) stopSharedReality() {
	x.running.Store(false)
	x.mu.Lock()
	if x.instance != nil {
		x.sharedRetired = append(x.sharedRetired, &sharedRealityGeneration{
			instance: x.instance, dispatcher: x.limitDispatcher, runtime: x.sharedRuntime, users: x.sharedUserIDsLocked(),
		})
	}
	generations := append([]*sharedRealityGeneration(nil), x.sharedRetired...)
	x.instance = nil
	x.limitDispatcher = nil
	x.sharedRuntime = nil
	x.mu.Unlock()
	for _, generation := range generations {
		if generation.runtime != nil {
			if generation.runtime.lease != nil {
				generation.runtime.lease.Close()
			}
			generation.runtime.disableAndCloseConnections()
		}
	}
	for _, generation := range generations {
		x.finishSharedRealityGeneration(generation)
	}
}
