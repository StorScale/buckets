// Copy into MinIO's cmd/ package and run:
//   go test -run TestBucketsConfigDump ./cmd/ > config.json
// It prints MinIO's config registry (subsystems, keys, defaults, help) for
// tools/configgen/gen.py.
package cmd

import (
	"encoding/json"
	"os"
	"sort"
	"testing"

	"github.com/minio/minio/internal/config"
)

func TestBucketsConfigDump(t *testing.T) {
	globalIsErasure = true
	initHelp()
	type key struct {
		Key, Default, Type, Description         string
		HiddenIfEmpty, Optional, Sensitive, Secret bool
	}
	type sub struct {
		Name, Description                        string
		MultipleTargets, Dynamic, SingleTarget bool
		Keys                                     []key
	}
	var subs []sub
	desc := map[string]config.HelpKV{}
	names := []string{} // HelpSubSysMap[""] order: how MinIO lists and exports subsystems
	for _, h := range config.HelpSubSysMap[""] {
		desc[h.Key] = h
		if _, ok := config.DefaultKVS[h.Key]; ok {
			names = append(names, h.Key)
		}
	}
	rest := []string{} // registered without help (deprecated): after the rest
	for n := range config.DefaultKVS {
		if _, ok := desc[n]; !ok {
			rest = append(rest, n)
		}
	}
	sort.Strings(rest)
	names = append(names, rest...)
	for _, n := range names {
		s := sub{Name: n, Description: desc[n].Description, MultipleTargets: desc[n].MultipleTargets,
			Dynamic: config.SubSystemsDynamic.Contains(n), SingleTarget: config.SubSystemsSingleTargets.Contains(n)}
		help := config.HelpSubSysMap[n]
		for _, kv := range config.DefaultKVS[n] {
			h, _ := help.Lookup(kv.Key)
			s.Keys = append(s.Keys, key{Key: kv.Key, Default: kv.Value, HiddenIfEmpty: kv.HiddenIfEmpty, Type: h.Type,
				Description: h.Description, Optional: h.Optional, Sensitive: h.Sensitive, Secret: h.Secret})
		}
		subs = append(subs, s)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	if err := enc.Encode(subs); err != nil {
		t.Fatal(err)
	}
}
