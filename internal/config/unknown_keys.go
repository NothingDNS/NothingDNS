package config

import (
	"reflect"
	"strings"

	"github.com/nothingdns/nothingdns/internal/util"
)

// Unknown-key detection below the document root.
//
// unmarshalToConfig already warns about unrecognised TOP-LEVEL sections,
// because "silently ignoring them means an operator can deploy a 'validated'
// config that does the wrong thing". That reasoning does not stop at depth 1,
// but the check did. A key one level down was dropped without a word:
//
//	server:
//	  listen: "127.0.0.1"   # not a key this loader knows — the key is `bind`
//	  port: 53
//
// `nothingdns -validate-config` reported that file as valid, and the daemon
// bound every interface. An operator who meant to expose the resolver to
// loopback only got it exposed to the whole network instead, with recursion
// enabled — an open resolver, silently.
//
// The known-key set is derived from the config structs' own yaml tags rather
// than a hand-maintained list, so it cannot drift away from what the loader
// actually reads.

// warnUnknownNestedKeys walks the parsed document against the Config struct
// and warns about every key inside a known section that no field receives.
//
// The document root is NOT re-checked here: unmarshalToConfig owns that, with
// its own distinction between typos and stale-but-documented sections.
func warnUnknownNestedKeys(root *Node, cfgType reflect.Type) {
	if root == nil || root.Type != NodeMapping {
		return
	}
	fields := yamlFields(cfgType)
	for _, key := range root.Keys() {
		ft, ok := fields[key]
		if !ok {
			continue // top-level unknowns are reported by unmarshalToConfig
		}
		child := root.Get(key)
		if child == nil || child.Type != NodeMapping {
			continue
		}
		walkUnknownKeys(child, key, ft)
	}
}

// walkUnknownKeys reports keys in node that have no counterpart in t, then
// descends into every child mapping whose field is itself a struct.
func walkUnknownKeys(node *Node, path string, t reflect.Type) {
	t = derefType(t)
	if t.Kind() != reflect.Struct {
		return
	}
	fields := yamlFields(t)
	for _, key := range node.Keys() {
		ft, ok := fields[key]
		if !ok {
			util.Warnf("config: unknown key %q in section %q — ignored (typo?)", key, path)
			continue
		}
		child := node.Get(key)
		if child == nil || child.Type != NodeMapping {
			continue
		}
		// A mapping received by a Go map has operator-chosen keys (view
		// names, user names, ...), so there is nothing to check it against.
		if derefType(ft).Kind() == reflect.Map {
			continue
		}
		walkUnknownKeys(child, path+"."+key, ft)
	}
}

// yamlFields maps a struct's yaml tag names to the field types behind them.
// Fields tagged "-" and untagged fields are not reachable from YAML and are
// therefore not valid keys.
func yamlFields(t reflect.Type) map[string]reflect.Type {
	t = derefType(t)
	out := make(map[string]reflect.Type)
	if t.Kind() != reflect.Struct {
		return out
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("yaml")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			continue
		}
		out[name] = f.Type
	}
	return out
}

func derefType(t reflect.Type) reflect.Type {
	for t != nil && (t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice) {
		t = t.Elem()
	}
	return t
}
