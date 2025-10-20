package main

import (
	"fmt"
	"reflect"
	"sync"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/decls"
	"github.com/google/cel-go/common/types"
	"golang.org/x/sync/singleflight"
	"google.golang.org/protobuf/types/known/structpb"
)

type metadataExtractorHandle struct {
	cache *metadataExtractorCache
	expr  string
	entry *celProgramEntry
}

func (h *metadataExtractorHandle) Evaluate(md *corev3.Metadata) (map[string]string, error) {
	if h == nil || h.cache == nil || h.entry == nil {
		return nil, nil
	}
	return h.cache.evaluate(h.entry, md)
}

func (h *metadataExtractorHandle) Release() {
	if h == nil || h.cache == nil || h.entry == nil {
		return
	}
	h.cache.release(h.expr)
	h.cache = nil
	h.entry = nil
}

type celProgramEntry struct {
	program  cel.Program
	refCount int32
}

type metadataExtractorCache struct {
	mu      sync.Mutex
	envOnce sync.Once
	celEnv  *cel.Env
	envErr  error

	entries map[string]*celProgramEntry
	group   singleflight.Group
}

var routeMetadataExtractorCache = newMetadataExtractorCache()

func newMetadataExtractorCache() *metadataExtractorCache {
	return &metadataExtractorCache{
		entries: make(map[string]*celProgramEntry),
	}
}

func (c *metadataExtractorCache) retain(expr string) (*metadataExtractorHandle, error) {
	c.mu.Lock()
	if entry, ok := c.entries[expr]; ok {
		entry.refCount++
		program := entry.program
		c.mu.Unlock()
		if program == nil {
			return nil, fmt.Errorf("trace_route_metadata_extractor program missing")
		}
		return &metadataExtractorHandle{
			cache: c,
			expr:  expr,
			entry: entry,
		}, nil
	}
	c.mu.Unlock()

	compiled, err, _ := c.group.Do(expr, func() (interface{}, error) {
		return c.compile(expr)
	})
	if err != nil {
		return nil, err
	}

	program := compiled.(cel.Program)

	c.mu.Lock()
	entry, ok := c.entries[expr]
	if ok {
		entry.refCount++
		if entry.program == nil {
			entry.program = program
		}
	} else {
		entry = &celProgramEntry{
			program:  program,
			refCount: 1,
		}
		c.entries[expr] = entry
	}
	c.mu.Unlock()

	return &metadataExtractorHandle{
		cache: c,
		expr:  expr,
		entry: entry,
	}, nil
}

func (c *metadataExtractorCache) release(expr string) {
	c.mu.Lock()
	entry, ok := c.entries[expr]
	if !ok {
		c.mu.Unlock()
		return
	}
	if entry.refCount <= 0 {
		c.mu.Unlock()
		panic("metadataExtractorCache.release: non-positive refCount")
	}
	entry.refCount--
	if entry.refCount == 0 {
		delete(c.entries, expr)
	}
	c.mu.Unlock()
}

func (c *metadataExtractorCache) evaluate(entry *celProgramEntry, md *corev3.Metadata) (map[string]string, error) {
	if entry == nil || entry.program == nil || md == nil {
		return nil, nil
	}

	input := metadataToCELInput(md)
	out, _, err := entry.program.Eval(map[string]any{"metadata": input})
	if err != nil {
		return nil, err
	}
	if out == nil {
		return nil, nil
	}
	native, err := out.ConvertToNative(reflect.TypeOf(map[string]any{}))
	if err != nil {
		return nil, fmt.Errorf("expected map result: %w", err)
	}

	nativeMap := native.(map[string]any)
	result := make(map[string]string, len(nativeMap))
	for key, value := range nativeMap {
		result[key] = fmt.Sprint(value)
	}
	return result, nil
}

func (c *metadataExtractorCache) compile(expr string) (cel.Program, error) {
	env, err := c.getEnv()
	if err != nil {
		return nil, err
	}
	ast, iss := env.Parse(expr)
	if iss.Err() != nil {
		return nil, iss.Err()
	}
	checked, iss := env.Check(ast)
	if iss.Err() != nil {
		return nil, iss.Err()
	}
	return env.Program(checked)
}

func (c *metadataExtractorCache) getEnv() (*cel.Env, error) {
	c.envOnce.Do(func() {
		c.celEnv, c.envErr = cel.NewEnv(
			cel.VariableDecls(
				decls.NewVariable("metadata", types.NewMapType(types.StringType, types.DynType)),
			),
		)
	})
	return c.celEnv, c.envErr
}

func metadataToCELInput(md *corev3.Metadata) map[string]any {
	if md == nil {
		return nil
	}
	filterMetadata := make(map[string]any, len(md.FilterMetadata))
	for ns, structVal := range md.FilterMetadata {
		if structVal == nil {
			continue
		}
		filterMetadata[ns] = structToMap(structVal)
	}
	return map[string]any{
		"filter_metadata": filterMetadata,
	}
}

func structToMap(s *structpb.Struct) map[string]any {
	if s == nil {
		return nil
	}
	return s.AsMap()
}
