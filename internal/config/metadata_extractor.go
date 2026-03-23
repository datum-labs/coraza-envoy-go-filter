// Copyright © 2025 Datum Technology, Inc.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"reflect"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/decls"
	"github.com/google/cel-go/common/types"
	"github.com/karlseguin/ccache/v3"
	"golang.org/x/sync/singleflight"
)

var metadataExtractorEnv *cel.Env
var expressionCache *ccache.Cache[*MetadataExtractor]
var expressionCacheSFGroup singleflight.Group

func init() {
	env, err := cel.NewEnv(
		cel.VariableDecls(
			decls.NewVariable("metadata", types.NewMapType(types.StringType, types.DynType)),
		),
	)
	if err != nil {
		panic(fmt.Sprintf("failed to create CEL environment: %v", err))
	}
	metadataExtractorEnv = env

	expressionCache = ccache.New(ccache.Configure[*MetadataExtractor]().MaxSize(512))
}

// MetadataExtractorFactory creates or retrieves a cached MetadataExtractor for the given CEL expression.
func MetadataExtractorFactory(expression string) (*MetadataExtractor, error) {
	entry := expressionCache.Get(expression)
	if entry != nil {
		return entry.Value(), nil
	}

	extractor, err, _ := expressionCacheSFGroup.Do(expression, func() (any, error) {
		ast, iss := metadataExtractorEnv.Parse(expression)
		if iss.Err() != nil {
			return nil, iss.Err()
		}
		checked, iss := metadataExtractorEnv.Check(ast)
		if iss.Err() != nil {
			return nil, iss.Err()
		}
		program, err := metadataExtractorEnv.Program(checked)
		if err != nil {
			return nil, err
		}
		return &MetadataExtractor{
			program: program,
		}, nil
	})

	if err != nil {
		return nil, err
	}

	expressionCache.Set(expression, extractor.(*MetadataExtractor), time.Minute*10)
	return extractor.(*MetadataExtractor), nil
}

// MetadataExtractor evaluates a CEL expression against Envoy route metadata.
type MetadataExtractor struct {
	program cel.Program
}

// Evaluate runs the CEL program against the given Envoy metadata and returns a string map.
func (m *MetadataExtractor) Evaluate(md *corev3.Metadata) (map[string]string, error) {
	input := metadataToCELInput(md)
	out, _, err := m.program.Eval(map[string]any{"metadata": input})
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

func metadataToCELInput(md *corev3.Metadata) map[string]any {
	if md == nil {
		return nil
	}
	filterMetadata := make(map[string]any, len(md.FilterMetadata))
	for ns, structVal := range md.FilterMetadata {
		if structVal == nil {
			continue
		}
		filterMetadata[ns] = structVal.AsMap()
	}
	return map[string]any{
		"filter_metadata": filterMetadata,
	}
}
