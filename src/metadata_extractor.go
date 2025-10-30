package main

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
var expressionCache *ccache.Cache[*metadataExtractor]
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

	expressionCache = ccache.New(ccache.Configure[*metadataExtractor]().MaxSize(512))
}

func metadataExtractorFactory(expression string) (*metadataExtractor, error) {
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
		return &metadataExtractor{
			program: program,
		}, nil
	})

	if err != nil {
		return nil, err
	}

	expressionCache.Set(expression, extractor.(*metadataExtractor), time.Minute*10)
	return extractor.(*metadataExtractor), nil
}

type metadataExtractor struct {
	program cel.Program
}

func (m *metadataExtractor) Evaluate(md *corev3.Metadata) (map[string]string, error) {
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
		if structVal != nil {
			filterMetadata[ns] = structVal.AsMap()
		}
	}
	return map[string]any{
		"filter_metadata": filterMetadata,
	}
}
