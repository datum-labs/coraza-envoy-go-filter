// Copyright © 2025 United Security Providers AG, Switzerland
// Copyright © 2025 Datum Technology, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/http"
	envoyconfigcorev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/proto"

	"coraza-waf/internal/config"
	"coraza-waf/internal/filter"
	"coraza-waf/internal/logging"
	"coraza-waf/internal/telemetry"
)

const PluginName = "coraza-waf"

func filterFactory(c any, callbacks api.FilterCallbackHandler) api.StreamFilter {
	conf, ok := c.(*config.Configuration)
	if !ok {
		panic("unexpected config type")
	}
	logging.Init(conf.LogFormat)

	metadata := filter.FilterMetadata{
		ClusterName:     getPropertyOrLogError(callbacks, "xds.cluster_name"),
		VirtualHostName: getPropertyOrLogError(callbacks, "xds.virtual_host_name"),
		RouteName:       callbacks.StreamInfo().GetRouteName(),
		FilterChainName: callbacks.StreamInfo().FilterChainName(),
	}

	var routeMetadata *envoyconfigcorev3.Metadata
	if metadataProtoBytes, err := callbacks.GetProperty("xds.route_metadata"); err == nil && len(metadataProtoBytes) > 0 {
		routeMetadata = new(envoyconfigcorev3.Metadata)
		if err := proto.Unmarshal([]byte(metadataProtoBytes), routeMetadata); err != nil {
			api.LogErrorf("failed to decode xds.route_metadata: %v", err)
			routeMetadata = nil
		}
	}

	if len(conf.TraceRouteMetadataExtractorExpression) > 0 && routeMetadata != nil {
		metadataExtractor, err := config.MetadataExtractorFactory(conf.TraceRouteMetadataExtractorExpression)
		if err != nil {
			api.LogErrorf("compile trace_route_metadata_extractor: %v", err)
		} else {
			attrs, err := metadataExtractor.Evaluate(routeMetadata)
			if err != nil {
				api.LogErrorf("trace_route_metadata_extractor evaluation failed: %v", err)
			} else {
				metadata.TraceRouteAttributes = attrs
			}
		}
	}

	return &filter.Filter{
		Callbacks: callbacks,
		Config:    *conf,
		Metadata:  metadata,
	}
}

func getPropertyOrLogError(callbacks api.FilterCallbackHandler, key string) string {
	value, err := callbacks.GetProperty(key)
	if err != nil {
		if errors.Is(err, api.ErrValueNotFound) {
			return ""
		}
		api.LogErrorf("failed to get property %s: %v", key, err)
		return ""
	}
	return value
}

func init() {
	_, err := telemetry.SetupOpenTelemetry(context.Background())
	if err != nil {
		panic(fmt.Sprintf("failed to setup OpenTelemetry: %v", err))
	}

	http.RegisterHttpFilterFactoryAndConfigParser(PluginName, filterFactory, &config.Parser{})
}

func main() {}
