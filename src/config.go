//  Copyright © 2023 Axkea, spacewander
//  Copyright © 2025 United Security Providers AG, Switzerland
//  SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	envoyconfigcorev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/proto"
)

func configFactory() api.StreamFilterFactory {
	return func(c interface{}, callbacks api.FilterCallbackHandler) api.StreamFilter {
		conf, ok := c.(*configuration)
		if !ok {
			panic("unexpected config type")
		}

		metadata := filterMetadata{
			clusterName:     getPropertyOrLogError(callbacks, "xds.cluster_name"),
			virtualHostName: getPropertyOrLogError(callbacks, "xds.virtual_host_name"),
			routeName:       callbacks.StreamInfo().GetRouteName(),
			filterChainName: callbacks.StreamInfo().FilterChainName(),
		}

		var routeMetadata *envoyconfigcorev3.Metadata
		if metadataProtoBytes, err := callbacks.GetProperty("xds.route_metadata"); err == nil && len(metadataProtoBytes) > 0 {
			routeMetadata = new(envoyconfigcorev3.Metadata)
			if err := proto.Unmarshal([]byte(metadataProtoBytes), routeMetadata); err != nil {
				api.LogErrorf("failed to decode xds.route_metadata: %v", err)
				routeMetadata = nil
			}
		}

		if len(conf.traceRouteMetadataExtractorExpression) > 0 && routeMetadata != nil {
			metadataExtractor, err := metadataExtractorFactory(conf.traceRouteMetadataExtractorExpression)
			if err != nil {
				api.LogErrorf("compile trace_route_metadata_extractor: %v", err)
			} else {
				attrs, err := metadataExtractor.Evaluate(routeMetadata)
				if err != nil {
					api.LogErrorf("trace_route_metadata_extractor evaluation failed: %v", err)
				} else {
					metadata.traceRouteAttributes = attrs
				}
			}
		}

		return &filter{
			callbacks: callbacks,
			conf:      conf,
			logger:    BuildLoggerMessage(conf.logFormat),
			metadata:  metadata,
		}
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
