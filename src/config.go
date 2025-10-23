//  Copyright © 2023 Axkea, spacewander
//  Copyright © 2025 United Security Providers AG, Switzerland
//  SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
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
