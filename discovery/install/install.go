// Copyright 2020 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package install has the side-effect of registering all builtin
// service discovery config types.
package install

import (
	_ "github.com/prometheus/prometheus/discovery/azure"        // register azure
	_ "github.com/prometheus/prometheus/discovery/digitalocean" // register digitalocean
	_ "github.com/prometheus/prometheus/discovery/dns"          // register dns
	_ "github.com/prometheus/prometheus/discovery/dockerswarm"  // register dockerswarm
	_ "github.com/prometheus/prometheus/discovery/marathon"     // register marathon
	_ "github.com/prometheus/prometheus/discovery/openstack"    // register openstack
	_ "github.com/prometheus/prometheus/discovery/triton"       // register triton
)
