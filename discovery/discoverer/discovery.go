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

// Package discoverer temporarily exists to break a dependency cycle that would
// exist between the discovery and config packages until the dependency inversion
// is completed. As a final step in the process, its contents will be split up and
// returned to the discovery and config package. The config package will depend
// on the discovery package, but not the other way around.
package discoverer

// TODO(abursavich): CLEANUP: this file's content will be moved to the discovery package

import (
	"context"

	"github.com/go-kit/kit/log"

	"github.com/prometheus/prometheus/discovery/targetgroup"
)

// Discoverer provides information about target groups. It maintains a set
// of sources from which TargetGroups can originate. Whenever a discovery provider
// detects a potential change, it sends the TargetGroup through its channel.
//
// Discoverer does not know if an actual change happened.
// It does guarantee that it sends the new TargetGroup whenever a change happens.
//
// Discoverers should initially send a full set of all discoverable TargetGroups.
type Discoverer interface {
	// Run hands a channel to the discovery provider (Consul, DNS, etc.) through which
	// it can send updated target groups. It must return when the context is canceled.
	// It should not close the update channel on returning.
	Run(ctx context.Context, up chan<- []*targetgroup.Group)
}

// Options provides options for a Discoverer.
type Options struct {
	Logger log.Logger
}

// ConfigOptions provides options for a Config.
type ConfigOptions struct {
	// Directory may be used to resolve relative file paths
	// in the config (e.g. TLS certificates).
	Directory string
}

// A Config provides the configuration and constructor for a Discoverer.
type Config interface {
	// Name returns the name of the discovery mechanism.
	Name() string

	// NewDiscoverer returns a Discoverer for the Config
	// with the given Options.
	NewDiscoverer(Options) (Discoverer, error)

	// SetOptions applies the ConfigOptions to the Config.
	SetOptions(ConfigOptions)
}
