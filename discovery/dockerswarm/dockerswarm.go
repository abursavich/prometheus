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

package dockerswarm

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/docker/docker/client"
	config_util "github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/version"

	"github.com/prometheus/prometheus/config"
	"github.com/prometheus/prometheus/discovery"
	"github.com/prometheus/prometheus/discovery/refresh"
	"github.com/prometheus/prometheus/discovery/targetgroup"
)

const (
	swarmName  = "dockerswarm"
	swarmLabel = model.MetaLabelPrefix + "dockerswarm_"
)

var userAgent = fmt.Sprintf("Prometheus/%s", version.Version)

// DefaultConfig is the default Docker Swarm SD configuration.
var DefaultConfig = Config{
	RefreshInterval: model.Duration(60 * time.Second),
	Port:            80,
}

func init() {
	config.RegisterServiceDiscovery(&Config{})
}

// Config is the configuration for Docker Swarm based service discovery.
type Config struct {
	HTTPClientConfig config_util.HTTPClientConfig `yaml:",inline"`

	Host string `yaml:"host"`
	Role string `yaml:"role"`
	Port int    `yaml:"port"`

	RefreshInterval model.Duration `yaml:"refresh_interval"`
}

// Name returns the name of the Config.
func (*Config) Name() string { return swarmName }

// NewDiscoverer returns a Discoverer for the Config.
func (c *Config) NewDiscoverer(opts discovery.DiscovererOptions) (discovery.Discoverer, error) {
	r, err := newRefresher(c)
	if err != nil {
		return nil, err
	}
	return refresh.NewDiscoverer(
		opts.Logger,
		time.Duration(c.RefreshInterval),
		r,
	), nil
}

// SetOptions applies the options to the Config.
func (c *Config) SetOptions(opts discovery.ConfigOptions) {
	config.SetHTTPClientConfigDirectory(&c.HTTPClientConfig, opts.Directory)
}

// Validate checks the Config for errors.
func (c *Config) Validate() error {
	return config.ValidateHTTPClientConfig(&c.HTTPClientConfig)
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultConfig
	type plain Config
	err := unmarshal((*plain)(c))
	if err != nil {
		return err
	}
	if c.Host == "" {
		return fmt.Errorf("host missing")
	}
	if _, err = url.Parse(c.Host); err != nil {
		return err
	}
	switch c.Role {
	case "services", "nodes", "tasks":
	case "":
		return fmt.Errorf("role missing (one of: tasks, services, nodes)")
	default:
		return fmt.Errorf("invalid role %s, expected tasks, services, or nodes", c.Role)
	}
	return nil
}

type refresher struct {
	client *client.Client
	role   string
	port   int
}

func newRefresher(conf *Config) (*refresher, error) {
	hostURL, err := url.Parse(conf.Host)
	if err != nil {
		return nil, err
	}

	opts := []client.Opt{
		client.WithHost(conf.Host),
		client.WithAPIVersionNegotiation(),
	}
	// There are other protocols than HTTP supported by the Docker daemon, like
	// unix, which are not supported by the HTTP client. Passing HTTP client
	// options to the Docker client makes those non-HTTP requests fail.
	if hostURL.Scheme == "http" || hostURL.Scheme == "https" {
		rt, err := config_util.NewRoundTripperFromConfig(conf.HTTPClientConfig, "dockerswarm_sd", false)
		if err != nil {
			return nil, err
		}
		opts = append(opts,
			client.WithHTTPClient(&http.Client{
				Transport: rt,
				Timeout:   time.Duration(conf.RefreshInterval),
			}),
			client.WithScheme(hostURL.Scheme),
			client.WithHTTPHeaders(map[string]string{
				"User-Agent": userAgent,
			}),
		)
	}
	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, fmt.Errorf("error setting up docker swarm client: %w", err)
	}

	return &refresher{
		client: cli,
		port:   conf.Port,
		role:   conf.Role,
	}, nil
}

func (*refresher) Name() string { return swarmName }

func (r *refresher) Refresh(ctx context.Context) ([]*targetgroup.Group, error) {
	switch r.role {
	case "services":
		return r.refreshServices(ctx)
	case "nodes":
		return r.refreshNodes(ctx)
	case "tasks":
		return r.refreshTasks(ctx)
	default:
		panic(fmt.Errorf("unexpected role %s", r.role))
	}
}
