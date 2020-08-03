// Copyright 2017 The Prometheus Authors
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

package openstack

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	conntrack "github.com/mwitkow/go-conntrack"
	"github.com/pkg/errors"
	config_util "github.com/prometheus/common/config"
	"github.com/prometheus/common/model"

	"github.com/prometheus/prometheus/config"
	"github.com/prometheus/prometheus/discovery"
	"github.com/prometheus/prometheus/discovery/refresh"
)

const openstackName = "openstack"

// DefaultConfig is the default OpenStack SD configuration.
var DefaultConfig = Config{
	Port:            80,
	RefreshInterval: model.Duration(60 * time.Second),
	Availability:    "public",
}

func init() {
	config.RegisterServiceDiscovery(&Config{})
}

// Config is the configuration for OpenStack based service discovery.
type Config struct {
	IdentityEndpoint            string                `yaml:"identity_endpoint"`
	Username                    string                `yaml:"username"`
	UserID                      string                `yaml:"userid"`
	Password                    config_util.Secret    `yaml:"password"`
	ProjectName                 string                `yaml:"project_name"`
	ProjectID                   string                `yaml:"project_id"`
	DomainName                  string                `yaml:"domain_name"`
	DomainID                    string                `yaml:"domain_id"`
	ApplicationCredentialName   string                `yaml:"application_credential_name"`
	ApplicationCredentialID     string                `yaml:"application_credential_id"`
	ApplicationCredentialSecret config_util.Secret    `yaml:"application_credential_secret"`
	Role                        Role                  `yaml:"role"`
	Region                      string                `yaml:"region"`
	RefreshInterval             model.Duration        `yaml:"refresh_interval"`
	Port                        int                   `yaml:"port"`
	AllTenants                  bool                  `yaml:"all_tenants,omitempty"`
	TLSConfig                   config_util.TLSConfig `yaml:"tls_config,omitempty"`
	Availability                string                `yaml:"availability,omitempty"`
}

// Name returns the name of the Config.
func (*Config) Name() string { return openstackName }

// NewDiscoverer returns a Discoverer for the Config.
func (c *Config) NewDiscoverer(opts discovery.DiscovererOptions) (discovery.Discoverer, error) {
	r, err := newRefresher(c, opts.Logger)
	if err != nil {
		return nil, err
	}
	return refresh.NewDiscoverer(opts.Logger, time.Duration(c.RefreshInterval), r), nil
}

// SetOptions applies the options to the Config.
func (c *Config) SetOptions(opts discovery.ConfigOptions) {
	config.SetTLSConfigDirectory(&c.TLSConfig, opts.Directory)
}

// Validate checks the Config for errors.
func (c *Config) Validate() error {
	return config.ValidateTLSConfig(&c.TLSConfig)
}

// Role is the role of the target in OpenStack.
type Role string

// The valid options for OpenStackRole.
const (
	// OpenStack document reference
	// https://docs.openstack.org/nova/pike/admin/arch.html#hypervisors
	OpenStackRoleHypervisor Role = "hypervisor"
	// OpenStack document reference
	// https://docs.openstack.org/horizon/pike/user/launch-instances.html
	OpenStackRoleInstance Role = "instance"
)

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *Role) UnmarshalYAML(unmarshal func(interface{}) error) error {
	if err := unmarshal((*string)(c)); err != nil {
		return err
	}
	switch *c {
	case OpenStackRoleHypervisor, OpenStackRoleInstance:
		return nil
	default:
		return errors.Errorf("unknown OpenStack SD role %q", *c)
	}
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultConfig
	type plain Config
	err := unmarshal((*plain)(c))
	if err != nil {
		return err
	}

	switch c.Availability {
	case "public", "internal", "admin":
	default:
		return fmt.Errorf("unknown availability %s, must be one of admin, internal or public", c.Availability)
	}

	if c.Role == "" {
		return errors.New("role missing (one of: instance, hypervisor)")
	}
	if c.Region == "" {
		return errors.New("openstack SD configuration requires a region")
	}

	return nil
}

func newRefresher(conf *Config, l log.Logger) (refresh.Refresher, error) {
	if l == nil {
		l = log.NewNopLogger()
	}
	var opts gophercloud.AuthOptions
	if conf.IdentityEndpoint == "" {
		var err error
		opts, err = openstack.AuthOptionsFromEnv()
		if err != nil {
			return nil, err
		}
	} else {
		opts = gophercloud.AuthOptions{
			IdentityEndpoint:            conf.IdentityEndpoint,
			Username:                    conf.Username,
			UserID:                      conf.UserID,
			Password:                    string(conf.Password),
			TenantName:                  conf.ProjectName,
			TenantID:                    conf.ProjectID,
			DomainName:                  conf.DomainName,
			DomainID:                    conf.DomainID,
			ApplicationCredentialID:     conf.ApplicationCredentialID,
			ApplicationCredentialName:   conf.ApplicationCredentialName,
			ApplicationCredentialSecret: string(conf.ApplicationCredentialSecret),
		}
	}
	client, err := openstack.NewClient(opts.IdentityEndpoint)
	if err != nil {
		return nil, err
	}
	tls, err := config_util.NewTLSConfig(&conf.TLSConfig)
	if err != nil {
		return nil, err
	}
	client.HTTPClient = http.Client{
		Transport: &http.Transport{
			IdleConnTimeout: 2 * time.Duration(conf.RefreshInterval),
			TLSClientConfig: tls,
			DialContext: conntrack.NewDialContextFunc(
				conntrack.DialWithTracing(),
				conntrack.DialWithName("openstack_sd"),
			),
		},
		Timeout: time.Duration(conf.RefreshInterval),
	}
	availability := gophercloud.Availability(conf.Availability)
	switch conf.Role {
	case OpenStackRoleHypervisor:
		return &hypervisorRefresher{
			provider:     client,
			authOpts:     &opts,
			region:       conf.Region,
			port:         conf.Port,
			availability: availability,
			logger:       l,
		}, nil
	case OpenStackRoleInstance:
		return &instanceRefresher{
			provider:     client,
			authOpts:     &opts,
			region:       conf.Region,
			port:         conf.Port,
			allTenants:   conf.AllTenants,
			availability: availability,
			logger:       l,
		}, nil
	default:
		return nil, errors.New("unknown OpenStack discovery role")
	}
}
