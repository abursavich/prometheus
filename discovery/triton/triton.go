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

package triton

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-kit/kit/log"
	conntrack "github.com/mwitkow/go-conntrack"
	"github.com/pkg/errors"
	config_util "github.com/prometheus/common/config"
	"github.com/prometheus/common/model"

	"github.com/prometheus/prometheus/config"
	"github.com/prometheus/prometheus/discovery"
	"github.com/prometheus/prometheus/discovery/refresh"
	"github.com/prometheus/prometheus/discovery/targetgroup"
)

const (
	tritonLabel             = model.MetaLabelPrefix + "triton_"
	tritonLabelGroups       = tritonLabel + "groups"
	tritonLabelMachineID    = tritonLabel + "machine_id"
	tritonLabelMachineAlias = tritonLabel + "machine_alias"
	tritonLabelMachineBrand = tritonLabel + "machine_brand"
	tritonLabelMachineImage = tritonLabel + "machine_image"
	tritonLabelServerID     = tritonLabel + "server_id"
)

// DefaultConfig is the default Triton SD configuration.
var DefaultConfig = Config{
	Role:            "container",
	Port:            9163,
	RefreshInterval: model.Duration(60 * time.Second),
	Version:         1,
}

func init() {
	config.RegisterServiceDiscovery(&Config{})
}

// Config is the configuration for Triton based service discovery.
type Config struct {
	Account         string                `yaml:"account"`
	Role            string                `yaml:"role"`
	DNSSuffix       string                `yaml:"dns_suffix"`
	Endpoint        string                `yaml:"endpoint"`
	Groups          []string              `yaml:"groups,omitempty"`
	Port            int                   `yaml:"port"`
	RefreshInterval model.Duration        `yaml:"refresh_interval,omitempty"`
	TLSConfig       config_util.TLSConfig `yaml:"tls_config,omitempty"`
	Version         int                   `yaml:"version"`
}

// Name returns the name of the Config.
func (*Config) Name() string { return "triton" }

// NewDiscoverer returns a Discoverer for the Config.
func (c *Config) NewDiscoverer(opts discovery.DiscovererOptions) (discovery.Discoverer, error) {
	return New(opts.Logger, c)
}

// SetOptions applies the options to the Config.
func (c *Config) SetOptions(opts discovery.ConfigOptions) {
	config.SetTLSConfigDirectory(&c.TLSConfig, opts.Directory)
}

// Validate checks the Config for errors.
func (c *Config) Validate() error {
	return config.ValidateTLSConfig(&c.TLSConfig)
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultConfig
	type plain Config
	err := unmarshal((*plain)(c))
	if err != nil {
		return err
	}
	if c.Role != "container" && c.Role != "cn" {
		return errors.New("triton SD configuration requires role to be 'container' or 'cn'")
	}
	if c.Account == "" {
		return errors.New("triton SD configuration requires an account")
	}
	if c.DNSSuffix == "" {
		return errors.New("triton SD configuration requires a dns_suffix")
	}
	if c.Endpoint == "" {
		return errors.New("triton SD configuration requires an endpoint")
	}
	if c.RefreshInterval <= 0 {
		return errors.New("triton SD configuration requires RefreshInterval to be a positive integer")
	}
	return nil
}

// DiscoveryResponse models a JSON response from the Triton discovery.
type DiscoveryResponse struct {
	Containers []struct {
		Groups      []string `json:"groups"`
		ServerUUID  string   `json:"server_uuid"`
		VMAlias     string   `json:"vm_alias"`
		VMBrand     string   `json:"vm_brand"`
		VMImageUUID string   `json:"vm_image_uuid"`
		VMUUID      string   `json:"vm_uuid"`
	} `json:"containers"`
}

// ComputeNodeDiscoveryResponse models a JSON response from the Triton discovery /gz/ endpoint.
type ComputeNodeDiscoveryResponse struct {
	ComputeNodes []struct {
		ServerUUID     string `json:"server_uuid"`
		ServerHostname string `json:"server_hostname"`
	} `json:"cns"`
}

// Discovery periodically performs Triton-SD requests. It implements
// the Discoverer interface.
type Discovery struct {
	discovery.Discoverer
	client   *http.Client
	interval time.Duration
	config   *Config
}

// New returns a new Discovery which periodically refreshes its targets.
func New(logger log.Logger, conf *Config) (*Discovery, error) {
	tls, err := config_util.NewTLSConfig(&conf.TLSConfig)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		TLSClientConfig: tls,
		DialContext: conntrack.NewDialContextFunc(
			conntrack.DialWithTracing(),
			conntrack.DialWithName("triton_sd"),
		),
	}
	client := &http.Client{Transport: transport}

	d := &Discovery{
		client:   client,
		interval: time.Duration(conf.RefreshInterval),
		config:   conf,
	}
	d.Discoverer = refresh.NewDiscovery(
		logger,
		"triton",
		time.Duration(conf.RefreshInterval),
		d.refresh,
	)
	return d, nil
}

// triton-cmon has two discovery endpoints:
// https://github.com/joyent/triton-cmon/blob/master/lib/endpoints/discover.js
//
// The default endpoint exposes "containers", otherwise called "virtual machines" in triton,
// which are (branded) zones running on the triton platform.
//
// The /gz/ endpoint exposes "compute nodes", also known as "servers" or "global zones",
// on which the "containers" are running.
//
// As triton is not internally consistent in using these names,
// the terms as used in triton-cmon are used here.

func (d *Discovery) refresh(ctx context.Context) ([]*targetgroup.Group, error) {
	var endpointFormat string
	switch d.config.Role {
	case "container":
		endpointFormat = "https://%s:%d/v%d/discover"
	case "cn":
		endpointFormat = "https://%s:%d/v%d/gz/discover"
	default:
		return nil, errors.New(fmt.Sprintf("unknown role '%s' in configuration", d.config.Role))
	}
	var endpoint = fmt.Sprintf(endpointFormat, d.config.Endpoint, d.config.Port, d.config.Version)
	if len(d.config.Groups) > 0 {
		groups := url.QueryEscape(strings.Join(d.config.Groups, ","))
		endpoint = fmt.Sprintf("%s?groups=%s", endpoint, groups)
	}

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "an error occurred when requesting targets from the discovery endpoint")
	}

	defer func() {
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
	}()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "an error occurred when reading the response body")
	}

	// The JSON response body is different so it needs to be processed/mapped separately.
	switch d.config.Role {
	case "container":
		return d.processContainerResponse(data, endpoint)
	case "cn":
		return d.processComputeNodeResponse(data, endpoint)
	default:
		return nil, errors.New(fmt.Sprintf("unknown role '%s' in configuration", d.config.Role))
	}
}

func (d *Discovery) processContainerResponse(data []byte, endpoint string) ([]*targetgroup.Group, error) {
	tg := &targetgroup.Group{
		Source: endpoint,
	}

	dr := DiscoveryResponse{}
	err := json.Unmarshal(data, &dr)
	if err != nil {
		return nil, errors.Wrap(err, "an error occurred unmarshaling the discovery response json")
	}

	for _, container := range dr.Containers {
		labels := model.LabelSet{
			tritonLabelMachineID:    model.LabelValue(container.VMUUID),
			tritonLabelMachineAlias: model.LabelValue(container.VMAlias),
			tritonLabelMachineBrand: model.LabelValue(container.VMBrand),
			tritonLabelMachineImage: model.LabelValue(container.VMImageUUID),
			tritonLabelServerID:     model.LabelValue(container.ServerUUID),
		}
		addr := fmt.Sprintf("%s.%s:%d", container.VMUUID, d.config.DNSSuffix, d.config.Port)
		labels[model.AddressLabel] = model.LabelValue(addr)

		if len(container.Groups) > 0 {
			name := "," + strings.Join(container.Groups, ",") + ","
			labels[tritonLabelGroups] = model.LabelValue(name)
		}

		tg.Targets = append(tg.Targets, labels)
	}

	return []*targetgroup.Group{tg}, nil
}

func (d *Discovery) processComputeNodeResponse(data []byte, endpoint string) ([]*targetgroup.Group, error) {
	tg := &targetgroup.Group{
		Source: endpoint,
	}

	dr := ComputeNodeDiscoveryResponse{}
	err := json.Unmarshal(data, &dr)
	if err != nil {
		return nil, errors.Wrap(err, "an error occurred unmarshaling the compute node discovery response json")
	}

	for _, cn := range dr.ComputeNodes {
		labels := model.LabelSet{
			tritonLabelMachineID:    model.LabelValue(cn.ServerUUID),
			tritonLabelMachineAlias: model.LabelValue(cn.ServerHostname),
		}
		addr := fmt.Sprintf("%s.%s:%d", cn.ServerUUID, d.config.DNSSuffix, d.config.Port)
		labels[model.AddressLabel] = model.LabelValue(addr)

		tg.Targets = append(tg.Targets, labels)
	}

	return []*targetgroup.Group{tg}, nil
}
