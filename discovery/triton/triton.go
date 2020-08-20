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
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	conntrack "github.com/mwitkow/go-conntrack"
	"github.com/pkg/errors"
	"github.com/prometheus/common/config"
	"github.com/prometheus/common/model"

	"github.com/prometheus/prometheus/discovery"
	"github.com/prometheus/prometheus/discovery/refresh"
	"github.com/prometheus/prometheus/discovery/targetgroup"
)

const (
	tritonName              = "triton"
	tritonLabel             = model.MetaLabelPrefix + tritonName + "_"
	tritonLabelGroups       = tritonLabel + "groups"
	tritonLabelMachineID    = tritonLabel + "machine_id"
	tritonLabelMachineAlias = tritonLabel + "machine_alias"
	tritonLabelMachineBrand = tritonLabel + "machine_brand"
	tritonLabelMachineImage = tritonLabel + "machine_image"
	tritonLabelServerID     = tritonLabel + "server_id"
)

// DefaultSDConfig is the default Triton SD configuration.
var DefaultSDConfig = SDConfig{
	Role:            "container",
	Port:            9163,
	RefreshInterval: model.Duration(60 * time.Second),
	Version:         1,
}

func init() {
	discovery.RegisterConfig(&SDConfig{})
}

// SDConfig is the configuration for Triton based service discovery.
type SDConfig struct {
	Account         string           `yaml:"account"`
	Role            string           `yaml:"role"`
	DNSSuffix       string           `yaml:"dns_suffix"`
	Endpoint        string           `yaml:"endpoint"`
	Port            int              `yaml:"port"`
	Groups          []string         `yaml:"groups,omitempty"`
	RefreshInterval model.Duration   `yaml:"refresh_interval,omitempty"`
	TLSConfig       config.TLSConfig `yaml:"tls_config,omitempty"`
	Version         int              `yaml:"version"`
}

// Name returns the name of the Config.
func (*SDConfig) Name() string { return tritonName }

// NewDiscoverer returns a Discoverer for the Config.
func (c *SDConfig) NewDiscoverer(opts discovery.DiscovererOptions) (discovery.Discoverer, error) {
	r, err := newRefresher(c)
	if err != nil {
		return nil, err
	}
	return refresh.NewDiscoverer(opts.Logger, time.Duration(c.RefreshInterval), r), nil
}

// SetDirectory joins any relative file paths with dir.
func (c *SDConfig) SetDirectory(dir string) {
	c.TLSConfig.SetDirectory(dir)
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *SDConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultSDConfig
	type plain SDConfig
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

func (c *SDConfig) url() (*url.URL, error) {
	u := &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(c.Endpoint, strconv.Itoa(c.Port)),
		Path:   fmt.Sprintf("/v%d", c.Version),
	}
	switch c.Role {
	case "container":
		u.Path += "/discover"
	case "cn":
		u.Path += "/gz/discover"
	default:
		return nil, fmt.Errorf("unknown role %q in configuration", c.Role)
	}
	if len(c.Groups) > 0 {
		qry := u.Query()
		qry.Set("groups", strings.Join(c.Groups, ","))
		u.RawQuery = qry.Encode()
	}
	return u, nil
}

type refresher struct {
	client *http.Client
	config *SDConfig
	url    string
}

func newRefresher(c *SDConfig) (*refresher, error) {
	u, err := c.url()
	if err != nil {
		return nil, err
	}
	tls, err := config.NewTLSConfig(&c.TLSConfig)
	if err != nil {
		return nil, err
	}
	return &refresher{
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tls,
				DialContext: conntrack.NewDialContextFunc(
					conntrack.DialWithTracing(),
					conntrack.DialWithName("triton_sd"),
				),
			},
		},
		config: c,
		url:    u.String(),
	}, nil
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

func (*refresher) Name() string { return tritonName }

func (r *refresher) Refresh(ctx context.Context) ([]*targetgroup.Group, error) {
	req, err := http.NewRequest("GET", r.url, nil)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	resp, err := r.client.Do(req)
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
	switch r.config.Role {
	case "container":
		return r.processContainerResponse(data)
	case "cn":
		return r.processComputeNodeResponse(data)
	default:
		return nil, fmt.Errorf("unknown role %q in configuration", r.config.Role)
	}
}

func (r *refresher) processContainerResponse(data []byte) ([]*targetgroup.Group, error) {
	type response struct {
		Containers []struct {
			Groups      []string `json:"groups"`
			ServerUUID  string   `json:"server_uuid"`
			VMAlias     string   `json:"vm_alias"`
			VMBrand     string   `json:"vm_brand"`
			VMImageUUID string   `json:"vm_image_uuid"`
			VMUUID      string   `json:"vm_uuid"`
		} `json:"containers"`
	}
	var resp response
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, errors.Wrap(err, "an error occurred unmarshaling the discovery response json")
	}

	tg := &targetgroup.Group{
		Source: r.url,
	}
	for _, container := range resp.Containers {
		labels := model.LabelSet{
			tritonLabelMachineID:    model.LabelValue(container.VMUUID),
			tritonLabelMachineAlias: model.LabelValue(container.VMAlias),
			tritonLabelMachineBrand: model.LabelValue(container.VMBrand),
			tritonLabelMachineImage: model.LabelValue(container.VMImageUUID),
			tritonLabelServerID:     model.LabelValue(container.ServerUUID),
		}
		addr := fmt.Sprintf("%s.%s:%d", container.VMUUID, r.config.DNSSuffix, r.config.Port)
		labels[model.AddressLabel] = model.LabelValue(addr)

		if len(container.Groups) > 0 {
			name := "," + strings.Join(container.Groups, ",") + ","
			labels[tritonLabelGroups] = model.LabelValue(name)
		}

		tg.Targets = append(tg.Targets, labels)
	}
	return []*targetgroup.Group{tg}, nil
}

func (r *refresher) processComputeNodeResponse(data []byte) ([]*targetgroup.Group, error) {
	type response struct {
		ComputeNodes []struct {
			ServerUUID     string `json:"server_uuid"`
			ServerHostname string `json:"server_hostname"`
		} `json:"cns"`
	}
	var resp response
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, errors.Wrap(err, "an error occurred unmarshaling the compute node discovery response json")
	}

	tg := &targetgroup.Group{
		Source: r.url,
	}
	for _, cn := range resp.ComputeNodes {
		labels := model.LabelSet{
			tritonLabelMachineID:    model.LabelValue(cn.ServerUUID),
			tritonLabelMachineAlias: model.LabelValue(cn.ServerHostname),
		}
		addr := fmt.Sprintf("%s.%s:%d", cn.ServerUUID, r.config.DNSSuffix, r.config.Port)
		labels[model.AddressLabel] = model.LabelValue(addr)

		tg.Targets = append(tg.Targets, labels)
	}
	return []*targetgroup.Group{tg}, nil
}
