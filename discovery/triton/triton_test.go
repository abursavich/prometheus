// Copyright 2016 The Prometheus Authors
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
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/common/config"
	"github.com/prometheus/common/model"

	"github.com/prometheus/prometheus/util/testutil"
)

var (
	conf = &SDConfig{
		Account:         "testAccount",
		Role:            "container",
		DNSSuffix:       "triton.example.com",
		Endpoint:        "127.0.0.1",
		Port:            443,
		Version:         1,
		RefreshInterval: 1,
		TLSConfig:       config.TLSConfig{InsecureSkipVerify: true},
	}
	cnConf = &SDConfig{
		Account:         "testAccount",
		Role:            "cn",
		DNSSuffix:       "triton.example.com",
		Endpoint:        "127.0.0.1",
		Port:            443,
		Version:         1,
		RefreshInterval: 1,
		TLSConfig:       config.TLSConfig{InsecureSkipVerify: true},
	}
)

func TestNew(t *testing.T) {
	r, err := newRefresher(conf)
	testutil.Ok(t, err)
	testutil.Assert(t, r != nil, "")
	testutil.Assert(t, r.client != nil, "")
	testutil.Assert(t, r.config != nil, "")
	testutil.Equals(t, conf.Account, r.config.Account)
	testutil.Equals(t, conf.DNSSuffix, r.config.DNSSuffix)
	testutil.Equals(t, conf.Endpoint, r.config.Endpoint)
	testutil.Equals(t, conf.Port, r.config.Port)
}

func TestNewBadConfig(t *testing.T) {
	r, err := newRefresher(&SDConfig{
		Account:         "badTestAccount",
		Role:            "container",
		DNSSuffix:       "bad.triton.example.com",
		Endpoint:        "127.0.0.1",
		Port:            443,
		Version:         1,
		RefreshInterval: 1,
		TLSConfig: config.TLSConfig{
			KeyFile:  "shouldnotexist.key",
			CAFile:   "shouldnotexist.ca",
			CertFile: "shouldnotexist.cert",
		},
	})
	testutil.NotOk(t, err)
	testutil.Assert(t, r == nil, "")
}

func TestNewGroupsConfig(t *testing.T) {
	cfg := &SDConfig{
		Account:         "testAccount",
		Role:            "container",
		DNSSuffix:       "triton.example.com",
		Endpoint:        "127.0.0.1",
		Groups:          []string{"foo", "bar"},
		Port:            443,
		Version:         1,
		RefreshInterval: 1,
		TLSConfig:       config.TLSConfig{InsecureSkipVerify: true},
	}
	r, err := newRefresher(cfg)
	testutil.Ok(t, err)
	testutil.Assert(t, r != nil, "")
	testutil.Assert(t, r.client != nil, "")
	testutil.Assert(t, r.config != nil, "")
	testutil.Equals(t, cfg.Account, r.config.Account)
	testutil.Equals(t, cfg.DNSSuffix, r.config.DNSSuffix)
	testutil.Equals(t, cfg.Endpoint, r.config.Endpoint)
	testutil.Equals(t, cfg.Groups, r.config.Groups)
	testutil.Equals(t, cfg.Port, r.config.Port)
}

func TestNewCNConfig(t *testing.T) {
	r, err := newRefresher(cnConf)
	testutil.Ok(t, err)
	testutil.Assert(t, r != nil, "")
	testutil.Assert(t, r.client != nil, "")
	testutil.Assert(t, r.config != nil, "")
	testutil.Equals(t, cnConf.Role, r.config.Role)
	testutil.Equals(t, cnConf.Account, r.config.Account)
	testutil.Equals(t, cnConf.DNSSuffix, r.config.DNSSuffix)
	testutil.Equals(t, cnConf.Endpoint, r.config.Endpoint)
	testutil.Equals(t, cnConf.Port, r.config.Port)
}

func TestRefreshNoTargets(t *testing.T) {
	tgts := testRefresh(t, conf, "{\"containers\":[]}")
	testutil.Assert(t, tgts == nil, "")
}

func TestRefreshMultipleTargets(t *testing.T) {
	var (
		dstr = `{"containers":[
		 	{
                                "groups":["foo","bar","baz"],
				"server_uuid":"44454c4c-5000-104d-8037-b7c04f5a5131",
				"vm_alias":"server01",
				"vm_brand":"lx",
				"vm_image_uuid":"7b27a514-89d7-11e6-bee6-3f96f367bee7",
				"vm_uuid":"ad466fbf-46a2-4027-9b64-8d3cdb7e9072"
			},
			{
				"server_uuid":"a5894692-bd32-4ca1-908a-e2dda3c3a5e6",
				"vm_alias":"server02",
				"vm_brand":"kvm",
				"vm_image_uuid":"a5894692-bd32-4ca1-908a-e2dda3c3a5e6",
				"vm_uuid":"7b27a514-89d7-11e6-bee6-3f96f367bee7"
			}]
		}`
	)

	tgts := testRefresh(t, conf, dstr)
	testutil.Assert(t, tgts != nil, "")
	testutil.Equals(t, 2, len(tgts))
}

func TestRefreshNoServer(t *testing.T) {
	r, err := newRefresher(conf)
	testutil.Ok(t, err)

	_, err = r.Refresh(context.Background())
	testutil.NotOk(t, err)
	testutil.Equals(t, strings.Contains(err.Error(), "an error occurred when requesting targets from the discovery endpoint"), true)
}

func TestRefreshCancelled(t *testing.T) {
	r, err := newRefresher(conf)
	testutil.Ok(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = r.Refresh(ctx)
	testutil.NotOk(t, err)
	testutil.Equals(t, strings.Contains(err.Error(), context.Canceled.Error()), true)
}

func TestRefreshCNsUUIDOnly(t *testing.T) {
	var (
		dstr = `{"cns":[
		 	{
				"server_uuid":"44454c4c-5000-104d-8037-b7c04f5a5131"
			},
			{
				"server_uuid":"a5894692-bd32-4ca1-908a-e2dda3c3a5e6"
			}]
		}`
	)

	tgts := testRefresh(t, cnConf, dstr)
	testutil.Assert(t, tgts != nil, "")
	testutil.Equals(t, 2, len(tgts))
}

func TestRefreshCNsWithHostname(t *testing.T) {
	var (
		dstr = `{"cns":[
		 	{
				"server_uuid":"44454c4c-5000-104d-8037-b7c04f5a5131",
				"server_hostname": "server01"
			},
			{
				"server_uuid":"a5894692-bd32-4ca1-908a-e2dda3c3a5e6",
				"server_hostname": "server02"
			}]
		}`
	)

	tgts := testRefresh(t, cnConf, dstr)
	testutil.Assert(t, tgts != nil, "")
	testutil.Equals(t, 2, len(tgts))
}

func testRefresh(t *testing.T, c *SDConfig, dstr string) []model.LabelSet {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, dstr)
	}))

	defer s.Close()

	u, err := url.Parse(s.URL)
	testutil.Ok(t, err)
	testutil.Assert(t, u != nil, "")

	host, strport, err := net.SplitHostPort(u.Host)
	testutil.Ok(t, err)
	testutil.Assert(t, host != "", "")
	testutil.Assert(t, strport != "", "")

	port, err := strconv.Atoi(strport)
	testutil.Ok(t, err)
	testutil.Assert(t, port != 0, "")

	cfg := *c
	cfg.Endpoint = host
	cfg.Port = port
	r, err := newRefresher(&cfg)
	testutil.Ok(t, err)

	tgs, err := r.Refresh(context.Background())
	testutil.Ok(t, err)
	testutil.Equals(t, 1, len(tgs))
	tg := tgs[0]
	testutil.Assert(t, tg != nil, "")

	return tg.Targets
}
