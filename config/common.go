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

package config

import (
	"path/filepath"

	"github.com/prometheus/common/config"
)

// JoinDir joins dir and path if path is relative.
// If path is empty or absolute, it is returned unchanged.
func JoinDir(dir, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(dir, path)
}

// SetHTTPClientConfigDirectory sets filepaths to be relative to dir.
func SetHTTPClientConfigDirectory(c *config.HTTPClientConfig, dir string) {
	if c == nil {
		return
	}
	SetTLSConfigDirectory(&c.TLSConfig, dir)
	if a := c.BasicAuth; a != nil {
		a.PasswordFile = JoinDir(dir, a.PasswordFile)
	}
	c.BearerTokenFile = JoinDir(dir, c.BearerTokenFile)
}

// SetTLSConfigDirectory sets filepaths to be relative to dir.
func SetTLSConfigDirectory(c *config.TLSConfig, dir string) {
	if c == nil {
		return
	}
	c.CAFile = JoinDir(dir, c.CAFile)
	c.CertFile = JoinDir(dir, c.CertFile)
	c.KeyFile = JoinDir(dir, c.KeyFile)
}
