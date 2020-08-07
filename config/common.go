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
	"fmt"
	"os"
	"path/filepath"

	"github.com/prometheus/common/config"
)

// Validater provides a mechanism to reject configs before they are used.
type Validater interface {
	// Validate returns an error if it can determine that a config
	// will fail when used. For example, it may reference missing
	// or invalid files.
	Validate() error
}

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

// ValidateHTTPClientConfig checks if the HTTP client config is valid.
func ValidateHTTPClientConfig(c *config.HTTPClientConfig) error {
	if a := c.BasicAuth; a != nil {
		if c.BearerToken != "" || c.BearerTokenFile != "" {
			return fmt.Errorf("cannot specify both basic auth and bearer token")
		}
		if a.Password != "" && a.PasswordFile != "" {
			return fmt.Errorf("basic auth cannot specify both password and password file: %v", a.PasswordFile)
		}
		if err := emptyOrFileExists(a.PasswordFile); err != nil {
			return fmt.Errorf("basic auth password file: %v: %w", a.PasswordFile, err)
		}
	}
	if c.BearerToken != "" && c.BearerTokenFile != "" {
		return fmt.Errorf("bearer token cannot specify both value and file: %v", c.BearerTokenFile)
	}
	if err := emptyOrFileExists(c.BearerTokenFile); err != nil {
		return fmt.Errorf("bearer token file: %v: %w", c.BearerTokenFile, err)
	}
	return ValidateTLSConfig(&c.TLSConfig)
}

// ValidateTLSConfig checks if the TLS config is valid.
func ValidateTLSConfig(c *config.TLSConfig) error {
	if err := emptyOrFileExists(c.CAFile); err != nil {
		return fmt.Errorf("certificate authority file: %v: %w", c.CAFile, err)
	}
	if err := emptyOrFileExists(c.CertFile); err != nil {
		return fmt.Errorf("certificate file: %v: %w", c.CertFile, err)
	}
	if err := emptyOrFileExists(c.KeyFile); err != nil {
		return fmt.Errorf("private key file: %v: %w", c.KeyFile, err)
	}
	if c.CertFile != "" && c.KeyFile == "" {
		return fmt.Errorf("certificate file specified without private key file: %v", c.CertFile)
	}
	if c.KeyFile != "" && c.CertFile != "" {
		return fmt.Errorf("private key file specified without certificate file: %v", c.KeyFile)
	}
	_, err := config.NewTLSConfig(c)
	return err
}

func emptyOrFileExists(path string) error {
	if path == "" {
		return nil
	}
	s, err := os.Stat(path)
	if err != nil {
		return err.(*os.PathError).Err
	}
	if s.IsDir() {
		return fmt.Errorf("found directory instead of file")
	}
	return nil
}
