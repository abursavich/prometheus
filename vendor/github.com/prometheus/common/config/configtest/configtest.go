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

// Package configtest provides config testing utilities.
package configtest

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/prometheus/common/config"
)

// LoadConfigFunc loads the given file as a config.
type LoadConfigFunc func(file string) (config.DirectorySetter, error)

// AssertEqualFunc asserts that the given values are equal
// and fails the test if they are not.
type AssertEqualFunc func(t testing.TB, want, got interface{})

// TestSetDirectory tests that calling SetDirectory on the config calls it on all
// inner and leaf values in the config.
func TestSetDirectory(t *testing.T, file string, loadFile LoadConfigFunc, assertEqual AssertEqualFunc) {
	filename, err := filepath.Abs(file)
	if err != nil {
		t.Fatalf("unexpected error getting absolute path: %v: %v", file, err)
	}
	dir := filepath.Dir(filename)

	mustLoadFile := func() config.DirectorySetter {
		c, err := loadFile(filename)
		if err != nil {
			t.Helper()
			t.Fatalf("unexpected error loading file: %v: %v", filename, err)
		}
		return c
	}

	// Test config as-is.
	want := mustLoadFile()
	SetDirectory(want, dir)

	got := mustLoadFile()
	got.SetDirectory(dir)

	assertEqual(t, want, got)

	// Test config after every field that looks like
	// it might contain a file path is non-empty.
	want = mustLoadFile()
	SetFile(want, "hello/file")
	SetDirectory(want, dir)

	got = mustLoadFile()
	SetFile(got, "hello/file")
	got.SetDirectory(dir)

	assertEqual(t, want, got)
}

// SetFile uses reflection to replace every field in the config that looks
// like a file path with the given path.
func SetFile(config config.DirectorySetter, path string) {
	setFile(reflect.ValueOf(config), path, set{})
}

// SetDirectory uses reflection to call SetDirectory with dir on every value
// in the config that implements it. For best results, dir should be an
// absolute path because SetDirectory should be called on inner and leaf
// values multiple times.
func SetDirectory(config config.DirectorySetter, dir string) {
	setDirectory(reflect.ValueOf(config), dir, set{})
}

var (
	stringTyp      = reflect.TypeOf("")
	stringSliceTyp = reflect.TypeOf([]string{})
)

type set map[interface{}]bool

func setFile(val reflect.Value, path string, seen set) {
	if isNil(val) || !canSet(val) {
		return
	}
	switch typ := val.Type(); typ.Kind() {
	case reflect.Ptr:
		if key := val.Interface(); !seen[key] {
			seen[key] = true
			setFile(val.Elem(), path, seen)
		}
	case reflect.Struct:
		for i, n := 0, typ.NumField(); i < n; i++ {
			tf := typ.Field(i)
			if tf.PkgPath != "" {
				continue // Field is unexported.
			}
			switch vf := val.Field(i); {
			case tf.Type == stringTyp && strings.HasSuffix(tf.Name, "File"):
				// Clear the string field, if it exists.
				sf := val.FieldByName(strings.TrimSuffix(tf.Name, "File"))
				if sf.IsValid() && sf.Type().Kind() == reflect.String {
					// NB: Check Kind because Type may be Secret.
					sf.SetString("")
				}
				// Set the file field.
				vf.SetString(path)
			case tf.Type == stringSliceTyp && strings.HasSuffix(tf.Name, "Files"):
				vf.Set(reflect.ValueOf([]string{path}))
			default:
				setFile(vf, path, seen)
			}
		}
	case reflect.Map:
		for _, key := range val.MapKeys() {
			setFile(key, path, seen)
			setFile(val.MapIndex(key), path, seen)
		}
	case reflect.Slice, reflect.Array:
		for i, n := 0, val.Len(); i < n; i++ {
			setFile(val.Index(i), path, seen)
		}
	case reflect.Interface:
		setFile(val.Elem(), path, seen)
	}
}

func setDirectory(val reflect.Value, dir string, seen set) {
	if isNil(val) || !canSet(val) {
		return
	}

	v := val
	if val.Kind() != reflect.Ptr && val.CanAddr() {
		v = val.Addr()
	}
	if i, ok := v.Interface().(config.DirectorySetter); ok {
		i.SetDirectory(dir)
	}

	switch typ := val.Type(); typ.Kind() {
	case reflect.Ptr:
		if key := val.Interface(); !seen[key] {
			seen[key] = true
			setDirectory(val.Elem(), dir, seen)
		}
	case reflect.Struct:
		for i, n := 0, typ.NumField(); i < n; i++ {
			if typ.Field(i).PkgPath != "" {
				continue // Field is unexported.
			}
			setDirectory(val.Field(i), dir, seen)
		}
	case reflect.Map:
		for _, key := range val.MapKeys() {
			setDirectory(key, dir, seen)
			setDirectory(val.MapIndex(key), dir, seen)
		}
	case reflect.Slice, reflect.Array:
		for i, n := 0, val.Len(); i < n; i++ {
			setDirectory(val.Index(i), dir, seen)
		}
	case reflect.Interface:
		setDirectory(val.Elem(), dir, seen)
	}
}

func canSet(val reflect.Value) bool {
	switch val.Kind() {
	case reflect.Ptr, reflect.Interface:
		return canSet(val.Elem())
	default:
		return val.CanSet()
	}
}

func isNil(val reflect.Value) bool {
	switch val.Kind() {
	case reflect.Ptr,
		reflect.Map,
		reflect.Slice,
		reflect.Interface,
		reflect.Chan,
		reflect.Func,
		reflect.UnsafePointer:
		return val.IsNil()
	default:
		return false
	}
}
