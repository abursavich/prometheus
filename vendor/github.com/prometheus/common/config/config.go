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

// This package no longer handles safe yaml parsing. In order to
// ensure correct yaml unmarshalling, use "yaml.UnmarshalStrict()".

package config

import (
	"fmt"
	"path/filepath"
	"reflect"
)

// Secret special type for storing secrets.
type Secret string

// MarshalYAML implements the yaml.Marshaler interface for Secrets.
func (s Secret) MarshalYAML() (interface{}, error) {
	if s != "" {
		return "<secret>", nil
	}
	return nil, nil
}

//UnmarshalYAML implements the yaml.Unmarshaler interface for Secrets.
func (s *Secret) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Secret
	return unmarshal((*plain)(s))
}

// JoinDir joins dir and path if path is relative.
// If path is empty or absolute, it is returned unchanged.
func JoinDir(dir, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(dir, path)
}

// DirectorySetter is a config type that contains file paths that may
// be relative to the file containing the config.
type DirectorySetter interface {
	// SetDirectory joins any relative file paths with dir.
	// Any paths that are empry or absolute remain unchanged.
	SetDirectory(dir string)
}

type seenMap map[interface{}]reflect.Value

// Clone returns a deep clone of v.
// Any unexported fields will be unset.
func Clone(v interface{}) interface{} {
	src := reflect.ValueOf(v)
	dst := reflect.New(src.Type()).Elem()
	reflectCopy(dst, src, seenMap{})
	return dst.Interface()
}

func reflectCopy(dst, src reflect.Value, seen seenMap) {
	typ := src.Type()
	if typ != dst.Type() {
		panic(fmt.Sprintf("config: internal error: type mismatch: %v != %v", typ, dst.Type()))
	}
	if isNil(src) {
		return
	}
	if val, ok := ifaceClone(src); ok {
		dst.Set(val)
		return
	}
	switch src.Kind() {
	case reflect.Struct:
		// dst.Set(src) // TODO: Share unexported values?
		for i, n := 0, typ.NumField(); i < n; i++ {
			if typ.Field(i).PkgPath != "" {
				continue // Field is unexported.
			}
			reflectCopy(dst.Field(i), src.Field(i), seen)
		}
	case reflect.Map:
		dst.Set(reflect.MakeMap(typ))
		for _, key := range src.MapKeys() {
			keyVal := reflect.New(typ.Key()).Elem()
			reflectCopy(keyVal, key, seen)
			val := reflect.New(typ.Elem()).Elem()
			reflectCopy(val, src.MapIndex(key), seen)
			dst.SetMapIndex(keyVal, val)
		}
	case reflect.Slice:
		dst.Set(reflect.MakeSlice(typ, src.Len(), src.Len()))
		for i, n := 0, src.Len(); i < n; i++ {
			reflectCopy(dst.Index(i), src.Index(i), seen)
		}
	case reflect.Array:
		for i, n := 0, src.Len(); i < n; i++ {
			reflectCopy(dst.Index(i), src.Index(i), seen)
		}
	case reflect.Ptr:
		if val, cyclic := seen[src.Interface()]; cyclic {
			dst.Set(val)
			return
		}
		ptr := reflect.New(typ.Elem())
		seen[src.Interface()] = ptr
		dst.Set(ptr)
		reflectCopy(ptr.Elem(), src.Elem(), seen)
	case reflect.Interface:
		val := reflect.New(src.Elem().Type()).Elem()
		reflectCopy(val, src.Elem(), seen)
		dst.Set(val)
	default:
		dst.Set(src)
	}
}

func ifaceClone(src reflect.Value) (reflect.Value, bool) {
	method := src.MethodByName("Clone")
	if !method.IsValid() {
		if src.CanAddr() && src.Kind() != reflect.Ptr {
			if v, ok := ifaceClone(src.Addr()); ok {
				return v.Elem(), true
			}
		}
		return reflect.Value{}, false
	}
	if typ := method.Type(); typ.NumIn() != 0 || typ.NumOut() != 1 || typ.Out(0) != src.Type() {
		return reflect.Value{}, false
	}
	return method.Call(nil)[0], true
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
