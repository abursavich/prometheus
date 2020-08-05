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

package discovery

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/prometheus/prometheus/discovery/targetgroup"
	"gopkg.in/yaml.v2"
)

const (
	configFieldPrefix      = "AUTO_DISCOVERY_"
	staticConfigsKey       = "static_configs"
	staticConfigsFieldName = configFieldPrefix + staticConfigsKey
)

var (
	configNames      = make(map[string]Config)
	configFieldNames = make(map[reflect.Type]string)
	configFields     []reflect.StructField

	configTypesMu sync.Mutex
	configTypes   = make(map[reflect.Type]reflect.Type)

	emptyStructType = reflect.TypeOf(struct{}{})
	configsType     = reflect.TypeOf(Configs{})
)

// RegisterConfig registers the given Config type for YAML marshaling and unmarshaling.
func RegisterConfig(config Config) {
	registerConfig(config.Name()+"_sd_configs", reflect.TypeOf(config), config)
}

func init() {
	// N.B.: static_configs is the only Config type implemented by default.
	// All other types are registered at init by their implementing packages.
	elemTyp := reflect.TypeOf(&targetgroup.Group{})
	registerConfig(staticConfigsKey, elemTyp, StaticConfig{})
}

func registerConfig(yamlKey string, elemType reflect.Type, config Config) {
	name := config.Name()
	if _, ok := configNames[name]; ok {
		panic(fmt.Sprintf("discovery: Config named %q is already registered", name))
	}
	configNames[name] = config

	fieldName := configFieldPrefix + yamlKey // must be exported
	configFieldNames[elemType] = fieldName

	// insert fields in sorted order
	i := sort.Search(len(configFields), func(k int) bool {
		return fieldName < configFields[k].Name
	})
	configFields = append(configFields, reflect.StructField{}) // add empty field at end
	copy(configFields[i+1:], configFields[i:])                 // shift fields to the right
	configFields[i] = reflect.StructField{                     // write new field in place
		Name: fieldName,
		Type: reflect.SliceOf(elemType),
		Tag:  reflect.StructTag(`yaml:"` + yamlKey + `,omitempty"`),
	}
}

func getConfigType(out reflect.Type) reflect.Type {
	configTypesMu.Lock()
	defer configTypesMu.Unlock()
	if typ, ok := configTypes[out]; ok {
		return typ
	}
	// initial exported fields map one-to-one
	var fields []reflect.StructField
	for i := 0; i < out.NumField(); i++ {
		switch field := out.Field(i); {
		case field.PkgPath == "" && field.Type != configsType:
			fields = append(fields, field)
		default:
			fields = append(fields, reflect.StructField{
				Name:    "_" + field.Name, // unexported
				PkgPath: out.PkgPath(),
				Type:    emptyStructType,
			})
		}
	}
	// append extra config fields on the end
	fields = append(fields, configFields...)
	typ := reflect.StructOf(fields)
	configTypes[out] = typ
	return typ
}

// UnmarshalYAMLWithInlineConfigs helps implement yaml.Unmarshal for structs
// that have a Configs field that should be inlined.
func UnmarshalYAMLWithInlineConfigs(out interface{}, unmarshal func(interface{}) error) error {
	// This function can be removed if https://github.com/go-yaml/yaml/issues/642 is fixed.

	outVal := reflect.ValueOf(out)
	if outVal.Kind() != reflect.Ptr {
		// TODO: panic?
		return fmt.Errorf("discovery: can only unmarshal into a struct pointer: %T", out)
	}
	outVal = outVal.Elem()
	if outVal.Kind() != reflect.Struct {
		// TODO: panic?
		return fmt.Errorf("discovery: can only unmarshal into a struct pointer: %T", out)
	}
	outTyp := outVal.Type()

	cfgTyp := getConfigType(outTyp)
	cfgPtr := reflect.New(cfgTyp)
	cfgVal := cfgPtr.Elem()

	// copy shared fields (defaults) to dynamic value
	var configs *Configs
	for i := 0; i < outVal.NumField(); i++ {
		if outTyp.Field(i).Type == configsType {
			configs = outVal.Field(i).Addr().Interface().(*Configs)
			continue
		}
		if cfgTyp.Field(i).PkgPath != "" {
			continue // field is unexported: ignore
		}
		cfgVal.Field(i).Set(outVal.Field(i))
	}
	if configs == nil {
		// TODO: panic?
		return fmt.Errorf("discovery: Configs field not found in type: %T", out)
	}

	// unmarshal into dynamic value
	if err := unmarshal(cfgPtr.Interface()); err != nil {
		return replaceYAMLTypeError(err, cfgTyp, outTyp)
	}

	// copy shared fields from dynamic value
	for i := 0; i < outVal.NumField(); i++ {
		if cfgTyp.Field(i).PkgPath != "" {
			continue // field is unexported: ignore
		}
		outVal.Field(i).Set(cfgVal.Field(i))
	}

	var err error
	*configs, err = readConfigs(cfgVal, outVal.NumField())
	return err
}

func readConfigs(structVal reflect.Value, startField int) (Configs, error) {
	var (
		configs Configs
		targets []*targetgroup.Group
	)
	for i := startField; i < structVal.NumField(); i++ {
		field := structVal.Field(i)
		if field.Kind() != reflect.Slice {
			panic("discovery: internal error: field is not a slice")
		}
		for k := 0; k < field.Len(); k++ {
			val := field.Index(k)
			if val.IsZero() || (val.Kind() == reflect.Ptr && val.Elem().IsZero()) {
				key := configFieldNames[field.Type().Elem()]
				key = strings.TrimPrefix(key, configFieldPrefix)
				return nil, fmt.Errorf("empty or null section in %s", key)
			}
			switch c := val.Interface().(type) {
			case *targetgroup.Group:
				// Add index to the static config target groups for unique identification
				// within scrape pool.
				c.Source = strconv.Itoa(len(targets))
				// coalesce multiple static configs into a single static config
				targets = append(targets, c)
			case Config:
				configs = append(configs, c)
			default:
				panic("discovery: internal error: slice element is not a Config")
			}
		}
	}
	if len(targets) > 0 {
		configs = append(configs, StaticConfig(targets))
	}
	return configs, nil
}

// MarshalYAMLWithInlineConfigs helps implement yaml.Marshal for structs
// that have a Configs field that should be inlined.
func MarshalYAMLWithInlineConfigs(in interface{}) (interface{}, error) {
	// This function can be removed if https://github.com/go-yaml/yaml/issues/642 is fixed.

	inVal := reflect.ValueOf(in)
	for inVal.Kind() == reflect.Ptr {
		inVal = inVal.Elem()
	}
	inType := inVal.Type()

	cfgTyp := getConfigType(inType)
	cfgPtr := reflect.New(cfgTyp)
	cfgVal := cfgPtr.Elem()

	// copy shared fields to dynamic value
	var configs *Configs
	for i := 0; i < inVal.NumField(); i++ {
		if inType.Field(i).Type == configsType {
			configs = inVal.Field(i).Addr().Interface().(*Configs)
		}
		if cfgTyp.Field(i).PkgPath != "" {
			continue // field is unexported: ignore
		}
		cfgVal.Field(i).Set(inVal.Field(i))
	}
	if configs == nil {
		// TODO: panic?
		return nil, fmt.Errorf("discovery: Configs field not found in type: %T", in)
	}

	if err := writeConfigs(cfgVal, *configs); err != nil {
		return nil, err
	}

	return cfgPtr.Interface(), nil
}

func writeConfigs(structVal reflect.Value, configs Configs) error {
	targets := structVal.FieldByName(staticConfigsFieldName).Addr().Interface().(*[]*targetgroup.Group)
	for _, c := range configs {
		if sc, ok := c.(StaticConfig); ok {
			*targets = append(*targets, sc...)
			continue
		}
		fieldName, ok := configFieldNames[reflect.TypeOf(c)]
		if !ok {
			return fmt.Errorf("discovery: cannot marshal unregistered Config type: %T", c)
		}
		field := structVal.FieldByName(fieldName)
		field.Set(reflect.Append(field, reflect.ValueOf(c)))
	}
	return nil
}

func replaceYAMLTypeError(err error, oldTyp, newTyp reflect.Type) error {
	if e, ok := err.(*yaml.TypeError); ok {
		oldStr := oldTyp.String()
		newStr := newTyp.String()
		for i, s := range e.Errors {
			e.Errors[i] = strings.Replace(s, oldStr, newStr, -1)
		}
	}
	return err
}
