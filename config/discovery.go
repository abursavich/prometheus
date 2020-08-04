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
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/prometheus/prometheus/discovery/discoverer"
	"github.com/prometheus/prometheus/discovery/targetgroup"
	"gopkg.in/yaml.v2"
)

const (
	configFieldPrefix      = "AUTO_"
	staticConfigsKey       = "static_configs"
	staticConfigsFieldName = configFieldPrefix + staticConfigsKey
)

var (
	configNames      = make(map[string]discoverer.Config)
	configFieldNames = make(map[reflect.Type]string)
	configFields     []reflect.StructField
	configTypes      sync.Map // map[reflect.Type]reflect.Type

	emptyStructType            = reflect.TypeOf(struct{}{})
	serviceDiscoveryConfigType = reflect.TypeOf(discoverer.ServiceDiscoveryConfig{})
)

// RegisterServiceDiscovery registers the given Config type along with the YAML key for the
// list of its type in the Configs object.
func RegisterServiceDiscovery(config discoverer.Config) {
	registerServiceDiscovery(config.Name()+"_sd_configs", reflect.TypeOf(config), config)
}

func init() {
	// N.B.: static_configs is the only Config type implemented by default.
	// All other types are registered at init by their implementing packages.
	elemTyp := reflect.TypeOf(&targetgroup.Group{})
	registerServiceDiscovery(staticConfigsKey, elemTyp, discoverer.StaticConfig{})
}

func registerServiceDiscovery(yamlKey string, elemType reflect.Type, config discoverer.Config) {
	name := config.Name()
	if _, ok := configNames[name]; ok {
		panic(fmt.Sprintf("config: service discovery config named %q is already registered", name))
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
	if v, ok := configTypes.Load(out); ok {
		return v.(reflect.Type)
	}
	// initial exported fields map one-to-one
	var fields []reflect.StructField
	for i := 0; i < out.NumField(); i++ {
		switch field := out.Field(i); {
		case field.PkgPath == "": // TODO(abursavich): && field.Type != configSliceType:
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
	typ, _ := configTypes.LoadOrStore(out, reflect.StructOf(fields))
	return typ.(reflect.Type)
}

func unmarshalWithDiscoveryConfigs(out interface{}, unmarshal func(interface{}) error) error {
	outVal := reflect.ValueOf(out)
	if outVal.Kind() != reflect.Ptr {
		panic("config: internal error: can only unmarshal into a struct pointer")
	}
	outVal = outVal.Elem()
	if outVal.Kind() != reflect.Struct {
		panic("config: internal error: can only unmarshal into a struct pointer")
	}
	outTyp := outVal.Type()

	cfgTyp := getConfigType(outTyp)
	cfgPtr := reflect.New(cfgTyp)
	cfgVal := cfgPtr.Elem()

	// copy shared fields (defaults) to dynamic value
	var configs *[]discoverer.Config
	for i := 0; i < outVal.NumField(); i++ {
		if cfgTyp.Field(i).PkgPath != "" {
			continue // field is unexported: ignore
		}
		if outTyp.Field(i).Type == serviceDiscoveryConfigType { // TODO(abursavich): change to configSliceType
			configs = &outVal.Field(i).Addr().Interface().(*discoverer.ServiceDiscoveryConfig).Configs
		}
		cfgVal.Field(i).Set(outVal.Field(i))
	}
	if configs == nil {
		panic("config: internal error: service discovery configs field not found")
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

	// collect dynamic discoverer.Config values
	var targets []*targetgroup.Group
	for i := outVal.NumField(); i < cfgVal.NumField(); i++ {
		field := cfgVal.Field(i)
		if field.Kind() != reflect.Slice {
			panic("config: internal error: field is not a slice")
		}
		for k := 0; k < field.Len(); k++ {
			val := field.Index(k)
			if val.IsZero() || (val.Kind() == reflect.Ptr && val.Elem().IsZero()) {
				key := configFieldNames[field.Type().Elem()]
				key = strings.TrimPrefix(key, configFieldPrefix)
				return errors.New("empty or null section in " + key)
			}
			switch c := val.Interface().(type) {
			case *targetgroup.Group:
				// Add index to the static config target groups for unique identification
				// within scrape pool.
				c.Source = strconv.Itoa(len(targets))
				// coalesce multiple static configs into a single static config
				targets = append(targets, c)
			case discoverer.Config:
				*configs = append(*configs, c)
			default:
				panic("config: internal error: slice element is not a discoverer.Config")
			}

		}
	}
	if len(targets) > 0 {
		*configs = append(*configs, discoverer.StaticConfig(targets))
	}
	return nil
}

func marshalWithDiscoveryConfigs(cfg interface{}) (interface{}, error) {
	cfgVal := reflect.ValueOf(cfg)
	for cfgVal.Kind() == reflect.Ptr {
		cfgVal = cfgVal.Elem()
	}
	cfgTyp := cfgVal.Type()

	outTyp := getConfigType(cfgTyp)
	outPtr := reflect.New(outTyp)
	outVal := outPtr.Elem()

	// copy shared fields to dynamic value
	var configs *[]discoverer.Config
	for i := 0; i < cfgVal.NumField(); i++ {
		if outTyp.Field(i).PkgPath != "" {
			continue // field is unexported: ignore
		}
		if cfgTyp.Field(i).Type == serviceDiscoveryConfigType { // TODO(abursavich): change to configSliceType
			configs = &cfgVal.Field(i).Addr().Interface().(*discoverer.ServiceDiscoveryConfig).Configs
		}
		outVal.Field(i).Set(cfgVal.Field(i))
	}
	if configs == nil {
		panic("config: internal error: service discovery configs field not found")
	}

	// collect dynamic discoverer.Config values
	targets := outVal.FieldByName(staticConfigsFieldName).Addr().Interface().(*[]*targetgroup.Group)
	for _, c := range *configs {
		if sc, ok := c.(discoverer.StaticConfig); ok {
			*targets = append(*targets, sc...)
			continue
		}
		fieldName, ok := configFieldNames[reflect.TypeOf(c)]
		if !ok {
			return nil, errors.Errorf("cannot marshal unregistered Config type: %T", c)
		}
		field := outVal.FieldByName(fieldName)
		field.Set(reflect.Append(field, reflect.ValueOf(c)))
	}

	return outPtr.Interface(), nil
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
