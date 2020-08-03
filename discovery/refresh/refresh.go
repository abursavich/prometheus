// Copyright 2019 The Prometheus Authors
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

package refresh

import (
	"context"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/prometheus/prometheus/discovery"
	"github.com/prometheus/prometheus/discovery/targetgroup"
)

var (
	failuresCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "prometheus_sd_refresh_failures_total",
			Help: "Number of refresh failures for the given SD mechanism.",
		},
		[]string{"mechanism"},
	)
	duration = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "prometheus_sd_refresh_duration_seconds",
			Help:       "The duration of a refresh in seconds for the given SD mechanism.",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"mechanism"},
	)
)

func init() {
	prometheus.MustRegister(duration, failuresCount)
}

// A Refresher refreshes a set of target groups.
type Refresher interface {
	Refresh(ctx context.Context) ([]*targetgroup.Group, error)
	Name() string
}

// discoverer implements the Discoverer interface.
type discoverer struct {
	logger    log.Logger
	interval  time.Duration
	refresher Refresher

	failures prometheus.Counter
	duration prometheus.Observer
}

// NewDiscoverer returns a Discoverer that uses the refresher to refresh its targets at every interval.
func NewDiscoverer(logger log.Logger, interval time.Duration, refresher Refresher) discovery.Discoverer {
	if logger == nil {
		logger = log.NewNopLogger()
	}
	return &discoverer{
		logger:    logger,
		interval:  interval,
		refresher: refresher,
		failures:  failuresCount.WithLabelValues(refresher.Name()),
		duration:  duration.WithLabelValues(refresher.Name()),
	}
}

// NewDiscovery returns a Discoverer function that calls a refresh() function at every interval.
func NewDiscovery(l log.Logger, mech string, interval time.Duration, refreshf func(ctx context.Context) ([]*targetgroup.Group, error)) discovery.Discoverer {
	return NewDiscoverer(l, interval, &refresher{
		name:    mech,
		refresh: refreshf,
	})
}

// Run implements the Discoverer interface.
func (d *discoverer) Run(ctx context.Context, ch chan<- []*targetgroup.Group) {
	// Get an initial set right away.
	tgs, err := d.refresh(ctx)
	if err != nil {
		if ctx.Err() != context.Canceled {
			level.Error(d.logger).Log("msg", "Unable to refresh target groups", "err", err.Error())
		}
	} else {
		select {
		case ch <- tgs:
		case <-ctx.Done():
			return
		}
	}

	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			tgs, err := d.refresh(ctx)
			if err != nil {
				if ctx.Err() != context.Canceled {
					level.Error(d.logger).Log("msg", "Unable to refresh target groups", "err", err.Error())
				}
				continue
			}

			select {
			case ch <- tgs:
			case <-ctx.Done():
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func (d *discoverer) refresh(ctx context.Context) ([]*targetgroup.Group, error) {
	now := time.Now()
	defer d.duration.Observe(time.Since(now).Seconds())
	tgs, err := d.refresher.Refresh(ctx)
	if err != nil {
		d.failures.Inc()
	}
	return tgs, err
}

// TODO(abursavich): CLEANUP: remove refresher and NewDiscovery once they are unused

type refresher struct {
	name    string
	refresh func(ctx context.Context) ([]*targetgroup.Group, error)
}

func (r *refresher) Name() string { return r.name }
func (r *refresher) Refresh(ctx context.Context) ([]*targetgroup.Group, error) {
	return r.refresh(ctx)
}
