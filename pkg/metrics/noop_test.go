// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package metrics_test

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aetomala/jwtauth/pkg/metrics"
)

var _ = Describe("NoOpMetrics", func() {
	var noop *metrics.NoOpMetrics

	BeforeEach(func() {
		noop = metrics.NewNoOpMetrics()
	})

	It("should return a non-nil instance", func() {
		Expect(noop).NotTo(BeNil())
	})

	It("should satisfy the Metrics interface", func() {
		var _ metrics.Metrics = noop // compile-time assertion
	})

	It("should not panic on IncrementCounter", func() {
		Expect(func() { noop.IncrementCounter("any", map[string]string{"k": "v"}) }).NotTo(Panic())
		Expect(func() { noop.IncrementCounter("any", nil) }).NotTo(Panic())
	})

	It("should not panic on AddCounter", func() {
		Expect(func() { noop.AddCounter("any", 5.0, map[string]string{}) }).NotTo(Panic())
	})

	It("should not panic on SetGauge", func() {
		Expect(func() { noop.SetGauge("any", 100.0, map[string]string{}) }).NotTo(Panic())
	})

	It("should not panic on RecordHistogram", func() {
		Expect(func() { noop.RecordHistogram("any", 0.5, map[string]string{}) }).NotTo(Panic())
	})

	It("should not panic on RecordDuration", func() {
		Expect(func() { noop.RecordDuration("any", 250*time.Millisecond, map[string]string{}) }).NotTo(Panic())
	})
})
