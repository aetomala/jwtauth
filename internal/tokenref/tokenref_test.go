// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package tokenref_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aetomala/jwtauth/internal/tokenref"
)

func TestTokenRef(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "TokenRef Suite")
}

var _ = Describe("Ref", func() {
	const token = "xF7hN2kP9mQ8rT4vL6wY3gAaBbCcDdEeFfGgHhIiJjK"

	It("should be deterministic", func() {
		Expect(tokenref.Ref(token)).To(Equal(tokenref.Ref(token)))
	})

	It("should return 16 lowercase hex characters", func() {
		Expect(tokenref.Ref(token)).To(MatchRegexp(`^[0-9a-f]{16}$`))
	})

	It("should return the SHA-256 digest prefix", func() {
		// sha256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
		Expect(tokenref.Ref("abc")).To(Equal("ba7816bf8f01cfea"))
	})

	It("should return empty string for empty input", func() {
		Expect(tokenref.Ref("")).To(BeEmpty())
	})

	It("should produce different outputs for different inputs", func() {
		Expect(tokenref.Ref(token)).NotTo(Equal(tokenref.Ref(token + "x")))
		Expect(tokenref.Ref("a")).NotTo(Equal(tokenref.Ref("b")))
	})

	It("should not contain the input", func() {
		Expect(tokenref.Ref(token)).NotTo(ContainSubstring(token))
	})
})
