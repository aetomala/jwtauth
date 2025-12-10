package jwtauth_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestJwtauth(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Jwtauth Suite")
}
