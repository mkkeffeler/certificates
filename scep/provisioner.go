package scep

import (
	"context"
	"time"

	"github.com/smallstep/certificates/authority/provisioner"
)

// Provisioner is an interface that implements a subset of the provisioner.Interface --
// only those methods required by the SCEP api/authority.
type Provisioner interface {
	AuthorizeSign(ctx context.Context, token string) (options []provisioner.SignOption, intermediateCert string, intermediateKey string, err error)
	GetName() string
	DefaultTLSCertDuration() time.Duration
	GetOptions() *provisioner.Options
	GetChallengePassword() string
	GetCapabilities() []string
}
