package api

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"net/http"

	"go.step.sm/crypto/pemutil"

	"go.step.sm/crypto/jose"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/errs"
)

// SignRequest is the request body for a certificate signature request.
type SignRequest struct {
	CsrPEM       CertificateRequest `json:"csr"`
	OTT          string             `json:"ott"`
	NotAfter     TimeDuration       `json:"notAfter,omitempty"`
	NotBefore    TimeDuration       `json:"notBefore,omitempty"`
	TemplateData json.RawMessage    `json:"templateData,omitempty"`
}

// Validate checks the fields of the SignRequest and returns nil if they are ok
// or an error if something is wrong.
func (s *SignRequest) Validate() error {
	if s.CsrPEM.CertificateRequest == nil {
		return errs.BadRequest("missing csr")
	}
	if err := s.CsrPEM.CertificateRequest.CheckSignature(); err != nil {
		return errs.Wrap(http.StatusBadRequest, err, "invalid csr")
	}
	if s.OTT == "" {
		return errs.BadRequest("missing ott")
	}

	return nil
}

func newJoseSigner(key crypto.Signer, so *jose.SignerOptions) (jose.Signer, error) {
	var alg jose.SignatureAlgorithm
	switch k := key.Public().(type) {
	case *ecdsa.PublicKey:
		switch k.Curve.Params().Name {
		case "P-256":
			alg = jose.ES256
		case "P-384":
			alg = jose.ES384
		case "P-521":
			alg = jose.ES512
		default:
			return nil, errors.Errorf("unsupported elliptic curve %s", k.Curve.Params().Name)
		}
	case ed25519.PublicKey:
		alg = jose.EdDSA
	case *rsa.PublicKey:
		alg = jose.DefaultRSASigAlgorithm
	default:
		return nil, errors.Errorf("unsupported key type %T", k)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, so)
	if err != nil {
		return nil, errors.Wrap(err, "error creating jose.Signer")
	}
	return signer, nil
}

func newJWKSigner(keyFile, password string) (jose.Signer, error) {
	signer, err := readKey(keyFile, password)
	if err != nil {
		return nil, err
	}
	kid, err := jose.Thumbprint(&jose.JSONWebKey{Key: signer.Public()})
	if err != nil {
		return nil, err
	}
	so := new(jose.SignerOptions)
	so.WithType("JWT")
	so.WithHeader("kid", kid)
	return newJoseSigner(signer, so)
}
func readKey(keyFile, password string) (crypto.Signer, error) {
	var opts []pemutil.Options
	if password != "" {
		opts = append(opts, pemutil.WithPassword([]byte(password)))
	}
	key, err := pemutil.Read(keyFile, opts...)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("key is not a crypto.Signer")
	}
	return signer, nil
}

// SignResponse is the response object of the certificate signature request.
type SignResponse struct {
	ServerPEM    Certificate          `json:"crt"`
	CaPEM        Certificate          `json:"ca"`
	CertChainPEM []Certificate        `json:"certChain"`
	TLSOptions   *config.TLSOptions   `json:"tlsOptions,omitempty"`
	TLS          *tls.ConnectionState `json:"-"`
}

// Sign is an HTTP handler that reads a certificate request and an
// one-time-token (ott) from the body and creates a new certificate with the
// information in the certificate request.
func (h *caHandler) Sign(w http.ResponseWriter, r *http.Request) {
	var body SignRequest
	if err := ReadJSON(r.Body, &body); err != nil {
		WriteError(w, errs.Wrap(http.StatusBadRequest, err, "error reading request body"))
		return
	}
	logOtt(w, body.OTT)
	if err := body.Validate(); err != nil {
		WriteError(w, err)
		return
	}
	opts := provisioner.SignOptions{
		NotBefore:    body.NotBefore,
		NotAfter:     body.NotAfter,
		TemplateData: body.TemplateData,
	}

	signOpts, overrideCert, overrideKey, err := h.Authority.AuthorizeSign(body.OTT)

	if err != nil {
		WriteError(w, errs.UnauthorizedErr(err))
		return
	}
	certChain, err := h.Authority.Sign(overrideCert, overrideKey, body.CsrPEM.CertificateRequest, opts, signOpts...)
	if err != nil {
		WriteError(w, errs.ForbiddenErr(err))
		return
	}
	certChainPEM := certChainToPEM(certChain)
	var caPEM Certificate
	if len(certChainPEM) > 1 {
		caPEM = certChainPEM[1]
	}
	LogCertificate(w, certChain[0])
	JSONStatus(w, &SignResponse{
		ServerPEM:    certChainPEM[0],
		CaPEM:        caPEM,
		CertChainPEM: certChainPEM,
		TLSOptions:   h.Authority.GetTLSOptions(),
	}, http.StatusCreated)
}
