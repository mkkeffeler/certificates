package sql

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/db/sql"
)

type dbCert struct {
	ID            string    `json:"id"`
	CreatedAt     time.Time `json:"createdAt"`
	AccountID     string    `json:"accountID"`
	OrderID       string    `json:"orderID"`
	Leaf          []byte    `json:"leaf"`
	Intermediates []byte    `json:"intermediates"`
}

// CreateCertificate creates and stores an ACME certificate type.
func (db *DB) CreateCertificate(ctx context.Context, cert *acme.Certificate, provisionerName string) error {
	var err error
	cert.ID, err = randID()
	if err != nil {
		return err
	}
	leaf := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Leaf.Raw,
	})
	var intermediates []byte
	for _, cert := range cert.Intermediates {
		intermediates = append(intermediates, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}

	dbch := &dbCert{
		ID:            cert.ID,
		AccountID:     cert.AccountID,
		OrderID:       cert.OrderID,
		Leaf:          leaf,
		Intermediates: intermediates,
		CreatedAt:     time.Now().UTC(),
	}
	return db.saveACMECertificate(ctx, []byte(cert.ID), cert.Leaf, dbch, nil, "certificate", certTable, ACMEcertExtensionsTable, ACMEcertSANsTable, provisionerName)
}

// GetCertificate retrieves and unmarshals an ACME certificate type from the
// datastore.
func (db *DB) GetCertificate(ctx context.Context, id string) (*acme.Certificate, error) {
	b, err := db.db.Get(certTable, []byte(id))
	if sql.IsErrNotFound(err) {
		return nil, acme.NewError(acme.ErrorMalformedType, "certificate %s not found", id)
	} else if err != nil {
		return nil, errors.Wrapf(err, "error loading certificate %s", id)
	}
	dbC := new(dbCert)
	if err := json.Unmarshal(b, dbC); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling certificate %s", id)
	}

	certs, err := parseBundle(append(dbC.Leaf, dbC.Intermediates...))
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing certificate chain for ACME certificate with ID %s", id)
	}

	return &acme.Certificate{
		ID:            dbC.ID,
		AccountID:     dbC.AccountID,
		OrderID:       dbC.OrderID,
		Leaf:          certs[0],
		Intermediates: certs[1:],
	}, nil
}

func parseBundle(b []byte) ([]*x509.Certificate, error) {
	var (
		err    error
		block  *pem.Block
		bundle []*x509.Certificate
	)
	for len(b) > 0 {
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, errors.New("error decoding PEM: data contains block that is not a certificate")
		}
		var crt *x509.Certificate
		crt, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.Wrapf(err, "error parsing x509 certificate")
		}
		bundle = append(bundle, crt)
	}
	if len(b) > 0 {
		return nil, errors.New("error decoding PEM: unexpected data")
	}
	return bundle, nil

}
