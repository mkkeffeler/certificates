package sql

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/db/sql/sql"
)

// dbNonce contains nonce metadata used in the ACME protocol.
type dbNonce struct {
	ID        string
	CreatedAt time.Time
	DeletedAt time.Time
}

// CreateNonce creates, stores, and returns an ACME replay-nonce.
// Implements the acme.DB interface.
func (db *DB) CreateNonce(ctx context.Context) (acme.Nonce, error) {
	_id, err := randID()
	if err != nil {
		return "", errors.Wrapf(err, "error creating nonce.")
	}

	id := base64.RawURLEncoding.EncodeToString([]byte(_id))
	n := &dbNonce{
		ID:        id,
		CreatedAt: clock.Now(),
	}
	if err = db.save(ctx, id, n, nil, "nonce", nonceTable); err != nil {
		return "", errors.Wrapf(err, "error saving nonce %s", string(_id))
	}
	return acme.Nonce(id), nil
}

// DeleteNonce verifies that the nonce is valid (by checking if it exists),
// and if so, consumes the nonce resource by deleting it from the database.
func (db *DB) DeleteNonce(ctx context.Context, nonce acme.Nonce) error {
	err := db.db.Update(&sql.Tx{
		Operations: []*sql.TxEntry{
			{
				Bucket: nonceTable,
				Key:    []byte(nonce),
				Cmd:    sql.Get,
			},
			{
				Bucket: nonceTable,
				Key:    []byte(nonce),
				Cmd:    sql.Delete,
			},
		},
	})

	switch {
	case sql.IsErrNotFound(err):
		return acme.NewError(acme.ErrorBadNonceType, "nonce %s not found", string(nonce))
	case err != nil:
		return errors.Wrapf(err, "error deleting nonce %s", string(nonce))
	default:
		return nil
	}
}
