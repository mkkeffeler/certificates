package sql

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/db/sql/sqldatabase"
	"github.com/smallstep/nosql/database"
)

func TestDB_CreateNonce(t *testing.T) {
	type test struct {
		db  sqldatabase.SQLDB
		err error
		_id *string
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/cmpAndSwap-error": func(t *testing.T) test {
			return test{
				db: &db.MockSQLDB{
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, nonceTable)
						assert.Equals(t, old, nil)

						dbn := new(dbNonce)
						assert.FatalError(t, json.Unmarshal(nu, dbn))
						assert.Equals(t, dbn.ID, string(key))
						assert.True(t, clock.Now().Add(-time.Minute).Before(dbn.CreatedAt))
						assert.True(t, clock.Now().Add(time.Minute).After(dbn.CreatedAt))
						return nil, false, errors.New("force")
					},
				},
				err: errors.New("error saving acme nonce: force"),
			}
		},
		"ok": func(t *testing.T) test {
			var (
				id    string
				idPtr = &id
			)

			return test{
				db: &db.MockSQLDB{
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						*idPtr = string(key)
						assert.Equals(t, bucket, nonceTable)
						assert.Equals(t, old, nil)

						dbn := new(dbNonce)
						assert.FatalError(t, json.Unmarshal(nu, dbn))
						assert.Equals(t, dbn.ID, string(key))
						assert.True(t, clock.Now().Add(-time.Minute).Before(dbn.CreatedAt))
						assert.True(t, clock.Now().Add(time.Minute).After(dbn.CreatedAt))
						return nil, true, nil
					},
				},
				_id: idPtr,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			db := DB{db: tc.db}
			if n, err := db.CreateNonce(context.Background()); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, string(n), *tc._id)
				}
			}
		})
	}
}

func TestDB_DeleteNonce(t *testing.T) {

	nonceID := "nonceID"
	type test struct {
		db      sqldatabase.SQLDB
		err     error
		acmeErr *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				db: &db.MockSQLDB{
					MUpdate: func(tx *sqldatabase.Tx) error {
						assert.Equals(t, tx.Operations[0].Bucket, nonceTable)
						assert.Equals(t, tx.Operations[0].Key, []byte(nonceID))
						assert.Equals(t, tx.Operations[0].Cmd, database.Get)

						assert.Equals(t, tx.Operations[1].Bucket, nonceTable)
						assert.Equals(t, tx.Operations[1].Key, []byte(nonceID))
						assert.Equals(t, tx.Operations[1].Cmd, database.Delete)
						return database.ErrNotFound
					},
				},
				acmeErr: acme.NewError(acme.ErrorBadNonceType, "nonce %s not found", nonceID),
			}
		},
		"fail/db.Update-error": func(t *testing.T) test {
			return test{
				db: &db.MockSQLDB{
					MUpdate: func(tx *sqldatabase.Tx) error {
						assert.Equals(t, tx.Operations[0].Bucket, nonceTable)
						assert.Equals(t, tx.Operations[0].Key, []byte(nonceID))
						assert.Equals(t, tx.Operations[0].Cmd, database.Get)

						assert.Equals(t, tx.Operations[1].Bucket, nonceTable)
						assert.Equals(t, tx.Operations[1].Key, []byte(nonceID))
						assert.Equals(t, tx.Operations[1].Cmd, database.Delete)
						return errors.New("force")
					},
				},
				err: errors.New("error deleting nonce nonceID: force"),
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				db: &db.MockSQLDB{
					MUpdate: func(tx *sqldatabase.Tx) error {
						assert.Equals(t, tx.Operations[0].Bucket, nonceTable)
						assert.Equals(t, tx.Operations[0].Key, []byte(nonceID))
						assert.Equals(t, tx.Operations[0].Cmd, database.Get)

						assert.Equals(t, tx.Operations[1].Bucket, nonceTable)
						assert.Equals(t, tx.Operations[1].Key, []byte(nonceID))
						assert.Equals(t, tx.Operations[1].Cmd, database.Delete)
						return nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			db := DB{db: tc.db}
			if err := db.DeleteNonce(context.Background(), acme.Nonce(nonceID)); err != nil {
				switch k := err.(type) {
				case *acme.Error:
					if assert.NotNil(t, tc.acmeErr) {
						assert.Equals(t, k.Type, tc.acmeErr.Type)
						assert.Equals(t, k.Detail, tc.acmeErr.Detail)
						assert.Equals(t, k.Status, tc.acmeErr.Status)
						assert.Equals(t, k.Err.Error(), tc.acmeErr.Err.Error())
						assert.Equals(t, k.Detail, tc.acmeErr.Detail)
					}
				default:
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}
