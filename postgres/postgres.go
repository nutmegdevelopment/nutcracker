package postgres

import (
	"database/sql"
	"errors"
	"github.com/jackc/pgx"
	pgx_stdlib "github.com/jackc/pgx/stdlib"
	"github.com/jinzhu/gorm"
	"github.com/nutmegdevelopment/nutcracker/secrets"
)

// DB is an implemntation of the db.DB interface
type DB struct {
	conn *gorm.DB
}

// Connect connects to the database using env vars.
// After connect, it creates tables if missing.
func (p *DB) Connect() (err error) {
	cfg, err := pgx.ParseEnvLibpq()
	if err != nil {
		return
	}

	pool, err := pgx.NewConnPool(pgx.ConnPoolConfig{
		ConnConfig:     cfg,
		MaxConnections: 25,
	})
	if err != nil {
		return
	}

	c, err := pgx_stdlib.OpenFromConnPool(pool)
	if err != nil {
		return
	}

	p.conn, err = gorm.Open("postgres", c)
	if err != nil {
		return
	}

	d := p.conn.AutoMigrate(&secrets.Secret{}, &secrets.Key{})

	return d.Error
}

func (p *DB) refresh() error {
	err := p.conn.DB().Ping()
	if err != nil {
		return p.Connect()
	}
	return nil
}

// Ping checks that the database is connected
func (p *DB) Ping() (err error) {
	return p.conn.DB().Ping()
}

// AddSecret inserts a new secret into the DB
func (p *DB) AddSecret(s *secrets.Secret) error {

	if err := p.refresh(); err != nil {
		return err
	}

	if s.Root {
		where := &secrets.Secret{Name: s.Name, Root: true}
		d := p.conn.Find(&secrets.Secret{}, where)
		if d.Error == nil {
			return errors.New("Secret already exists")
		}
		if d.Error != gorm.ErrRecordNotFound {
			return d.Error
		}
	}

	d := p.conn.Find(&secrets.Key{}, &secrets.Key{Name: s.Key.Name})
	switch {

	case d.Error == gorm.ErrRecordNotFound:
		err := p.conn.Create(&s.Key).Error
		if err != nil {
			return err
		}

	case d.Error != nil:
		return d.Error

	}

	return p.addSecret(s)
}

func (p *DB) addSecret(s *secrets.Secret) error {
	return p.conn.Create(s).Error
}

// AddKey inserts a key into the DB
func (p *DB) AddKey(k *secrets.Key) error {
	if err := p.refresh(); err != nil {
		return err
	}

	return p.conn.Create(k).Error
}

// GetKey selects a key from the database based on values provided in k.
func (p *DB) GetKey(k *secrets.Key) error {
	if err := p.refresh(); err != nil {
		return err
	}

	return p.conn.Find(k, k).Error
}

// GetRootSecret returns the latest matching root secret
func (p *DB) GetRootSecret(s *secrets.Secret) error {
	if err := p.refresh(); err != nil {
		return err
	}

	s.Root = true
	d := p.conn.Order("id asc").Find(s, s)
	if d.Error != nil {
		return d.Error
	}
	return p.conn.Find(&s.Key, s.KeyID).Error
}

// GetSharedSecret returns the shared cert linking s and k
func (p *DB) GetSharedSecret(s *secrets.Secret, k *secrets.Key) error {
	if err := p.refresh(); err != nil {
		return err
	}
	// We don't use a join due to conflicting columns
	err := p.GetKey(k)
	if err != nil {
		return err
	}

	s.Root = false
	s.KeyID = k.ID
	d := p.conn.Order("id asc").Find(s, s)
	if d.Error != nil {
		return d.Error
	}
	return p.conn.Find(&s.Key, s.KeyID).Error
}

// UpdateSecret updates a secret by adding a new copy of it to the db.
func (p *DB) UpdateSecret(s *secrets.Secret) error {
	if err := p.refresh(); err != nil {
		return err
	}
	// we need a new ID
	s.ID = 0
	return p.addSecret(s)
}

// ListSecrets returns an iterator function that walks through all secrets in the database.
// The iterator takes an integer argument, which is the maximum number of results to return per iteration.
// If a key name is specified, the results are limited to secrets shared with that key.
func (p *DB) ListSecrets(key *string) func(int) ([]secrets.Secret, error) {
	pos := 0

	return func(n int) (res []secrets.Secret, err error) {
		if err := p.refresh(); err != nil {
			return nil, err
		}

		var rows *sql.Rows

		if key != nil {
			rows, err = p.conn.Table("secrets").Select(
				"secrets.id, secrets.name, secrets.message, secrets.nonce, secrets.pubkey, secrets.key_id").Joins(
				"left join keys on secrets.key_id = keys.id").Where(
				"keys.name = ?", *key).Order("id asc").Limit(n).Offset(pos).Rows()
		} else {
			rows, err = p.conn.Table("secrets").Select("id, name, message, nonce, pubkey, key_id").Order("id asc").Limit(n).Offset(pos).Rows()
		}

		for rows.Next() {
			out := new(secrets.Secret)
			err = rows.Scan(&out.ID, &out.Name, &out.Message, &out.Nonce, &out.Pubkey, &out.KeyID)
			if err != nil {
				return
			}
			res = append(res, *out)
		}
		err = rows.Close()
		pos += len(res)
		return
	}
}

// ListKeys returns an iterator function that walks through all keys in the database.
// The iterator takes an integer argument, which is the maximum number of results to return per iteration.
// If a secret name is specified, the results are limited to keys with access to that secret.
func (p *DB) ListKeys(secret *string) func(int) ([]secrets.Key, error) {
	pos := 0

	return func(n int) (res []secrets.Key, err error) {
		if err := p.refresh(); err != nil {
			return nil, err
		}

		var rows *sql.Rows

		if secret != nil {
			rows, err = p.conn.Table("keys").Select(
				"keys.id, keys.name, keys.key, keys.nonce, keys.public, keys.read_only").Joins(
				"left join secrets on keys.id = secrets.key_id").Where(
				"secrets.name = ?", *secret).Order("id asc").Limit(n).Offset(pos).Rows()
		} else {
			rows, err = p.conn.Table("keys").Select("id, name, key, nonce, public, read_only").Order("id asc").Limit(n).Offset(pos).Rows()
		}

		for rows.Next() {
			out := new(secrets.Key)
			var ro sql.NullBool
			err = rows.Scan(&out.ID, &out.Name, &out.Key, &out.Nonce, &out.Public, &ro)
			if err != nil {
				return
			}
			if ro.Valid {
				out.ReadOnly = ro.Bool
			} else {
				out.ReadOnly = false
			}
			res = append(res, *out)
		}
		err = rows.Close()
		pos += len(res)
		return
	}
}

// DeleteSecret removes a secret from the DB
func (p *DB) DeleteSecret(s *secrets.Secret) (err error) {
	if s == nil || s.ID == 0 {
		return errors.New("No secret specified")
	}

	if s.Name == "master" {
		return errors.New("Cannot delete master")
	}

	return p.conn.Delete(s).Error
}

// DeleteKey removes a key from the DB
func (p *DB) DeleteKey(k *secrets.Key) (err error) {
	if k == nil || k.ID == 0 {
		return errors.New("No key specified")
	}

	if k.Name == "master" {
		return errors.New("Cannot delete master")
	}

	return p.conn.Delete(k).Error
}

// Metrics returns data about the state of the database
func (p *DB) Metrics() (map[string]interface{}, error) {
	metrics := make(map[string]interface{})
	var count int

	err := p.conn.Table("secrets").Count(&count).Error
	if err != nil {
		return metrics, err
	}
	metrics["secrets"] = count

	err = p.conn.Table("keys").Count(&count).Error
	if err != nil {
		return metrics, err
	}
	metrics["keys"] = count

	return metrics, nil
}
