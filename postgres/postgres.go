package postgres

import (
	"errors"
	"github.com/jackc/pgx"
	pgx_stdlib "github.com/jackc/pgx/stdlib"
	"github.com/jinzhu/gorm"
	"github.com/nutmegdevelopment/nutcracker/secrets"
)

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
func (p *DB) ListSecrets() func(int) ([]secrets.Secret, error) {
	pos := 0
	return func(n int) (res []secrets.Secret, err error) {
		if err := p.refresh(); err != nil {
			return nil, err
		}
		s := new(secrets.Secret)
		s.Root = false
		rows, err := p.conn.Order("id asc").Limit(n).Offset(pos).Find(s).Rows()
		for rows.Next() {
			out := new(secrets.Secret)
			err = rows.Scan(&out.ID, &out.Name, &out.Message, &out.Nonce, &out.Pubkey, &out.KeyID, &out.Root)
			if err != nil {
				return
			}
			res = append(res, *out)
		}
		rows.Close()
		pos = len(res)
		return
	}
}

// ListKeys returns an iterator function that walks through all keys in the database.
// The iterator takes an integer argument, which is the maximum number of results to return per iteration.
func (p *DB) ListKeys() func(int) ([]secrets.Key, error) {
	pos := 0
	return func(n int) (res []secrets.Key, err error) {
		if err := p.refresh(); err != nil {
			return nil, err
		}
		k := new(secrets.Key)
		rows, err := p.conn.Order("id asc").Limit(n).Offset(pos).Find(k).Rows()
		for rows.Next() {
			out := new(secrets.Key)
			err = rows.Scan(&out.ID, &out.Name, &out.Key, &out.Nonce, &out.Public, &out.ReadOnly)
			if err != nil {
				return
			}
			res = append(res, *out)
		}
		rows.Close()
		pos = len(res)
		return
	}
}
