package postgres

import (
	"errors"
	"github.com/jackc/pgx"
	pgx_stdlib "github.com/jackc/pgx/stdlib"
	"github.com/jinzhu/gorm"
	"github.com/nutmegdevelopment/nutcracker/secrets"
)

type DB struct {
	conn gorm.DB
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
		if d.Error != gorm.RecordNotFound {
			return d.Error
		}
	}
	return p.addSecret(s)
}

func (p *DB) addSecret(s *secrets.Secret) error {
	tx := p.conn.Begin()

	// Add the key, if missing
	if s.Key.Name != "" {
		d := tx.Find(&s.Key)
		if d.Error == gorm.RecordNotFound {

			d = tx.Create(&s.Key)
			if d.Error != nil {
				tx.Rollback()
				return d.Error
			}

		} else if d.Error != nil {
			tx.Rollback()
			return d.Error
		}

		s.KeyID = s.Key.ID

	}

	d := tx.Create(s)
	if d.Error != nil {
		tx.Rollback()
		return d.Error
	}

	return tx.Commit().Error
}

// AddKey inserts a key into the DB
func (p *DB) AddKey(k *secrets.Key) error {
	if err := p.refresh(); err != nil {
		return err
	}

	return p.conn.FirstOrCreate(k, &secrets.Key{Name: k.Name}).Error
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
