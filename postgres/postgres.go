package postgres

import (
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

// AddSecret inserts a secret into the DB
func (p *DB) AddSecret(s *secrets.Secret) error {

	tx := p.conn.Begin()

	// Add the key, if missing
	if s.Key.Name != "" {
		d := tx.Find(&s.Key)
		if d.Error == gorm.RecordNotFound {

			d := tx.Create(&s.Key)
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
	return p.conn.FirstOrCreate(k, &secrets.Key{Name: k.Name}).Error
}

// GetKey selects a key from the database based on values provided in k.
func (p *DB) GetKey(k *secrets.Key) error {
	return p.conn.Find(k, k).Error
}

// GetRootSecret returns the latest matching root secret
func (p *DB) GetRootSecret(s *secrets.Secret) error {
	s.Root = true
	return p.conn.Order("id desc").Find(s, s).Error
}

// GetSharedSecret returns the shared cert linking s and k
func (p *DB) GetSharedSecret(s *secrets.Secret, k *secrets.Key) error {
	// We don't use a join due to conflicting columns
	err := p.GetKey(k)
	if err != nil {
		return err
	}

	s.Root = false
	s.KeyID = k.ID
	return p.conn.Order("id, desc").Find(s, s).Error
}

// UpdateSecret updates a secret
func (p *DB) UpdateSecret(s *secrets.Secret) error {
	return p.conn.Update(s).Error
}
