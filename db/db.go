package db

import (
	"github.com/jackc/pgx"
	pgx_stdlib "github.com/jackc/pgx/stdlib"
	"github.com/jinzhu/gorm"
	"github.com/nutmegdevelopment/nutcracker/secrets"
)

var conn gorm.DB

// Connect connects to the database using env vars.
// After connect, it creates tables if missing.
func DBConnect() (err error) {
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

	conn, err = gorm.Open("postgres", c)
	if err != nil {
		return
	}

	d := conn.AutoMigrate(&secrets.Secret{}, &secrets.Key{})

	return d.Error
}

// AddSecret inserts a secret into the DB
func AddSecret(s *secrets.Secret) error {

	tx := conn.Begin()

	// Add the key, if missing
	if s.Key.Name != "" {

		d := tx.FirstOrCreate(&s.Key, &secrets.Key{Name: s.Key.Name})
		if d.Error != nil {
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
func AddKey(k *secrets.Key) error {
	return conn.FirstOrCreate(k, &secrets.Key{Name: k.Name}).Error
}

// GetKey selects a key from the database based on values provided in k.
func GetKey(k *secrets.Key) error {
	return conn.Find(k, k).Error
}

// Get Secrets returns all matching secrets from the database.
func GetSecrets(s *secrets.Secret) ([]secrets.Secret, error) {
	res := make([]secrets.Secret, 0)
	d := conn.Find(&res, s)
	return res, d.Error
}

func UpdateSecret(s secrets.Secret) error {
	return conn.Update(s).Error
}
