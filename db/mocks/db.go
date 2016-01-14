package mocks

import "github.com/stretchr/testify/mock"

import "github.com/nutmegdevelopment/nutcracker/secrets"

type DB struct {
	mock.Mock
}

// Connect provides a mock function with given fields:
func (_m *DB) Connect() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AddSecret provides a mock function with given fields: _a0
func (_m *DB) AddSecret(_a0 *secrets.Secret) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*secrets.Secret) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AddKey provides a mock function with given fields: _a0
func (_m *DB) AddKey(_a0 *secrets.Key) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*secrets.Key) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetKey provides a mock function with given fields: _a0
func (_m *DB) GetKey(_a0 *secrets.Key) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*secrets.Key) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetSecrets provides a mock function with given fields: _a0
func (_m *DB) GetSecrets(_a0 *secrets.Secret) ([]secrets.Secret, error) {
	ret := _m.Called(_a0)

	var r0 []secrets.Secret
	if rf, ok := ret.Get(0).(func(*secrets.Secret) []secrets.Secret); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]secrets.Secret)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*secrets.Secret) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdateSecret provides a mock function with given fields: _a0
func (_m *DB) UpdateSecret(_a0 *secrets.Secret) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*secrets.Secret) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
