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

// GetRootSecret provides a mock function with given fields: _a0
func (_m *DB) GetRootSecret(_a0 *secrets.Secret) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*secrets.Secret) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetSharedSecret provides a mock function with given fields: _a0, _a1
func (_m *DB) GetSharedSecret(_a0 *secrets.Secret, _a1 *secrets.Key) error {
	ret := _m.Called(_a0, _a1)

	var r0 error
	if rf, ok := ret.Get(0).(func(*secrets.Secret, *secrets.Key) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ListSecrets provides a mock function with given fields: _a0
func (_m *DB) ListSecrets(_a0 *string) func(int) ([]secrets.Secret, error) {
	ret := _m.Called(_a0)

	var r0 func(int) ([]secrets.Secret, error)
	if rf, ok := ret.Get(0).(func(*string) func(int) ([]secrets.Secret, error)); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(func(int) ([]secrets.Secret, error))
		}
	}

	return r0
}

// ListKeys provides a mock function with given fields: _a0
func (_m *DB) ListKeys(_a0 *string) func(int) ([]secrets.Key, error) {
	ret := _m.Called(_a0)

	var r0 func(int) ([]secrets.Key, error)
	if rf, ok := ret.Get(0).(func(*string) func(int) ([]secrets.Key, error)); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(func(int) ([]secrets.Key, error))
		}
	}

	return r0
}

// DeleteSecret provides a mock function with given fields: _a0
func (_m *DB) DeleteSecret(_a0 *secrets.Secret) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*secrets.Secret) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteKey provides a mock function with given fields: _a0
func (_m *DB) DeleteKey(_a0 *secrets.Key) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*secrets.Key) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
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

// RotateMaster provides a mock function with given fields: _a0
func (_m *DB) RotateMaster(_a0 *secrets.Secret) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*secrets.Secret) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Ping provides a mock function with given fields:
func (_m *DB) Ping() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Metrics provides a mock function with given fields:
func (_m *DB) Metrics() (map[string]interface{}, error) {
	ret := _m.Called()

	var r0 map[string]interface{}
	if rf, ok := ret.Get(0).(func() map[string]interface{}); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string]interface{})
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
