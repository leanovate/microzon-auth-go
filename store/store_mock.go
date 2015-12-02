// Automatically generated by MockGen. DO NOT EDIT!
// Source: ./store/store.go

package store

import (
	x509 "crypto/x509"
	gomock "github.com/golang/mock/gomock"
	common "github.com/leanovate/microzon-auth-go/common"
	time "time"
)

// Mock of Store interface
type MockStore struct {
	ctrl     *gomock.Controller
	recorder *_MockStoreRecorder
}

// Recorder for MockStore (not exported)
type _MockStoreRecorder struct {
	mock *MockStore
}

func NewMockStore(ctrl *gomock.Controller) *MockStore {
	mock := &MockStore{ctrl: ctrl}
	mock.recorder = &_MockStoreRecorder{mock}
	return mock
}

func (_m *MockStore) EXPECT() *_MockStoreRecorder {
	return _m.recorder
}

func (_m *MockStore) AddCertificate(thumbprint string, certificate *x509.Certificate) error {
	ret := _m.ctrl.Call(_m, "AddCertificate", thumbprint, certificate)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockStoreRecorder) AddCertificate(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "AddCertificate", arg0, arg1)
}

func (_m *MockStore) FindCertificate(thumbprint string) (*x509.Certificate, error) {
	ret := _m.ctrl.Call(_m, "FindCertificate", thumbprint)
	ret0, _ := ret[0].(*x509.Certificate)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockStoreRecorder) FindCertificate(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "FindCertificate", arg0)
}

func (_m *MockStore) AllCertificates() ([]*x509.Certificate, error) {
	ret := _m.ctrl.Call(_m, "AllCertificates")
	ret0, _ := ret[0].([]*x509.Certificate)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockStoreRecorder) AllCertificates() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "AllCertificates")
}

func (_m *MockStore) RemoveCertificate(thumbprint string) error {
	ret := _m.ctrl.Call(_m, "RemoveCertificate", thumbprint)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockStoreRecorder) RemoveCertificate(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "RemoveCertificate", arg0)
}

func (_m *MockStore) AddRevocation(sha256 common.RawSha256, expiresAt time.Time) error {
	ret := _m.ctrl.Call(_m, "AddRevocation", sha256, expiresAt)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockStoreRecorder) AddRevocation(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "AddRevocation", arg0, arg1)
}

func (_m *MockStore) SetRevocationsListener(listener func(uint64, common.RawSha256, time.Time)) {
	_m.ctrl.Call(_m, "SetRevocationsListener", listener)
}

func (_mr *_MockStoreRecorder) SetRevocationsListener(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "SetRevocationsListener", arg0)
}

func (_m *MockStore) Close() {
	_m.ctrl.Call(_m, "Close")
}

func (_mr *_MockStoreRecorder) Close() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Close")
}
