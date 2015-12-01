// Automatically generated by MockGen. DO NOT EDIT!
// Source: ./store/store.go

package store

import (
	x509 "crypto/x509"
	gomock "github.com/golang/mock/gomock"
	certificates "github.com/leanovate/microzon-auth-go/certificates"
	revocations "github.com/leanovate/microzon-auth-go/revocations"
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

func (_m *MockStore) SelfCertificate() (*certificates.CertWithKey, error) {
	ret := _m.ctrl.Call(_m, "SelfCertificate")
	ret0, _ := ret[0].(*certificates.CertWithKey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockStoreRecorder) SelfCertificate() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "SelfCertificate")
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

func (_m *MockStore) CertificateByThumbprint(x5t string) (*x509.Certificate, error) {
	ret := _m.ctrl.Call(_m, "CertificateByThumbprint", x5t)
	ret0, _ := ret[0].(*x509.Certificate)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockStoreRecorder) CertificateByThumbprint(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "CertificateByThumbprint", arg0)
}

func (_m *MockStore) AddRevocation(sha256 revocations.RawSha256, expiresAt time.Time) error {
	ret := _m.ctrl.Call(_m, "AddRevocation", sha256, expiresAt)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockStoreRecorder) AddRevocation(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "AddRevocation", arg0, arg1)
}

func (_m *MockStore) ListRevocations(sinceVersion uint64, maxLength uint) (*revocations.RevocationListVO, error) {
	ret := _m.ctrl.Call(_m, "ListRevocations", sinceVersion, maxLength)
	ret0, _ := ret[0].(*revocations.RevocationListVO)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockStoreRecorder) ListRevocations(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "ListRevocations", arg0, arg1)
}

func (_m *MockStore) CurrentRevocationsVersion() uint64 {
	ret := _m.ctrl.Call(_m, "CurrentRevocationsVersion")
	ret0, _ := ret[0].(uint64)
	return ret0
}

func (_mr *_MockStoreRecorder) CurrentRevocationsVersion() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "CurrentRevocationsVersion")
}

func (_m *MockStore) ObserveRevocationsVersion(version uint64, timeout time.Duration) chan revocations.ObserveState {
	ret := _m.ctrl.Call(_m, "ObserveRevocationsVersion", version, timeout)
	ret0, _ := ret[0].(chan revocations.ObserveState)
	return ret0
}

func (_mr *_MockStoreRecorder) ObserveRevocationsVersion(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "ObserveRevocationsVersion", arg0, arg1)
}

func (_m *MockStore) IsRevoked(sha256 revocations.RawSha256) (bool, error) {
	ret := _m.ctrl.Call(_m, "IsRevoked", sha256)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockStoreRecorder) IsRevoked(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "IsRevoked", arg0)
}

func (_m *MockStore) Close() {
	_m.ctrl.Call(_m, "Close")
}

func (_mr *_MockStoreRecorder) Close() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Close")
}
