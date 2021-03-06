// Automatically generated by MockGen. DO NOT EDIT!
// Source: github.com/leanovate/microzon-auth-go/store (interfaces: AgentStore)

package store

import (
	x509 "crypto/x509"
	gomock "github.com/golang/mock/gomock"
	common "github.com/leanovate/microzon-auth-go/common"
)

// Mock of AgentStore interface
type MockAgentStore struct {
	ctrl     *gomock.Controller
	recorder *_MockAgentStoreRecorder
}

// Recorder for MockAgentStore (not exported)
type _MockAgentStoreRecorder struct {
	mock *MockAgentStore
}

func NewMockAgentStore(ctrl *gomock.Controller) *MockAgentStore {
	mock := &MockAgentStore{ctrl: ctrl}
	mock.recorder = &_MockAgentStoreRecorder{mock}
	return mock
}

func (_m *MockAgentStore) EXPECT() *_MockAgentStoreRecorder {
	return _m.recorder
}

func (_m *MockAgentStore) AllCertificates() ([]*x509.Certificate, error) {
	ret := _m.ctrl.Call(_m, "AllCertificates")
	ret0, _ := ret[0].([]*x509.Certificate)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockAgentStoreRecorder) AllCertificates() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "AllCertificates")
}

func (_m *MockAgentStore) Close() {
	_m.ctrl.Call(_m, "Close")
}

func (_mr *_MockAgentStoreRecorder) Close() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Close")
}

func (_m *MockAgentStore) FindCertificate(_param0 string) (*x509.Certificate, error) {
	ret := _m.ctrl.Call(_m, "FindCertificate", _param0)
	ret0, _ := ret[0].(*x509.Certificate)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockAgentStoreRecorder) FindCertificate(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "FindCertificate", arg0)
}

func (_m *MockAgentStore) SetRevocationsListener(_param0 common.RevocationsListener) error {
	ret := _m.ctrl.Call(_m, "SetRevocationsListener", _param0)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockAgentStoreRecorder) SetRevocationsListener(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "SetRevocationsListener", arg0)
}
