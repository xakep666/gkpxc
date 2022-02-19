package gkpxc

import "net"

type clientConfig struct {
	customConn         net.Conn
	errorHandlers      []func(err error)
	lockChangeHandlers []func(locked bool)
}

type ClientOption func(o *clientConfig)

// WithConn sets custom connection for client. It will not be closed by Client.Close.
func WithConn(conn net.Conn) ClientOption {
	return func(o *clientConfig) {
		o.customConn = conn
	}
}

// WithAsyncErrorHandler adds async error handler. Such errors may occur on signal read.
func WithAsyncErrorHandler(handler func(err error)) ClientOption {
	return func(o *clientConfig) {
		o.errorHandlers = append(o.errorHandlers, handler)
	}
}

// WithLockChangeHandler adds lock/unlock signal handler.
func WithLockChangeHandler(handler func(locked bool)) ClientOption {
	return func(o *clientConfig) {
		o.lockChangeHandlers = append(o.lockChangeHandlers, handler)
	}
}
