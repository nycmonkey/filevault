package httputil

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/http"
)

func TlsVersion(v uint16) string {
	switch v {
	case tls.VersionSSL30:
		return `SSL30`
	case tls.VersionTLS10:
		return `TLS10`
	case tls.VersionTLS11:
		return `TLS11`
	case tls.VersionTLS12:
		return `TLS12`
	}
	return "Unknown"
}

type ResponseWriterLogger interface {
	http.ResponseWriter
	http.Flusher
	Status() int
	Size() int
}

type responseLogger struct {
	w            http.ResponseWriter
	status, size int
}

type hijackLogger struct {
	responseLogger
}

type hijackCloseNotifier struct {
	ResponseWriterLogger
	http.Hijacker
	http.CloseNotifier
}

type closeNotifyWriter struct {
	ResponseWriterLogger
	http.CloseNotifier
}

func (l *responseLogger) Header() http.Header {
	return l.w.Header()
}

func (l *responseLogger) Write(b []byte) (int, error) {
	if l.status == 0 {
		// The status will be StatusOK if WriteHeader has not been called yet
		l.status = http.StatusOK
	}
	size, err := l.w.Write(b)
	l.size += size
	return size, err
}

func (l *responseLogger) WriteHeader(s int) {
	l.w.WriteHeader(s)
	l.status = s
}

func (l *responseLogger) Status() int {
	return l.status
}

func (l *responseLogger) Size() int {
	return l.size
}

func (l *responseLogger) Flush() {
	f, ok := l.w.(http.Flusher)
	if ok {
		f.Flush()
	}
}

func (l *hijackLogger) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h := l.responseLogger.w.(http.Hijacker)
	conn, rw, err := h.Hijack()
	if err == nil && l.responseLogger.status == 0 {
		// The status will be StatusSwitchingProtocols if there was no error and
		// WriteHeader has not been called yet
		l.responseLogger.status = http.StatusSwitchingProtocols
	}
	return conn, rw, err
}

func NewResponseWriterLogger(w http.ResponseWriter) ResponseWriterLogger {
	var logger ResponseWriterLogger = &responseLogger{w: w}
	if _, ok := w.(http.Hijacker); ok {
		logger = &hijackLogger{responseLogger{w: w}}
	}
	h, ok1 := logger.(http.Hijacker)
	c, ok2 := w.(http.CloseNotifier)
	if ok1 && ok2 {
		return hijackCloseNotifier{logger, h, c}
	}
	if ok2 {
		return &closeNotifyWriter{logger, c}
	}
	return logger
}
