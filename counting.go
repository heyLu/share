package main

import (
	"io"
	"net/http"
)

var _ io.ReadCloser = &countingReader{}

type countingReader struct {
	io.ReadCloser
	countFn func(bytesWritten int)
}

func CountingReadCloser(r io.ReadCloser, countFn func(int)) io.ReadCloser {
	return &countingReader{
		ReadCloser: r,
		countFn:    countFn,
	}
}

func (cr *countingReader) Read(p []byte) (n int, err error) {
	n, err = cr.ReadCloser.Read(p)
	cr.countFn(n)
	return n, err
}

type countingResponseWriter struct {
	http.ResponseWriter
	countFn func(int)
}

func CountingResponseWriter(w http.ResponseWriter, countFn func(int)) http.ResponseWriter {
	return &countingResponseWriter{
		ResponseWriter: w,
		countFn:        countFn,
	}
}

func (cw *countingResponseWriter) Write(p []byte) (n int, err error) {
	n, err = cw.ResponseWriter.Write(p)
	cw.countFn(n)
	return n, err
}
