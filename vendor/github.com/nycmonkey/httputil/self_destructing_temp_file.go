package httputil

import (
	"io"
	"io/ioutil"
	"net/http"
	"os"
)

type TempFile interface {
	http.File
	Name() string
	io.Writer
}

type selfDestructingFile struct {
	f TempFile
}

func NewSelfDestructingTempFile(dir, prefix string) (tf TempFile, err error) {
	var f *os.File
	f, err = ioutil.TempFile(dir, prefix)
	if err != nil {
		return
	}
	return &selfDestructingFile{f}, nil
}

func (sdf *selfDestructingFile) Close() error {
	_ = sdf.f.Close()
	return os.Remove(sdf.f.Name())
}

func (sdf *selfDestructingFile) Readdir(count int) ([]os.FileInfo, error) {
	return sdf.f.Readdir(count)
}

func (sdf *selfDestructingFile) Name() string {
	return sdf.f.Name()
}

func (sdf *selfDestructingFile) Read(p []byte) (n int, err error) {
	return sdf.f.Read(p)
}

func (sdf *selfDestructingFile) Write(p []byte) (n int, err error) {
	return sdf.f.Write(p)
}

func (sdf *selfDestructingFile) Seek(offset int64, whence int) (int64, error) {
	return sdf.f.Seek(offset, whence)
}

func (sdf *selfDestructingFile) Stat() (os.FileInfo, error) {
	return sdf.f.Stat()
}
