package bundle

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/sevenzip"
)

func MakeBundleFile(path string) resource.BundleFile {
	if path == "" {
		return nil
	}
	return func() (fs.File, error) {
		if _, err := os.Stat(C.Path.BundleMRS()); os.IsNotExist(err) {
			return nil, fmt.Errorf("bundle file not exist: %s", C.Path.BundleMRS())
		}
		r, err := sevenzip.OpenReader(C.Path.BundleMRS())
		if err != nil {
			return nil, fmt.Errorf("open bundle file error: %w", err)
		}
		f, err := r.Open(path)
		if err != nil {
			_ = r.Close()
			return nil, fmt.Errorf("open path in bundle file error: %w", err)
		}
		return file{f, r}, nil
	}
}

type file struct {
	fs.File
	closer io.Closer
}

func (f file) Close() error {
	err1 := f.File.Close()
	err2 := f.closer.Close()
	return errors.Join(err1, err2)
}
