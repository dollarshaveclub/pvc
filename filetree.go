package pvc

import (
	"fmt"
	"os"
	"io/ioutil"
)

// Default mapping for this backend
const (
	DefaultFileTreeMapping = "{{ .ID }}"
	DefaultFileTreeRootPath = "/vault/secrets"
	// TODO make this overrideable through cmd flags
	MaxFileTreeFileSizeBytes = 2_000_000 // 2 MB```"
)

type fileTreeBackendGetter struct {
	mapper   SecretMapper
	config   *fileTreeBackend
	rootPath string
}

func newFileTreeBackendGetter(ft *fileTreeBackend) (*fileTreeBackendGetter, error) {
	// TODO _ check for optional FileTreeRootPath override and handle accordingly 
	if ft.mapping == "" {
		ft.mapping = DefaultFileTreeMapping
	}
	sm, err := newSecretMapper(ft.mapping)
	if err != nil {
		return nil, fmt.Errorf("file tree error with mapping: %v", err)
	}
	if ft.rootPath == "" {
		ft.rootPath = DefaultFileTreeRootPath
	}
	return &fileTreeBackendGetter{
		mapper:   sm,
		config:   ft,
	}, nil
}


func (ftg *fileTreeBackendGetter) Get(id string) ([]byte, error) {
	secretFilePath := fmt.Sprintf("%v/%v", ftg.rootPath, id)
	fi, err := os.Stat(secretFilePath)
	if err != nil {
		return nil, fmt.Errorf("file tree error, error getting file stats :%v", err)
	}
	size := fi.Size()
	if size > MaxFileTreeFileSizeBytes {
		return nil, fmt.Errorf("file tree error secret file to large: %v", err)
	}
	if c, err := ioutil.ReadFile(secretFilePath); err != nil {
		return []byte(c), nil
	}
	return nil, fmt.Errorf("file tree error retrieving secret %v at path %v : %v", id, secretFilePath, err)
}
