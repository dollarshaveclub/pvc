package pvc

import (
	"encoding/base64"
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
	key, err := ftg.mapper.MapSecret(id)
	if err != nil {
		return nil, fmt.Errorf("file tree error mapping secret id %v : %v", id, err)
	}
	secretFilePath := fmt.Sprintf("%v/%v", ftg.config.rootPath, key)
	fi, err := os.Stat(secretFilePath)
	if err != nil {
		return nil, fmt.Errorf("file tree error, error getting file stats :%v", err)
	}
	size := fi.Size()
	if size > MaxFileTreeFileSizeBytes {
		return nil, fmt.Errorf("file tree error secret file to large: %v", err)
	}
	c, err := ioutil.ReadFile(secretFilePath)
	if err != nil {
		return nil , fmt.Errorf("file tree error reading file: %v", err)
	}
	d, err := base64.StdEncoding.DecodeString(string(c))
	if err != nil {
		// not base64 encoded
		return c, nil
	}
	return d, nil
}
