package pvc

import (
	"fmt"
	"io/ioutil"
)

// Default mapping for this backend
const (
	DefaultFileTreeMapping = "{{ .ID }}"
	DefaultFileTreeRootPath = "/vault/secrets"
	// TODO make this overrideable through cmd flags
	MaxFileTreeFileSizeBytes = "2_000_000" // 2 MB```"
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
	return &fileTreeBackendGetter{
		mapper:   sm,
		config:   ft,
		contents: c,
	}, nil
}

func (ftg *fileTreeBackendGetter) Get(id string) ([]byte, error) {
	fi, err := os.Stat(fmt.Sprintf("%v/%v", ftg.rootPath, id)
	if err != nil {
		return err
	}
	size := fi.Size()
	if size > MaxFileTreeFileSizeBytes {
		return nil, fmt.Errorf("file tree error secret file to large: %v", err)
	}
	if c, err := ioutil.ReadFile(ft.fileLocation); err != nil {
		return nil, fmt.Errorf("file tree error reading file location %v", err)
	}
	key, err := ftg.mapper.MapSecret(id)
	if err != nil {
		return nil, fmt.Errorf("error mapping id to object key: %v", err)
	}
	if val, ok := ftg.contents[key]; ok {
		return []byte(val), nil
	}
	return nil, fmt.Errorf("secret not found: %v", key)
}
