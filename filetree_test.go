package pvc

import "testing"

func TestFileTreeBackendGetter(t *testing.T) {
	tb := &fileTreeBackend{
		rootPath: "testing",
	}
	_, err := newFileTreeBackendGetter(tb)
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
}

func TestFileTreeBackendGetterGet(t *testing.T) {
	expectedValue := "DrFeelgood"
	tb := &fileTreeBackend{
		rootPath: "testing",
	}
	tbg, err := newFileTreeBackendGetter(tb)
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
	sid := "username"
	s, err := tbg.Get(sid)
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if string(s) != expectedValue {
		t.Fatalf("bad value: %v (expected %v)", string(s), expectedValue)
	}
}
