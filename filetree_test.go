package pvc

import "testing"

func TestLocalfileBackendGetter(t *testing.T) {
	tb := &LocalfileBackend{
		rootPath: "testing",
	}
	_, err := newLocalfileBackendGetter(tb)
	if err != nil {
		t.Fatalf("should have succeeded: %v", err)
	}
}

func TestLocalfileBackendGetterGet(t *testing.T) {
	expectedValue := "DrFeelgood"
	tb := &LocalFileBackend{
		rootPath: "testing",
	}
	tbg, err := newLocalfileBackendGetter(tb)
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
