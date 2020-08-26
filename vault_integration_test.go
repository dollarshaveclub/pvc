package pvc

import (
	"log"
	"os"
	"testing"
)

const (
	testSecretPath = "secret/development/test_value"
)

var testvb = vaultBackend{
	host:               os.Getenv("VAULT_ADDR"),
	appid:              os.Getenv("VAULT_TEST_APPID"),
	userid:             os.Getenv("VAULT_TEST_USERID"),
	token:              os.Getenv("VAULT_TEST_TOKEN"),
	authRetries:        3,
	authRetryDelaySecs: 1,
}

func testGetVaultClient(t *testing.T) *vaultClient {
	vc, err := newVaultClient(&testvb)
	if err != nil {
		log.Fatalf("error creating client: %v", err)
	}
	return vc
}

func TestVaultIntegrationAppIDAuth(t *testing.T) {
	if testvb.host == "" {
		t.Skipf("VAULT_ADDR undefined, skipping")
		return
	}
	vc := testGetVaultClient(t)
	err := vc.AppIDAuth(testvb.appid, testvb.userid, "")
	if err != nil {
		log.Fatalf("error authenticating: %v", err)
	}
}

func TestVaultIntegrationTokenAuth(t *testing.T) {
	if testvb.host == "" {
		t.Skipf("VAULT_ADDR undefined, skipping")
		return
	}
	vc := testGetVaultClient(t)
	err := vc.TokenAuth(testvb.token)
	if err != nil {
		log.Fatalf("error authenticating: %v", err)
	}
}

func TestVaultIntegrationGetValue(t *testing.T) {
	if testvb.host == "" {
		t.Skipf("VAULT_ADDR undefined, skipping")
		return
	}
	vc := testGetVaultClient(t)
	err := vc.AppIDAuth(testvb.appid, testvb.userid, "")
	if err != nil {
		t.Fatalf("error authenticating: %v", err)
	}
	s, err := vc.GetValue(testSecretPath)
	if err != nil {
		t.Fatalf("error getting value: %v", err)
	}
	if string(s) != "foo" {
		t.Fatalf("bad value: %v (expected 'foo')", string(s))
	}
}
