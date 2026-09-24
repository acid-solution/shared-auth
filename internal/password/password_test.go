package password

import "testing"

func TestHasher(t *testing.T) {
	hasher := NewHasher(4)
	hash, err := hasher.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !hasher.Compare(hash, "correct horse battery staple") {
		t.Fatal("correct password was rejected")
	}
	if hasher.Compare(hash, "incorrect password") {
		t.Fatal("incorrect password was accepted")
	}
	if _, err := hasher.Hash("short"); err == nil {
		t.Fatal("short password was accepted")
	}
}
