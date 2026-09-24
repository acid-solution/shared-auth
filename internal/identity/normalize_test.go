package identity

import "testing"

func TestNormalizeEmail(t *testing.T) {
	got, err := NormalizeEmail("  Person@Example.COM ")
	if err != nil || got != "person@example.com" {
		t.Fatalf("NormalizeEmail() = %q, %v", got, err)
	}
	for _, value := range []string{"", "name", "a@", "a@example.com\nBcc:x@y.com"} {
		if _, err := NormalizeEmail(value); err == nil {
			t.Fatalf("NormalizeEmail(%q) unexpectedly succeeded", value)
		}
	}
}
