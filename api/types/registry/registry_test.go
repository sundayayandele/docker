package registry

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRegistryTypesRegURL(t *testing.T) {
	reg := RegURL{}

	// unofficial & insecure
	if err := reg.Parse("http://valid.address.com:1234/path"); err != nil {
		t.Fatalf("valid address must not fail: %s", err)
	}
	assert.Equal(t, "valid.address.com:1234", reg.Host())
	assert.Equal(t, "valid.address.com:1234/path", reg.Prefix())
	assert.Equal(t, "http", reg.Scheme())
	assert.Equal(t, false, reg.IsSecure())
	assert.Equal(t, false, reg.IsOfficial())
	assert.Equal(t, "http://valid.address.com:1234/path", reg.String())

	// unofficial & secure
	if err := reg.Parse("https://valid.address.com:8080"); err != nil {
		t.Fatalf("valid address must not fail: %s", err)
	}
	assert.Equal(t, true, reg.IsSecure())
	assert.Equal(t, false, reg.IsOfficial())

	// default to "https" if no URI scheme is specified
	if err := reg.Parse("unspecified-scheme.address.com"); err != nil {
		t.Fatalf("valid address must not fail: %s", err)
	}
	assert.Equal(t, true, reg.IsSecure())
	assert.Equal(t, false, reg.IsOfficial())

	// official and secure
	if err := reg.Parse("https://docker.io"); err != nil {
		t.Fatalf("valid address must not fail: %s", err)
	}
	assert.Equal(t, true, reg.IsSecure())
	assert.Equal(t, true, reg.IsOfficial())

	// unspecified host
	if err := reg.Parse("http://"); err == nil {
		t.Fatal("invalid address must fail")
	}

	// unsupported scheme
	if err := reg.Parse("htpx://test.com"); err == nil {
		t.Fatal("invalid address must fail")
	}

	// user/password not allowed
	if err := reg.Parse("https://user:password@test.com"); err == nil {
		t.Fatal("invalid address must fail")
	}
}

func TestRegistryTypesMirror(t *testing.T) {
	// insecure
	if mir, err := NewMirror("http://insecure.mirror.com"); err != nil {
		t.Fatalf("valid mirror must not fail: %s", err)
	} else {
		assert.Equal(t, false, mir.URL.IsSecure())
	}

	// secure
	if mir, err := NewMirror("https://secure.mirror.com"); err != nil {
		t.Fatalf("valid mirror must not fail: %s", err)
	} else {
		assert.Equal(t, true, mir.URL.IsSecure())
	}

	// default to secure
	if mir, err := NewMirror("secure.mirror.com"); err != nil {
		t.Fatalf("valid mirror must not fail: %s", err)
	} else {
		assert.Equal(t, true, mir.URL.IsSecure())
	}

	// invalid
	if _, err := NewMirror("htpx://invalid.mirror.com"); err == nil {
		t.Fatal("invalid mirror must fail")
	}
}

func TestRegistryTypesRegistry(t *testing.T) {
	// insecure
	if reg, err := NewRegistry("http://insecure.registry.com"); err != nil {
		t.Fatalf("valid registry must not fail: %s", err)
	} else {
		assert.Equal(t, false, reg.URL.IsSecure())
	}

	// secure
	if reg, err := NewRegistry("https://secure.registry.com"); err != nil {
		t.Fatalf("valid registry must not fail: %s", err)
	} else {
		assert.Equal(t, true, reg.URL.IsSecure())
	}

	// default to secure
	if reg, err := NewRegistry("secure.registry.com"); err != nil {
		t.Fatalf("valid registry must not fail: %s", err)
	} else {
		assert.Equal(t, true, reg.URL.IsSecure())
	}

	// invalid
	if _, err := NewRegistry("htpx://invalid.registry.com"); err == nil {
		t.Fatal("invalid registry must fail")
	}

	// secure with mirrors
	if reg, err := NewRegistry("https://secure.registry.com"); err != nil {
		t.Fatalf("valid registry must not fail: %s", err)
	} else {
		assert.Equal(t, true, reg.URL.IsSecure())
		// adding secure mirror
		if err := reg.AddMirror("https://secure.mirror.com"); err != nil {
			t.Fatalf("adding valid mirror must not fail: %s", err)
		}
		if !reg.ContainsMirror("https://secure.mirror.com") {
			t.Fatal("registry should contain mirror")
		}
		// adding insecure mirror (will only yield a warning for a secure registry)
		if err := reg.AddMirror("http://insecure.mirror.com"); err != nil {
			t.Fatalf("adding valid mirror must not fail: %s", err)
		}
		if !reg.ContainsMirror("http://insecure.mirror.com") {
			t.Fatal("registry should contain mirror")
		}
		// add invalid mirror
		if err := reg.AddMirror("htpx://invalid.mirror.com"); err == nil {
			t.Fatal("adding invalid mirror must fail")
		}
	}
}
