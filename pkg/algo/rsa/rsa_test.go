package rsakp

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"reflect"
	"testing"

	"github.com/harmony-one/asym-key-pkgs/pkg/akp"
)

func dumpKeyPackage(t *testing.T, val interface{}) {
	if bytes, err := asn1.Marshal(val); err == nil {
		t.Logf("base64 encoding: %s", base64.StdEncoding.EncodeToString(bytes))
	} else {
		t.Errorf("cannot marshal key package: %v", err)
	}
}

func TestRoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("cannot generate RSA key pair: %v", err)
	}
	subtest := func(t *testing.T, pub interface{}) {
		pkg, err := Packer.Pack(priv, pub)
		if err != nil {
			t.Fatalf("cannot pack RSA key pair: %v", err)
		}
		dumpKeyPackage(t, *pkg)
		priv2, pub2, extras, err := Unpacker.Unpack(pkg)
		if err != nil {
			t.Fatalf("cannot unpack RSA key pair: %v", err)
		}
		if !reflect.DeepEqual(priv, priv2) {
			t.Errorf("reconstructed key %+v is different from the original %+v "+
				"(pkg is %+v)", priv2, priv, pkg,
			)
		}
		if !reflect.DeepEqual(pub, pub2) {
			t.Errorf("expected public key %+v but got %+v", pub, pub2)
		}
		if len(extras) > 0 {
			t.Errorf("no extras were expected, but got some: %+v", extras)
		}
	}
	t.Run("WithoutPublic", func(t *testing.T) { subtest(t, nil) })
	t.Run("WithPublic", func(t *testing.T) { subtest(t, priv.Public()) })
}

func TestPacker_Pack(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("cannot generate RSA key pair: %v", err)
	}
	t.Run("BadPrivateKey", func(t *testing.T) {
        for _, priv := range []interface{}{
        	nil, 0, 1, "", "OMG", struct{}{},
		} {
            t.Run(fmt.Sprintf("%v", priv), func(t *testing.T) {
            	pkg, err := Packer.Pack(priv, nil)
            	if err != akp.ErrSkip {
            		t.Errorf("Pack returned %+v; expected %+v", err, akp.ErrSkip)
				}
            	if pkg != nil {
            		t.Errorf("Pack returned non-nil key package %+v", pkg)
				}
			})
		}
	})
	t.Run("BadPublicKey", func(t *testing.T) {
		for _, pub := range []interface{}{
			0, 1, "", "OMG", struct{}{},
		} {
			t.Run(fmt.Sprintf("%v", pub), func(t *testing.T) {
				pkg, err := Packer.Pack(priv, pub)
				if err != akp.ErrSkip {
					t.Errorf("Pack returned %+v; expected %+v", err, akp.ErrSkip)
				}
				if pkg != nil {
					t.Errorf("Pack returned non-nil key package %+v", pkg)
				}
			})
		}
	})
}