package dsakp

import (
	"crypto/dsa"
	"crypto/rand"
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

func generateKey(t *testing.T) *dsa.PrivateKey {
	var priv dsa.PrivateKey
	err := dsa.GenerateParameters(&priv.Parameters, rand.Reader, dsa.L1024N160)
	if err != nil {
		t.Fatalf("cannot generate DSA parameters: %v", err)
	}
	err = dsa.GenerateKey(&priv, rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate DSA key pair: %v", err)
	}
	return &priv
}

func TestRoundTrip(t *testing.T) {
	priv := generateKey(t)
	subtest := func(t *testing.T, pub interface{}) {
		pkg, err := Packer.Pack(priv, pub)
		if err != nil {
			t.Fatalf("cannot pack DSA key pair: %v", err)
		}
		dumpKeyPackage(t, *pkg)
		priv2, pub2, extras, err := Unpacker.Unpack(pkg)
		if err != nil {
			t.Fatalf("cannot unpack DSA key pair: %v", err)
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
	t.Run("WithPublic", func(t *testing.T) { subtest(t, &priv.PublicKey) })
}

func TestPacker_Pack(t *testing.T) {
	priv := generateKey(t)
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
