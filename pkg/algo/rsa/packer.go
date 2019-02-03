package rsakp

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"github.com/harmony-one/asym-key-pkgs/pkg/akp"
)

type packer struct{}

// Packer is the singleton packer instance.
var Packer packer

func (packer packer) Pack(
	priv interface{}, pub interface{}, options ...interface{},
) (pkg *akp.OneAsymmetricKey, err error) {
	var (
		privKey *rsa.PrivateKey
		pubKey  *rsa.PublicKey
		ok      bool
	)
	if privKey, ok = priv.(*rsa.PrivateKey); !ok {
		return nil, akp.ErrSkip
	}
	if pub == nil {
		return Pack(privKey, nil, options)
	}
	if pubKey, ok = pub.(*rsa.PublicKey); !ok {
		return nil, akp.ErrSkip
	}
	return Pack(privKey, pubKey, options)
}

// Pack packs the given RSA key pair into a key package.
func Pack(
	privKey *rsa.PrivateKey, pubKey *rsa.PublicKey, options ...interface{},
) (pkg *akp.OneAsymmetricKey, err error) {
	pkg = &akp.OneAsymmetricKey{
		Version: akp.V1,
		PrivateKeyAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: algorithmOID, Parameters: asn1.NullRawValue,
		},
	}
	pkg.PrivateKey = x509.MarshalPKCS1PrivateKey(privKey)
	if pkg.PrivateKey == nil {
		return nil, errors.New("cannot serialize RSA private key")
	}
	if pubKey != nil {
		pubBytes := x509.MarshalPKCS1PublicKey(pubKey)
		if pubBytes == nil {
			return nil, errors.New("cannot serialize RSA public key")
		}
		pkg.PublicKey = asn1.BitString{
			Bytes:     pubBytes,
			BitLength: 8 * len(pubBytes),
		}
		pkg.Version = akp.V2
	}
	return pkg, nil
}
