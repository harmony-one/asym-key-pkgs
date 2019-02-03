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
	pkg = &akp.OneAsymmetricKey{
		Version: akp.V1,
		PrivateKeyAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: algorithmOID, Parameters: asn1.NullRawValue,
		},
	}
	privKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, akp.ErrSkip
	}
	pkg.PrivateKey = x509.MarshalPKCS1PrivateKey(privKey)
	if pkg.PrivateKey == nil {
		return nil, errors.New("cannot serialize RSA private key")
	}
	if pub != nil {
		pubKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, akp.ErrSkip
		}
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
