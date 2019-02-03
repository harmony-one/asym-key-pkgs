package rsakp

import (
	"crypto/x509"

	"github.com/harmony-one/asym-key-pkgs/pkg/akp"
)

type unpacker struct{}

// Unpacker is the singleton RSA unpacker instance.
var Unpacker unpacker

func (unpacker unpacker) Unpack(pkg *akp.OneAsymmetricKey) (
	priv interface{}, pub interface{}, extras []interface{}, err error,
) {
	priv, err = x509.ParsePKCS1PrivateKey(pkg.PrivateKey)
	if err != nil {
		return nil, nil, nil, err
	}
	if pkg.PublicKey.Bytes != nil {
		pub, err = x509.ParsePKCS1PublicKey(pkg.PublicKey.Bytes)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	return priv, pub, nil, nil
}
