package rsakp

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"

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

// ErrNotRSA means the unpacked key is not an RSA key.
var ErrNotRSA = errors.New("not an RSA key")

// Unpack unpacks a key package into an RSA key pair.
func Unpack(pkg *akp.OneAsymmetricKey) (
	priv *rsa.PrivateKey, pub *rsa.PublicKey, extras []interface{}, err error,
) {
	privKey, pubKey, extras, err := Unpacker.Unpack(pkg)
	if err != nil {
		return nil, nil, nil, err
	}
	var ok bool
	if priv, ok = privKey.(*rsa.PrivateKey); !ok {
		return nil, nil, nil, ErrNotRSA
	}
	if pubKey == nil {
		return priv, nil, extras, nil
	}
	if pub, ok = pubKey.(*rsa.PublicKey); !ok {
		return nil, nil, nil, ErrNotRSA
	}
	return priv, pub, extras, nil
}
