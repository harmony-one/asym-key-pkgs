package dsakp

import (
	"crypto/dsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/harmony-one/asym-key-pkgs/pkg/akp"
	"math/big"
)

type unpacker struct{}

// Unpacker is the singleton DSA unpacker instance.
var Unpacker unpacker

// Unpack unpacks a DSA private key.
//
// DSA parameters (P, Q, G) are optional in RFC 3279.
// Unpack recognizes this,
// and returns an intentionally incomplete private and public key if the
// algorithm parameters are missing: The Parameter portion – the fields P, Q,
// and G – are all nilled out.
// This condition is not reflected in the error code,
// so the caller must deal with this and either substitute default parameters
// if available, or reject the key.
func (unpacker unpacker) Unpack(pkg *akp.OneAsymmetricKey) (
	priv interface{}, pub interface{}, extras []interface{}, err error,
) {
	var privKey dsa.PrivateKey
	dssParmsBytes := pkg.PrivateKeyAlgorithm.Parameters.FullBytes
	if len(dssParmsBytes) > 0 {
		var dssParms asn1DssParms
		rest, e := asn1.Unmarshal(dssParmsBytes, &dssParms)
		if err != nil {
			return nil, nil, nil, fmt.Errorf(
				"cannot unmarshal DSA parameters: %v", e)
		}
		if len(rest) > 0 {
			return nil, nil, nil, errors.New("extra data after DSA parameters")
		}
		privKey.P = dssParms.P
		privKey.Q = dssParms.Q
		privKey.G = dssParms.G
	}
	rest, err := asn1.Unmarshal(pkg.PrivateKey, &privKey.X)
	if err != nil {
		return nil, nil, nil, fmt.Errorf(
			"cannot unmarshal private key: %v", err)
	}
	if len(rest) > 0 {
		return nil, nil, nil, errors.New("extra data after DSA private key")
	}
	if privKey.G != nil {
		privKey.Y = new(big.Int).Exp(privKey.G, privKey.X, privKey.P)
	}
	if pkg.PublicKey.Bytes == nil {
		return &privKey, nil, nil, nil
	}
	var pubKey dsa.PublicKey
	pubKey.Parameters = privKey.Parameters
	rest, err = asn1.Unmarshal(pkg.PublicKey.Bytes, &pubKey.Y)
	if err != nil {
		return nil, nil, nil, fmt.Errorf(
			"cannot unmarshal public key: %v", err)
	}
	if len(rest) > 0 {
		return nil, nil, nil, errors.New("extra data after DSA private key")
	}
	return &privKey, &pubKey, nil, nil
}

// ErrNotDSA means the unpacked key is not an DSA key.
var ErrNotDSA = errors.New("not an DSA key")

// Unpack unpacks a key package into an DSA key pair.
func Unpack(pkg *akp.OneAsymmetricKey) (
	priv *dsa.PrivateKey, pub *dsa.PublicKey, extras []interface{}, err error,
) {
	privKey, pubKey, extras, err := Unpacker.Unpack(pkg)
	if err != nil {
		return nil, nil, nil, err
	}
	var ok bool
	if priv, ok = privKey.(*dsa.PrivateKey); !ok {
		return nil, nil, nil, ErrNotDSA
	}
	if pubKey == nil {
		return priv, nil, extras, nil
	}
	if pub, ok = pubKey.(*dsa.PublicKey); !ok {
		return nil, nil, nil, ErrNotDSA
	}
	return priv, pub, extras, nil
}
