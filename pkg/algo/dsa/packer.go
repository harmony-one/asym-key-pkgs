package dsakp

import (
	"crypto/dsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"github.com/harmony-one/asym-key-pkgs/pkg/akp"
)

type packer struct{}

// Packer is the singleton packer instance.
var Packer packer

func (packer packer) Pack(
	priv interface{}, pub interface{}, options ...interface{},
) (pkg *akp.OneAsymmetricKey, err error) {
	var (
		privKey *dsa.PrivateKey
		pubKey  *dsa.PublicKey
		ok      bool
	)
	if privKey, ok = priv.(*dsa.PrivateKey); !ok {
		return nil, akp.ErrSkip
	}
	if pub == nil {
		return Pack(privKey, nil, options)
	}
	if pubKey, ok = pub.(*dsa.PublicKey); !ok {
		return nil, akp.ErrSkip
	}
	return Pack(privKey, pubKey, options)
}

// Pack packs the given RSA key pair into a key package.
func Pack(
	privKey *dsa.PrivateKey, pubKey *dsa.PublicKey, options ...interface{},
) (pkg *akp.OneAsymmetricKey, err error) {
	params := privKey.Parameters
	dssParmsBytes, err := asn1.Marshal(asn1DssParms{
		P: params.P, Q: params.Q, G: params.G,
	})
	if err != nil {
		return nil, err
	}
	pkg = &akp.OneAsymmetricKey{
		Version: akp.V1,
		PrivateKeyAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: algorithmOID,
		},
	}
	_, err = asn1.Unmarshal(dssParmsBytes, &pkg.PrivateKeyAlgorithm.Parameters)
	if err != nil {
		return nil, err
	}
	// RFC 5958, section 2: “a DSA key is an INTEGER” (private).
	pkg.PrivateKey, err = asn1.Marshal(privKey.X)
	if err != nil {
		return nil, err
	}
	if pubKey != nil {
		// RFC 5958, section 2: “a DSA key is an INTEGER” (public).
		pubBytes, err := asn1.Marshal(pubKey.Y)
		if err != nil {
			return nil, err
		}
		pkg.PublicKey = asn1.BitString{
			Bytes:     pubBytes,
			BitLength: 8 * len(pubBytes),
		}
		pkg.Version = akp.V2
	}
	return pkg, nil
}
