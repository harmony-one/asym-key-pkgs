// Package dsakp implements DSA signature keys as defined in RFC 3279,
// section 2.3.2.
package dsakp

import (
	"crypto/dsa"
	"encoding/asn1"
	"github.com/harmony-one/asym-key-pkgs/pkg/akp"
	"math/big"
)

var algorithmOID = asn1.ObjectIdentifier{
	/*iso*/ 1 /*member-body*/, 2 /*us*/, 840 /*x9-57*/, 10040 /*x9cm*/, 4, 1,
}

func init() {
	akp.Packers.Register(Packer, &dsa.PrivateKey{})
	akp.Unpackers.Register(Unpacker, algorithmOID)
}

// Dss-Parms in RFC 3279.  Keep the same field order as in RFC 3279.
type asn1DssParms struct {
	P *big.Int
	Q *big.Int
	G *big.Int
}
