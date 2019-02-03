package rsakp

import (
	"crypto/rsa"
	"encoding/asn1"

	"github.com/harmony-one/asym-key-pkgs/pkg/akp"
)

var algorithmOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}

func init() {
	akp.Packers.Register(Packer, &rsa.PrivateKey{})
	akp.Unpackers.Register(Unpacker, algorithmOID)
}
