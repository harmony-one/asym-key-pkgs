package akp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
)

// AsymmetricKeyPackage contains one or more OneAsymmetricKey elements.
type AsymmetricKeyPackage []OneAsymmetricKey

// OneAsymmetricKey is one private key.
type OneAsymmetricKey struct {
	// Version is V2 if PublicKey is present, otherwise V1
	Version int

	// PrivateKeyAlgorithm is an algorithm OID and optional key pair parameters.
	PrivateKeyAlgorithm pkix.AlgorithmIdentifier

	// PrivateKey contains the value of the private key.
	// The interpretation is defined in the registration of the
	// PrivateKeyAlgorithm.
	PrivateKey []byte

	// Attributes contains information corresponding to the public key,
	// e.g. certificates.
	Attributes []Attribute `asn1:"optional,tag:0,set"`

	// PublicKey, when present, contains the public key.
	// The structure within the bit string depends on the private key algorithm.
	PublicKey asn1.BitString `asn1:"optional,tag:1"`
}

// PrivateKeyInfo is the old (RFC 5208) name of OneAsymmetricKey.
type PrivateKeyInfo = OneAsymmetricKey

// AKP version
const (
	V1 = 0 // PublicKey is absent
	V2 = 1 // PublicKey is present
)

// Attribute is a PKIX-defined general-purpose attribute.
type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}
