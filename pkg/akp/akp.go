// Package akp implements RFC 5958 Asymmetric Key Package.
package akp

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"reflect"
)

// ErrSkip is returned by a packer or an unpacker,
// for a private key with an unrecognized type or a key package with an
// unrecognized algorithm OID, respectively.
var ErrSkip = errors.New("skip")

// Packer packs a private/public key pair into a key package.
//
// The public key is optional.
//
// Options may be specific to the key type.
// They may affect the encoding and/or key attributes.
//
// It returns the key pair package struct or an error.
// pkg != nil ⇔ err == nil.
type Packer interface {
	Pack(
		priv interface{}, pub interface{}, options ...interface{},
	) (pkg *OneAsymmetricKey, err error)
}

type packers map[reflect.Type][]Packer

// Packers is the global packer registry.
var Packers packers

func init() {
	Packers = make(packers)
}

// Register registers a packer under the private key types that it handles.
func (packers packers) Register(packer Packer, types ...interface{}) {
	if packer == nil {
		panic("packer is nil")
	}
	for _, v := range types {
		typ := reflect.TypeOf(v)
		if typ == nil {
			panic("dynamic type is nil")
		}
		packers[typ] = append(packers[typ], packer)
	}
}

// Pack packs a private/public key pair into a key package.
//
// It searches the receiver for the right packers for the private key type,
// and tries them, in the order of registration.
func (packers packers) Pack(
	priv interface{}, pub interface{}, options ...interface{},
) (pkg *OneAsymmetricKey, err error) {
	typ := reflect.TypeOf(priv)
	if typ == nil {
		return nil, errors.New("nil private key")
	}
	for _, packer := range packers[typ] {
		pkg, err = packer.Pack(priv, pub)
		if err != ErrSkip {
			return
		}
	}
	return nil, errors.New("no packer can pack key")
}

// Unpacker unpacks a key package into a private/public key pair.
//
// It returns the unpacked key pair or an error.
// The public key is returned only if present in the key package.
//
// It may also return a slice of extra information.
type Unpacker interface {
	Unpack(pkg *OneAsymmetricKey) (
		priv interface{}, pub interface{}, extras []interface{}, err error,
	)
}

type unpackers map[string][]Unpacker

// Unpackers is the global unpacker registry.
var Unpackers unpackers

func init() {
	Unpackers = make(unpackers)
}

// Register registers an unpacker under the algorithm OIDs that it handles.
func (unpackers unpackers) Register(
	unpacker Unpacker, algorithms ...asn1.ObjectIdentifier,
) {
	if unpacker == nil {
		panic("unpacker is nil")
	}
	for _, algorithm := range algorithms {
		s := algo2str(algorithm)
		unpackers[s] = append(unpackers[s], unpacker)
	}
}

func algo2str(algorithm asn1.ObjectIdentifier) string {
	bytes, err := asn1.Marshal(algorithm)
	if err != nil {
		panic("cannot encode algorithm OID")
	}
	return string(bytes)
}

// Unpack unpacks a key package into a private/public key pair.
//
// It searches the receiver for the right unpackers for the algorithm OID,
// and tries them, in the order of registration.
func (unpackers unpackers) Unpack(pkg *OneAsymmetricKey) (
	priv interface{}, pub interface{}, extras []interface{}, err error,
) {
	if pkg == nil {
		panic("key package is nil")
	}
	s := algo2str(pkg.PrivateKeyAlgorithm.Algorithm)
	for _, unpacker := range unpackers[s] {
		priv, pub, extras, err = unpacker.Unpack(pkg)
		if err != ErrSkip {
			return
		}
	}
	return nil, nil, nil, errors.New("no unpacker can unpack key package")
}

// Pack packs a private/public key pair into a key package.
//
// The public key is optional.
//
// Options may be specific to the key type.
// They may affect the encoding and/or key attributes.
//
// It returns the key pair package struct or an error.
// pkg != nil ⇔ err == nil.
var Pack = Packers.Pack

// Unpack unpacks a key package into a private/public key pair.
//
// It returns the unpacked key pair or an error.
// The public key is returned only if present in the key package.
//
// It may also return a slice of extra information.
var Unpack = Unpackers.Unpack

// Encode encodes a private/public key pair into a ASN.1-encoded key package.
//
// The public key is optional.
//
// Options may be specific to the key type.
// They may affect the encoding and/or key attributes.
//
// It returns the key pair package bytes or an error.
// encoded != nil ⇔ err == nil.
func Encode(
	priv interface{}, pub interface{}, options ...interface{},
) (encoded []byte, err error) {
	pkg, err := Pack(priv, pub, options...)
	if err != nil {
		return
	}
	return asn1.Marshal(pkg)
}

// Decode decodes an ASN.1-encoded key package into a private/public key pair.
//
// It returns the unpacked key pair or an error.
// The public key is returned only if present in the key package.
//
// It may also return a slice of extra information.
func Decode(encoded []byte) (
	priv interface{}, pub interface{}, extras []interface{}, err error,
) {
	var pkg OneAsymmetricKey
	rest, err := asn1.Unmarshal(encoded, &pkg)
	if err != nil {
		return
	}
	if len(rest) > 0 {
		err = fmt.Errorf("trailing data after key package")
		return
	}
	return Unpack(&pkg)
}
