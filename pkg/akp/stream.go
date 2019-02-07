package akp

import (
	"io"

	dvr "github.com/harmony-one/asym-key-pkgs/pkg/dervaluereader"
)

// Write writes a private/public key pair to the given writer.
func Write(
	w io.Writer, priv interface{}, pub interface{}, options ...interface{},
) (int, error) {
	bytes, err := Encode(priv, pub, options...)
	if err != nil {
		return 0, err
	}
	return w.Write(bytes)
}

// Read reads a private/public key pair from the given reader.
func Read(r io.Reader) (
	priv interface{}, pub interface{}, extras []interface{}, n int, err error,
) {
	v, err := dvr.New(r).Read()
	n = len(v)
	if err == nil {
		priv, pub, extras, err = Decode(v)
	}
	return
}
