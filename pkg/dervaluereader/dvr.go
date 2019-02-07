// Package dvr implements an ASN.1 value reader.
package dvr

import (
	"errors"
	"fmt"
	"io"
	"math/big"
)

// DERValueReader reads exactly one ASN.1 value from the given reader.
type DERValueReader struct {
	r io.Reader
	b []byte
	p int
}

func (r *DERValueReader) readMore(amount int) (err error) {
	r.p = len(r.b)
	r.b = append(r.b, make([]byte, amount)...)
	n, err := io.ReadFull(r.r, r.b[r.p:])
	r.b = r.b[:r.p+n]
	return err
}

func (r *DERValueReader) readTag() (err error) {
	if err = r.readMore(1); err != nil {
		return err
	}
	if r.b[r.p]&0x1f == 0x1f {
		// High-tag-number form
		for {
			if err = r.readMore(1); err != nil {
				return err
			}
			if r.b[r.p]&0x80 == 0 {
				break
			}
		}
	}
	return nil
}

func (r *DERValueReader) readLength() (int, error) {
	var err error
	if err = r.readMore(1); err != nil {
		return 0, err
	}
	b := r.b[r.p]
	if b&0x80 == 0 {
		// Short form
		return int(b), nil
	}
	if b == 0x80 {
		return 0, errors.New("indefinite-length encoded; not a DER value")
	}
	// Long form
	if err = r.readMore(int(b & 0x7f)); err != nil {
		return 0, err
	}
	lb := new(big.Int).SetBytes(r.b[r.p:])
	if !lb.IsInt64() {
		return 0, fmt.Errorf("DER value length (%v) out of range", lb)
	}
	l64 := lb.Int64()
	if l64 < 0 || l64 > int64(^uint(0)>>1) {
		return 0, fmt.Errorf("DER value length (%v) out of range", lb)
	}
	return int(l64), nil
}

// Read reads exactly one ASN.1 value from the given reader.
func (r *DERValueReader) Read() ([]byte, error) {
	var err error
	if err = r.readTag(); err != nil {
		return r.b, err
	}
	l, err := r.readLength()
	if err != nil {
		return r.b, err
	}
	if err = r.readMore(l); err != nil {
		return r.b, err
	}
	return r.b, nil
}

// New returns a new instance created from the given reader.
func New(r io.Reader) *DERValueReader {
	return &DERValueReader{r: r}
}
