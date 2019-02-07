package akp

import "os"

// Save saves the given private/public key pair in a file.
func Save(
	filename string, priv interface{}, pub interface{}, options ...interface{},
) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close() // nolint
	_, err = Write(file, priv, pub, options...)
	return err
}

// Load loads a private/public key pair from the given file.
func Load(filename string) (
	priv interface{}, pub interface{}, extras []interface{}, err error,
) {
	file, err := os.Open(filename) // nolint
	if err != nil {
		return nil, nil, nil, err
	}
	defer file.Close() // nolint
	priv, pub, extras, _, err = Read(file)
	return
}
