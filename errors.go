package filevault

import "errors"

var (

	// ErrRecipientNotInWhitelist is returned when the specified key fingerprint
	// is not found in the ProdSupportPubRing
	ErrRecipientNotInWhitelist = errors.New(
		`The recipient's PGP fingerprint is not in the authorized keychain`)

	// ErrInvalidPGPFingerprint is returned when a specified PGP key fingerprint
	// does not parse from hex with optional spaces to exactly 20 bytes
	ErrInvalidPGPFingerprint = errors.New(`The PGP fingerprint provided is not a valid hex encoding of 20 bytes`)

	// ErrKeyFingerprintNotSpecified is returned when an export is requested
	// without specifying the recipient's key fingerprint
	ErrKeyFingerprintNotSpecified = errors.New(`A specific PGP key fingerprint is required, but was not specified`)

	// ErrInvalidID is returned when a specified file ID does not match
	// the regular expression /^[a-z0-9]{64}$/
	ErrInvalidID = errors.New(`Invalid file ID`)

	// ErrIncorrectPassphrase is returned when a passphrase does not decrypt a
	// private key
	ErrIncorrectPassphrase = errors.New(`Incorect private key passphrase`)

	// ErrMasterKeyNotFound is returned when a specified key fingerprint
	// is not found on the provided secret keyring
	ErrMasterKeyNotFound = errors.New(`The specified master key fingerprint was not found on the secure keyring`)
)
