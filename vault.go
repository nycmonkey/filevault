package filevault

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

var (

	// PGPSettings defines the cipher (AES256) and compression settings
	// (ZLIB with default compression) used by the filevault
	PGPSettings = &packet.Config{
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig:      &packet.CompressionConfig{Level: packet.DefaultCompression},
	}

	// HashAlgo is the cyptographic hashing algorithm used to identify files
	HashAlgo = sha256.New

	// IDLength is the length of file identifiers in bytes
	IDLength = hex.EncodedLen(sha256.Size)

	// SubDirCharLen specifies how many characters of the file ID will be used to
	// generate subdirectories under the file, key and meta root folders. Since
	// each character can be one of 16 possible values ([a-f0-9]),
	// the maximum number of subdirectories will be 16^SubDirCharLen
	SubDirCharLen = 2

	// IDPattern is a regular expression that all valid IDs must match
	IDPattern = regexp.MustCompile(fmt.Sprintf("^[a-f0-9]{%d}$", IDLength))

	// DEKBytes defines the number or random bytes used to generate the data
	// encrypting keys.  The random bytes are base64 encoded and used as a PGP
	// passphrase for symmetric encryption
	DEKBytes = 16
)

// Vault stores sensitive files
type Vault interface {

	// Store adds a file and associated metadata into the vault
	Store(unencryptedData io.Reader, md *Metadata) (id string, err error)

	// Export re-encrypts a file in the vault with a specified public key
	// and stores the output in a pre-configured location
	Export(id string, recipientFingerprint [20]byte) (path string, err error)

	// Get copies the unencrypted data of a file to the provided Writer
	Get(id string, dest io.Writer, requester string) (err error)

	// GetMetadata loads available metadata for a specified file
	GetMetadata(id string, md *Metadata) error

	// LoadExportKeyring reloads approved export recipients from the configured
	// ProdSupportKeyring file path
	LoadExportKeyring(data io.Reader) error
}

// NewVault returns a new Vault
func NewVault(c *Config) (v Vault, err error) {
	var masterKey *openpgp.Entity
	var exportWhitelist []*openpgp.Entity

	var f *os.File
	f, err = os.Open(c.SecRing)
	if err != nil {
		return
	}
	var entitylist openpgp.EntityList
	entitylist, err = openpgp.ReadArmoredKeyRing(f)
	if err != nil {
		f.Close()
		return
	}
	f.Close()
	var fp [20]byte
	fp, err = HexStringToFingerprint(c.MasterKeyFingerprint)
	if err != nil {
		return
	}
	var ok bool
	masterKey, ok = getKeyByFingerprint(entitylist, fp)
	if !ok {
		err = ErrMasterKeyNotFound
		return
	}

	f, err = os.Open(c.ProdSupportPubRing)
	if err != nil {
		return
	}

	exportWhitelist, err = openpgp.ReadArmoredKeyRing(f)
	if err != nil {
		return
	}
	f.Close()

	if masterKey.PrivateKey.Encrypted {
		err = masterKey.PrivateKey.Decrypt([]byte(c.MasterKeyPassphrase))
		if err != nil {
			err = ErrIncorrectPassphrase
			return
		}
	}

	var imp = &vault{
		masterKey:       masterKey,
		keyPassphrase:   c.MasterKeyPassphrase,
		exportWhitelist: exportWhitelist,
		keyDir:          c.KeyRoot,
		metaDir:         c.MetaRoot,
		fileDir:         c.DataRoot,
		exportDir:       c.ProdSupportDir,
	}
	imp.logKeys()
	return imp, err
}

func (v *vault) logKeys() {
	var keyname string
	for n := range v.masterKey.Identities {
		keyname = n
		break
	}
	log.Println("Using master key", v.masterKey.PrimaryKey.KeyIdShortString(), keyname)
	for _, entity := range v.exportWhitelist {
		for n := range entity.Identities {
			keyname = n
			break
		}
		log.Println("Authorized export to", entity.PrimaryKey.KeyIdString(), keyname)
	}
	return
}

func (v *vault) LoadExportKeyring(data io.Reader) error {
	exportWhitelist, err := openpgp.ReadArmoredKeyRing(data)
	if err != nil {
		return err
	}
	v.exportWhitelist = exportWhitelist
	v.logKeys()
	return nil
}

// Store adds a new file to the data store
func (v *vault) Store(unencryptedData io.Reader, md *Metadata) (id string, err error) {
	var dek string
	dek, err = newDek()
	if err != nil {
		return
	}
	// write initially to a temp file so as not to overwrite the file
	// then we rename it to the target destination
	var tmp *os.File
	tmp, err = ioutil.TempFile(v.fileDir, "filevault-inbound")
	if err != nil {
		return
	}
	defer tmp.Close()
	var plaintext io.WriteCloser // where to send the plaintext to encrypt
	plaintext, err = openpgp.SymmetricallyEncrypt(
		tmp,
		[]byte(dek), // we encrypt each file with a random passphrase
		&openpgp.FileHints{
			IsBinary: true,
			FileName: md.Filename},
		PGPSettings)
	if err != nil {
		return
	}
	digest := HashAlgo()
	mw := io.MultiWriter(digest, plaintext)
	if _, err = io.Copy(mw, unencryptedData); err != nil {
		return
	}

	// finish encrypting data, calculate digest
	err = plaintext.Close()
	if err != nil {
		return
	}
	_ = tmp.Close()
	id = fmt.Sprintf("%x", digest.Sum(nil))

	// create final output paths
	if err = v.mkDirs(id); err != nil {
		return
	}

	// rename the encrypted data to match the file ID
	var p string
	p, err = v.filePath(id)
	if err != nil {
		return
	}
	if err = os.Rename(tmp.Name(), p); err != nil {
		return
	}

	// store the data encypting key in encrypted form
	err = v.storeDek(id, dek)
	if err != nil {
		return
	}

	// write the file metadata
	var mdBytes []byte
	mdBytes, err = json.MarshalIndent(md, "", "\t")
	if err != nil {
		return
	}
	p, err = v.metaPath(id)
	if err != nil {
		return
	}
	err = ioutil.WriteFile(p, mdBytes, os.FileMode(int(0644)))
	log.Println("STORE", id, md.Subject, `"`+md.Filename+`"`)
	// all done
	return
}

// GetMetadata retrieves data about a file in the Vault
func (v *vault) GetMetadata(id string, md *Metadata) (err error) {
	var path string
	path, err = v.metaPath(id)
	if err != nil {
		return
	}
	var data []byte
	data, err = ioutil.ReadFile(path)
	if err != nil {
		return
	}
	return json.Unmarshal(data, md)
}

// Get copies unencrypted file data to the provided io.WriteCloser
func (v *vault) Get(id string, dest io.Writer, user string) (err error) {
	md := &Metadata{}
	err = v.GetMetadata(id, md)
	if err != nil {
		return
	}
	log.Println("GET", id, md.Subject, `"`+md.Filename+`"`, user)
	return v.decrypt(dest, id)
}

// Export outputs data encrypted with the target recipient's public key
func (v *vault) Export(id string, recipientFingerprint [20]byte) (path string, err error) {
	recipient, ok := v.whitelistedRecipient(recipientFingerprint)
	if !ok {
		err = ErrRecipientNotInWhitelist
		return
	}
	md := &Metadata{}
	err = v.GetMetadata(id, md)
	if err != nil {
		return
	}
	// TO DO: make sure output path exists
	var out *os.File
	err = os.MkdirAll(v.exportDir, 0744)
	if err != nil {
		return
	}
	path = filepath.Join(v.exportDir, fmt.Sprintf("%s.gpg", md.Filename))
	out, err = os.Create(path)
	if err != nil {
		return
	}
	defer out.Close()
	var plaintext io.WriteCloser
	plaintext, err = openpgp.Encrypt(out,
		[]*openpgp.Entity{recipient},
		v.masterKey,
		&openpgp.FileHints{
			IsBinary: true,
			FileName: md.Filename},
		PGPSettings)
	if err != nil {
		return
	}
	defer plaintext.Close()
	err = v.decrypt(plaintext, id)
	var pkname string
	for k := range recipient.Identities {
		pkname = k
		break
	}
	log.Println("EXPORT", id, md.Subject, `"`+md.Filename+`"`, pkname)
	return
}

// Metadata describes a file in the Vault
type Metadata struct {
	Filename, Subject, MimeType string
	Received                    time.Time
	Size                        int64
}

func validID(id string) bool {
	return IDPattern.MatchString(id)
}
func subdirFn(id string) (string, error) {
	if validID(id) && len(id) > SubDirCharLen {
		return id[0:SubDirCharLen], nil
	}
	return "", ErrInvalidID
}

// Generate a new random data encrypting key
func newDek() (dek string, err error) {
	rawKey := make([]byte, DEKBytes)
	_, err = rand.Read(rawKey)
	if err != nil {
		return
	}
	dek = base64.RawStdEncoding.EncodeToString(rawKey)
	return
}

func (v *vault) keyPath(id string) (dir string, err error) {
	var subdir string
	subdir, err = subdirFn(id)
	if err != nil {
		return
	}
	return filepath.Join(v.keyDir, subdir, id+".key.gpg"), nil
}

func (v *vault) metaPath(id string) (dir string, err error) {
	var subdir string
	subdir, err = subdirFn(id)
	if err != nil {
		return
	}
	return filepath.Join(v.metaDir, subdir, id+".json"), nil
}

func (v *vault) filePath(id string) (dir string, err error) {
	var subdir string
	subdir, err = subdirFn(id)
	if err != nil {
		return
	}
	return filepath.Join(v.fileDir, subdir, id+".gpg"), nil
}

// store an encrypted data encrypting key
func (v *vault) storeDek(fileID, key string) (err error) {
	var output *os.File
	var path string
	path, err = v.keyPath(fileID)
	if err != nil {
		return
	}
	output, err = os.Create(path)
	if err != nil {
		return
	}
	defer output.Close()
	var plaintext io.WriteCloser
	plaintext, err = openpgp.Encrypt(output, []*openpgp.Entity{v.masterKey}, v.masterKey, nil, PGPSettings)
	if err != nil {
		return
	}
	if _, err = io.Copy(plaintext, strings.NewReader(key)); err != nil {
		return
	}
	return plaintext.Close()
}

func (v *vault) mkDirs(id string) (err error) {
	var p string
	p, err = v.filePath(id)
	if err != nil {
		return
	}
	if err = os.MkdirAll(filepath.Dir(p), 0744); err != nil {
		return
	}
	p, err = v.metaPath(id)
	if err != nil {
		return
	}
	if err = os.MkdirAll(filepath.Dir(p), 0744); err != nil {
		return
	}
	p, err = v.keyPath(id)
	if err != nil {
		return
	}
	return os.MkdirAll(filepath.Dir(p), 0744)
}

// Preferred key lookup method; unambiguous
func getKeyByFingerprint(keyring openpgp.EntityList, fp [20]byte) (
	e *openpgp.Entity, ok bool) {
	for _, entity := range keyring {
		// emails can be spoofed and ambiguous, so we verify using full fingerprints
		if bytes.Equal(fp[0:20], entity.PrimaryKey.Fingerprint[0:20]) {
			return entity, true
		}
	}
	return e, false
}

// This is needed to prevent an incorrect key from retrying repeatedly
func mkDecFunc(key []byte, keyType string) func([]openpgp.Key, bool) ([]byte, error) {
	var called int
	return func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		called++
		if called > 1 {
			return key, ErrIncorrectPassphrase
		}
		return key, nil
	}
}

func (v *vault) whitelistedRecipient(fp [20]byte) (e *openpgp.Entity, ok bool) {
	return getKeyByFingerprint(v.exportWhitelist, fp)
}

func (v *vault) nullPrompt(keys []openpgp.Key, symmetric bool) ([]byte, error) {
	return []byte(v.keyPassphrase), nil
}

func (v *vault) decrypt(dest io.Writer, id string) (err error) {
	var kf, df *os.File
	var p string
	p, err = v.keyPath(id)
	if err != nil {
		return
	}
	kf, err = os.Open(p)
	if err != nil {
		return
	}
	defer func() {
		_ = kf.Close()
	}()
	var md *openpgp.MessageDetails
	md, err = openpgp.ReadMessage(kf, openpgp.EntityList{v.masterKey}, v.nullPrompt, PGPSettings)
	if err != nil {
		return
	}
	var dek []byte
	dek, err = ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return
	}
	p, err = v.filePath(id)
	if err != nil {
		return
	}
	df, err = os.Open(p)
	if err != nil {
		return
	}
	defer func() {
		_ = df.Close()
	}()
	md, err = openpgp.ReadMessage(df, nil, mkDecFunc(dek, "Data Encrypting Key"), PGPSettings)
	if err != nil {
		return
	}
	_, err = io.Copy(dest, md.UnverifiedBody)
	return
}

type vault struct {
	masterKey                *openpgp.Entity
	keyPassphrase            string
	exportWhitelist          []*openpgp.Entity
	keyDir, metaDir, fileDir string
	exportDir                string
}

// HexStringToFingerprint converts a string with optional spaces
// into the 20 byte array format of a PGP key fingerprint
func HexStringToFingerprint(input string) (fp [20]byte, err error) {
	var b []byte
	b, err = hex.DecodeString(strings.Replace(input, " ", "", -1))
	if err != nil {
		return
	}
	if len(b) != 20 {
		err = ErrInvalidPGPFingerprint
		return
	}
	copy(fp[0:20], b)
	return
}
