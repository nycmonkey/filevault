package filevault

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// Config stores the configuration parameters for a filevault
type Config struct {
	TLSCert, TLSKey             string
	DataRoot, KeyRoot, MetaRoot string
	ProdSupportDir              string
	ProdSupportPubRing          string
	LogFile                     string
	EmailFrom, EmailTo          string
	SMTPServer                  string
	SMTPPort                    int
	SecRing                     string
	MasterKeyPassphrase         string
	MasterKeyFingerprint        string
	HTTPLog                     string
	HtpasswdFile                string
}

// Validate performs some sanity checks on configuration values
func (c Config) Validate() (err error) {
	var fi os.FileInfo

	// validate key fingerprint
	_, err = HexStringToFingerprint(c.MasterKeyFingerprint)
	if err != nil {
		return
	}

	// validate TLSCert
	if len(c.TLSCert) == 0 {
		return errors.New("Missing config param: TLSCert")
	}
	fi, err = os.Stat(c.TLSCert)
	if err != nil {
		return fmt.Errorf("Config error in TLSCert '%s': %s", c.TLSCert, err)
	}
	if fi.IsDir() {
		return fmt.Errorf("Config error in TLSCert '%s': expected file path, got directory", c.TLSCert)
	}

	// validate TLSKey
	if len(c.TLSKey) == 0 {
		return errors.New("Missing config param: TLSKey")
	}
	fi, err = os.Stat(c.TLSKey)
	if err != nil {
		return fmt.Errorf("Config error in TLSKey '%s': %s", c.TLSKey, err)
	}
	if fi.IsDir() {
		return fmt.Errorf("Config error in TLSKey '%s': expected file path, got directory", c.TLSKey)
	}

	// validate SecRing
	if len(c.SecRing) == 0 {
		return errors.New("Missing config param: SecRing")
	}
	fi, err = os.Stat(c.SecRing)
	if err != nil {
		return fmt.Errorf("Config error in SecRing '%s': %s", c.SecRing, err)
	}
	if fi.IsDir() {
		return fmt.Errorf("Config error in SecRing '%s': expected file path, got directory", c.SecRing)
	}

	// validate ProdSupportPubRing
	if len(c.ProdSupportPubRing) == 0 {
		return errors.New("Missing config param: ProdSupportPubRing")
	}
	fi, err = os.Stat(c.ProdSupportPubRing)
	if err != nil {
		return fmt.Errorf("Config error in ProdSupportPubRing '%s': %s", c.ProdSupportPubRing, err)
	}
	if fi.IsDir() {
		return fmt.Errorf("Config error in ProdSupportPubRing '%s': expected file path, got directory", c.ProdSupportPubRing)
	}

	// validate DataRoot
	if len(c.DataRoot) == 0 {
		return errors.New("Missing config param: DataRoot")
	}
	fi, err = os.Stat(c.DataRoot)
	if err != nil {
		// doesn't exist... can we create it?
		if err = os.MkdirAll(c.DataRoot, 0744); err != nil {
			return fmt.Errorf("Config error in DataRoot '%s': %s", c.DataRoot, err)
		}
	} else {
		if !fi.IsDir() {
			return fmt.Errorf("Config error in DataRoot '%s': expected directory, got file path", c.DataRoot)
		}
	}

	// validate ProdSupportDir
	if len(c.ProdSupportDir) == 0 {
		return errors.New("Missing config param: ProdSupportDir")
	}
	fi, err = os.Stat(c.ProdSupportDir)
	if err != nil {
		// doesn't exist... can we create it?
		if err = os.MkdirAll(c.ProdSupportDir, 0744); err != nil {
			return fmt.Errorf("Config error in ProdSupportDir '%s': %s", c.ProdSupportDir, err)
		}
	} else {
		if !fi.IsDir() {
			return fmt.Errorf("Config error in ProdSupportDir '%s': expected directory, got file path", c.ProdSupportDir)
		}
	}

	// validate KeyRoot
	if len(c.KeyRoot) == 0 {
		return errors.New("Missing config param: KeyRoot")
	}
	fi, err = os.Stat(c.KeyRoot)
	if err != nil {
		// doesn't exist... can we create it?
		if err = os.MkdirAll(c.KeyRoot, 0744); err != nil {
			return fmt.Errorf("Config error in KeyRoot '%s': %s", c.KeyRoot, err)
		}
	} else {
		if !fi.IsDir() {
			return fmt.Errorf("Config error in KeyRoot '%s': expected directory, got file path", c.KeyRoot)
		}
	}

	// validate MetaRoot
	if len(c.MetaRoot) == 0 {
		return errors.New("Missing config param: MetaRoot")
	}
	fi, err = os.Stat(c.MetaRoot)
	if err != nil {
		// doesn't exist... can we create it?
		if err = os.MkdirAll(c.MetaRoot, 0744); err != nil {
			return fmt.Errorf("Config error in MetaRoot '%s': %s", c.MetaRoot, err)
		}
	} else {
		if !fi.IsDir() {
			return fmt.Errorf("Config error in MetaRoot '%s': expected directory, got file path", c.MetaRoot)
		}
	}

	// validate HTTPLog
	if len(c.HTTPLog) > 0 {
		fi, err = os.Stat(filepath.Dir(c.HTTPLog))
		if err != nil {
			// doesn't exist... can we create it?
			if err = os.MkdirAll(filepath.Dir(c.HTTPLog), 0744); err != nil {
				return fmt.Errorf("Config error in HTTPLog '%s': %s", c.HTTPLog, err)
			}
		}
	}

	// validate HtpasswdFile
	if len(c.HtpasswdFile) == 0 {
		return errors.New("Missing config param: HtpasswdFile")
	}
	fi, err = os.Stat(c.HtpasswdFile)
	if err != nil {
		return fmt.Errorf("Config error in HtpasswdFile '%s': %s", c.HtpasswdFile, err)
	}
	if fi.IsDir() {
		return fmt.Errorf("Config error in HtpasswdFile '%s': expected file path, got directory", c.HtpasswdFile)
	}

	if len(c.MasterKeyPassphrase) == 0 {
		log.Println("no passphrase specified for secure keyring")
	}

	return nil
}
