package main

import (
	"encoding/json"
	"expvar"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/Sirupsen/logrus"
	"github.com/Sirupsen/logrus/formatters/logstash"
	"github.com/abbot/go-http-auth"
	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	fv "github.com/nycmonkey/filevault"
	"github.com/nycmonkey/httputil"
	"github.com/zbindenren/logrus_mail"
)

var (
	configFile     = flag.String("config", "config.toml", "configuration file")
	config         fv.Config
	vault          fv.Vault
	appLog         *logrus.Entry
	logfile        *os.File
	hostname       string
	username       string
	exportCounter  *expvar.Int
	importCounter  *expvar.Int
	panicCounter   *expvar.Int
	refreshCounter *expvar.Int
	idMatcher      = regexp.MustCompile(`[a-z0-9]{64}$`)
)

func init() {
	exportCounter = expvar.NewInt("exports")
	importCounter = expvar.NewInt("imports")
	panicCounter = expvar.NewInt("panics")
	refreshCounter = expvar.NewInt("export-key-reloads")
}

func main() {
	var err error
	loadConfig()
	configureLogging()
	secrets := auth.HtpasswdFileProvider(config.HtpasswdFile)
	authenticator := auth.NewBasicAuthenticator("FileVault", secrets)
	defer logfile.Close()
	vault, err = fv.NewVault(&config)
	if err != nil {
		log.Fatal(err)
	}
	mw := alice.New(loggingHandler, panicHandler)
	r := mux.NewRouter()
	r.Handle("/file", mw.ThenFunc(putHandler)).Methods("POST")
	r.Handle("/refresh-keys", mw.ThenFunc(refreshKeysHandler)).Methods("POST")
	r.Handle("/export/{id:[0-9a-f]{64}}", mw.ThenFunc(exportHandler)).Methods("POST")
	r.Handle("/meta/{id:[0-9a-f]{64}}", mw.ThenFunc(metaHandler)).Methods("GET")
	r.Handle("/file/{id:[0-9a-f]{64}}", mw.ThenFunc(auth.JustCheck(authenticator, getHandler))).Methods("GET")
	http.Handle("/", r)
	log.Fatal(http.ListenAndServeTLS(":443", config.TLSCert, config.TLSKey, nil))
}

func configureLogging() {
	logrus.SetFormatter(&logstash.LogstashFormatter{Type: "FileVault"})
	var err error
	if len(config.HTTPLog) > 0 {
		logfile, err = os.OpenFile(config.HTTPLog, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		if err == nil {
			logrus.SetOutput(logfile)
		}
	}
	hostname, err = os.Hostname()
	var usr *user.User
	usr, err = user.Current()
	if err == nil {
		username = usr.Username
	} else {
		username = "unknown"
	}
	hook, err := logrus_mail.NewMailHook("FileVault", config.SMTPServer, config.SMTPPort, config.EmailFrom, config.EmailTo)
	if err == nil {
		logrus.AddHook(hook)
	}
	appLog = logrus.WithFields(logrus.Fields{
		"server":      hostname,
		"svc_account": username,
	})
	if err != nil {
		appLog.WithFields(logrus.Fields{
			"error": err,
		}).Warn("Couldn't add email hook for errors")
	}
}

func panicHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				panicCounter.Add(1)
				appLog.WithFields(logrus.Fields{
					"error": err,
				}).Error("Caught panic")
				http.Error(w, http.StatusText(500), 500)
			}
		}()

		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func loggingHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		lrw := httputil.NewResponseWriterLogger(w)
		t1 := time.Now()
		next.ServeHTTP(lrw, r)
		t2 := time.Now()
		appLog.WithFields(logrus.Fields{
			"response_time_seconds": t2.Sub(t1).Seconds(),
			"client":                r.RemoteAddr,
			"user_agent":            r.UserAgent(),
			"url":                   r.URL.String(),
			"http_proto":            r.Proto,
			"bytes_received":        r.ContentLength,
			"tls_version":           httputil.TlsVersion(r.TLS.Version),
			"form":                  r.Form,
			"status":                lrw.Status(),
			"size":                  lrw.Size(),
			"method":                r.Method,
		}).Info("Request completed")
	}
	return http.HandlerFunc(fn)
}

func getHandler(w http.ResponseWriter, r *http.Request) {
	id := idMatcher.FindString(r.URL.Path)
	md := &fv.Metadata{}
	err := vault.GetMetadata(id, md)
	if err != nil {
		fmt.Println(err)
		http.NotFound(w, r)
		return
	}
	if len(md.Filename) > 0 {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, md.Filename))
	}
	if len(md.MimeType) > 0 {
		w.Header().Set("Content-Type", md.MimeType)
	}
	if md.Size != 0 {
		w.Header().Set("Content-Length", fmt.Sprint(md.Size))
	}
	w.Header().Set("ETag", id)
	err = vault.Get(id, w, r.Header.Get("X-Authenticated-Username"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	return
}

func putHandler(w http.ResponseWriter, r *http.Request) {
	// send a file using the 'file' parameter,
	// or send a path to a file accessible by
	// the server using the 'path' parameter

	// get the start time now so we know when the file was received
	start := time.Now()

	// if subject is not specified, fail early
	subject := r.FormValue("subject")
	if len(subject) == 0 {
		http.Error(w, "Missing required field 'subject'", http.StatusBadRequest)
		return
	}

	// data is provided as a path or attached file
	n, s, rc, err := getData(r)
	if err != nil {
		switch {
		case os.IsNotExist(err):
			http.Error(w, err.Error(), http.StatusNotFound)
		case os.IsPermission(err):
			http.Error(w, err.Error(), http.StatusUnauthorized)
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// close the open file handle when we're done
	defer rc.Close()

	// populate the metadata
	md := &fv.Metadata{
		Subject:  subject,
		Filename: n,
		Received: start,
		Size:     s,
		MimeType: mime.TypeByExtension(filepath.Ext(n)),
	}

	// Store(unencryptedData io.Reader, md *Metadata) (id string, err error)
	var id string
	id, err = vault.Store(rc, md)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR STORING FILE:%s\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the fileID to the client
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(id))
	importCounter.Add(1)
	return
}

func refreshKeysHandler(w http.ResponseWriter, r *http.Request) {
	data, err := os.Open(config.ProdSupportPubRing)
	if err != nil {
		switch {
		case os.IsNotExist(err):
			http.Error(w, err.Error(), http.StatusNotFound)
		case os.IsPermission(err):
			http.Error(w, err.Error(), http.StatusUnauthorized)
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	err = vault.LoadExportKeyring(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	refreshCounter.Add(1)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Success"))
	return
}

func metaHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	md := &fv.Metadata{}
	err := vault.GetMetadata(id, md)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var js []byte
	js, err = json.Marshal(md)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
	return
}

func exportHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	recipient := r.FormValue("recipient")
	if len(recipient) == 0 {
		http.Error(w, "Missing required field 'recipient', which must be a hex encoded PGP public key finderprint", http.StatusBadRequest)
		return
	}
	fingerprint, err := fv.HexStringToFingerprint(recipient)
	if err != nil {
		http.Error(w, "'recipient' must be a hex encoded PGP public key finderprint", http.StatusBadRequest)
		return
	}
	var path string
	path, err = vault.Export(id, fingerprint)
	if err != nil {
		switch err {
		case fv.ErrRecipientNotInWhitelist:
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	// Return the filepath to the client
	w.WriteHeader(http.StatusCreated)
	fmt.Fprint(w, path)
	exportCounter.Add(1)
	return
}

func loadConfig() {
	// load configuration
	flag.Parse()
	configData, err := ioutil.ReadFile(*configFile)
	if err != nil {
		log.Fatalln("Error reading configuration file:", err)
	}
	_, err = toml.Decode(string(configData), &config)
	if err != nil {
		log.Fatalln("Error decoding configuration file:", err)
	}
	if err = config.Validate(); err != nil {
		log.Fatalln(err)
	}
	log.Println("Config OK")
	return
}

func dataFromPath(p string) (name string, size int64, rc io.ReadCloser, err error) {
	var fi os.FileInfo
	fi, err = os.Stat(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error calling os.Stat(%s) on uploaded file: %s\r\n", p, err)
		return
	}
	size = fi.Size()
	var f *os.File
	f, err = os.Open(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error calling os.Open(%s) on uploaded file: %s\r\n", p, err)
		return
	}
	name = filepath.Base(p)
	return name, size, f, nil
}

// wrapper method to return consistent results whether file data is received via
// a path or an http upload
func getData(r *http.Request) (name string, size int64, rc io.ReadCloser, err error) {
	path := r.FormValue("path")
	if len(path) > 0 {
		return dataFromPath(path)
	}
	var (
		f  multipart.File
		fh *multipart.FileHeader
	)
	f, fh, err = r.FormFile("file")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing FormFile: %s\r\n", err)
		return
	}
	d := ioutil.Discard
	size, err = io.Copy(d, f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting size of uploaded file: %s\r\n", err)
		return
	}
	_, err = f.Seek(0, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error rewinding uploaded file: %s\r\n", err)
		return
	}
	return filepath.Base(fh.Filename), size, f, nil
}
