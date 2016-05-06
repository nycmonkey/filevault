# FileVault

Secure, content-addressable storage for sensitive files.  Uses random, unique data encrypting key for each file at rest. Exports encrypted file to whitelisted recipient using recipient's PGP public key.

## Web API

### `POST /file`

Adds a file to the FileVault

**Required parameters**

* One of "file" or "path"
  * "file" is the key to an http file upload (i.e., client sends the data)
  * "path" is a full path to the file on a shared filesystem (must be accessible by the FileVault server / service account)
* "subject" - a string describing the content, which cannot be blank (e.g., category.subcategory.scope.source.v1)

**Response**

* Responds with a 201 status code ("CREATED") if the ingestion succeeds
* Response body is a plain string of the sha256 hexdigest of the file's contents matching /^[a-f0-9]{64}$/
* The sha256 hexdigest is the ID of the file in the FileVault

**Tips**

* Confirm that the response is a 201; if not, assume the file was not ingested
* Compare the returned digest with one calculated locally to verify that the vault received what you intended to send

  * With sha256sum: `sha256sum <file>`
  * With openssl: `openssl dgst -sha256 -hex <file>`


### `GET /file/{id}`

Download an unencrypted copy of the file.

**Required parameters**

Username and password must be provided using Basic Authentication.  FileVault
configuration must point to a valid [htpasswd](https://en.wikipedia.org/wiki/.htpasswd)
file.  A simple command line tool for adding and removing users from an htpasswd
file is available [here](https://github.com/nycmonkey/htpasswd).


### `GET /meta/{id}`

Returns metadata associated with a file in the vault as JSON.

**Request**

* id is the sha256 hexdigest of the file's contents (returned by POST /file)
* id must match /^[a-f0-9]{64}$/

**Response**

* 404 if file ID is not in the FileVault
* If successful, response is a 200 with a JSON body consisting of:
  * "Subject": a string of the subject provided when the file was stored
  * "Received": a timestamp in RFC 3339 format representing when the file was ingested by the FileVault
  * "Filename": a string of the original file name at time of ingestion
  * "MimeType": the detected MimeType of the file (using only the file extension)
  * "Size": the size of the unencrypted file, in bytes

```javascript
{
  "Filename": "foo.txt",
  "Subject": "whatever.was.specified.at.ingest",
  "MimeType": "text/plain",
  "Received": "2015-12-19T16:39:57-08:00",
  "Size": 12345684
}
```

### `POST /export/{id}`

Request the export of a file from the vault to a particular recipient

**Required parameters**

* recipient: a hex-encoded string of the 20 byte PGP public key fingerprint of the target recipient

**Response**

* If authorized, the response is plain string with a path to the exported file
* The exported file will be encrypted with the specified PGP public key
* If the public key is not in the whitelisted keyring, the response will be 401 ("Unauthorized")

**tips**

* From gpg, you can view the fingerprints of the keys in your keyring using `gpg --fingerprint`
* This FileVault server only exports to a single folder defined in its configuration file

### `POST /refresh-keys`

Causes FileVault to reload the whitelisted export keys from the configured keyring location

**Required parameters**

NONE
