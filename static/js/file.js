const KEY_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$-_.+!*'(,";
const PBKDF2_ITERATIONS = 50000;
const BLOCK_SIZE = 5242880;

/**
 * Progress handler
 * @callback ProgressHandler
 * @param {Object} progressEvent
 * @returns {void}
 */

/**
 * Generates a password for encryption
 * @param {number} length character length of the password
 * @returns {string}
 */
function generatePassword(length) {
    let array = new Uint8Array(length);
    let cryptoObj = window.crypto || window.msCrypto;
    cryptoObj.getRandomValues(array);
    let output = "";
    while (output.length < length) {
        for (let i = 0; i < array.length; i++) {
            // skip values that are larger than the biggest multiple of KEY_ALPHABET.length
            // otherwise we wouldn't have a good distribution
            if (array[i] > Math.floor(255/KEY_ALPHABET.length)*KEY_ALPHABET.length) continue;
            output += KEY_ALPHABET[Math.abs(array[i] % KEY_ALPHABET.length)];
            if (output.length === length) break;
        }
    }
    return output;
}


/**
 * Represents a cryptographic pair used for file encryption.
 * Includes the AES-GCM key and both encryption IVs.
 */
class CryptoPair {
    /**
     * @type CryptoKey
     * @readonly
     */
    key;
    /**
     * @type string
     * @readonly
     */
    password;
    /**
     * @type ArrayBuffer
     * @readonly
     */
    ogBlockIV;
    /**
     * @type ArrayBuffer
     * @readonly
     */
    filenameIV;

    /** @type boolean */
    _filenameEncrypted;

    /** @type Uint8Array */
    _currentIV;

    constructor(password, key, ogBlockIV, filenameIV) {
        this.password = password;
        this.key = key;
        this.ogBlockIV = ogBlockIV;
        this.filenameIV = filenameIV;
        this._filenameEncrypted = false;
        this._currentIV = ogBlockIV;
    }

    /**
     * Constructs a CryptoPair from a password and salt. The password is utf8 encoded.
     * @param {string} password
     * @param {Uint8Array} salt 32 bytes of salt
     * @constructs
     * @returns {Promise<CryptoPair>}
     */
    static async fromPassword(password, salt) {
        const subtle = (window.crypto || window.msCrypto).subtle;

        const importedPassword = await subtle.importKey(
            "raw",
            new TextEncoder().encode(password),
            "PBKDF2",
            false,
            ["deriveBits"]
        );
        const strengthened = await subtle.deriveBits(
            {name: "PBKDF2", hash: "SHA-256", salt: salt, iterations: PBKDF2_ITERATIONS},
            importedPassword,
            768
        );

        const key = await subtle.importKey(
            "raw",
            strengthened.slice(0, 32),
            "AES-GCM",
            false,
            ["encrypt", "decrypt"]
        );

        return new CryptoPair(password, key, strengthened.slice(32, 64), strengthened.slice(64, 96));
    }

    /**
     * Encrypt and base64 encode a filename. Single use only to ensure key privacy.
     * @param {string} filename
     * @returns {Promise<String>}
     */
    async encryptFilename(filename) {
        if (this._filenameEncrypted) {
            throw "Cannot encrypt twice using the same IV";
        }
        this._filenameEncrypted = true;

        let subtle = (window.crypto || window.msCrypto).subtle;

        let enc_bytes = await subtle.encrypt(
            {name: "AES-GCM", iv: this.filenameIV, tagLength: 128},
            this.key,
            new TextEncoder().encode(filename)
        );
        return btoa(
            new Uint8Array(enc_bytes)
                .reduce((data, byte) => data + String.fromCharCode(byte), '')
        );
    }

    /**
     * Encrypts a block of 5242880 (5MiB) bytes according to the f.bain protocol.
     * Generates a new IV for next use.
     * @param {Uint8Array} blockData 5242880
     * @returns {Promise<ArrayBuffer>} ciphertext
     */
    async encryptBlock(blockData) {
        const cryptoObj = window.crypto || window.msCrypto;

        const newIv = new Uint8Array(32);
        cryptoObj.getRandomValues(newIv);

        const subtle = cryptoObj.subtle;

        let block = new Uint8Array(newIv.byteLength + blockData.byteLength);
        block.set(newIv, 0);
        block.set(blockData, 32);

        const cipher = await subtle.encrypt(
            {name: "AES-GCM", iv: this._currentIV, tagLength: 128},
            this.key,
            block
        );

        this._currentIV = newIv;

        return cipher;
    }

    /**
     * Base64 decode and decrypt a filename.
     * @param {string} cipher
     * @returns {Promise<string>} filename
     */
    async decryptFilename(cipher) {
        const b64 = atob(cipher);
        const decoded_cipher = new Uint8Array(b64.length);
        for (let i = 0; i < b64.length; i++) decoded_cipher[i] = b64.charCodeAt(i);

        const subtle = (window.crypto || window.msCrypto).subtle;
        return new TextDecoder().decode(await subtle.decrypt(
            {name: "AES-GCM", iv: this.filenameIV, tagLength: 128},
            this.key,
            decoded_cipher
        ));
    }

    /**
     * Decrypts a block of 5242928 (~5MiB) bytes according to the f.bain protocol.
     * @param {ArrayBuffer} cipher
     * @returns {Promise<ArrayBuffer>} block
     */
    async decryptBlock(cipher) {
        const subtle = (window.crypto || window.msCrypto).subtle;
        const d_block = await subtle.decrypt(
            {"name": "AES-GCM", "iv": this._currentIV, "tagLength": 128},
            this.key, cipher);
        this._currentIV = new Uint8Array(d_block.slice(0, 32)); // update iv for next iteration
        return d_block.slice(32, cipher.byteLength);
    }

}


/** Represents a local file to be encrypted with the f.bain protocol */
class LocalFile {
    /**
     * Constructs an instance ready for encryption
     * @param {File} file specifies the file object
     */
    constructor(file) {
        this.file = file;
    }

    /**
     * Upload this file to a host.
     * @param {number} keyLength length of the encryption key
     * @param {string} host file host in format <protocol>://<host> leave undefined to
     * use the current address as the host, notice no / at the end
     * @param {ProgressHandler} progressHandler optional handler for progress updates
     *
     * @return {Promise<{uuid: string, revocationToken: string, password: string}>}
     *  object containing the uuid, revocationToken, and password
     */
    async upload(keyLength, host, progressHandler) {
        if (host === undefined) host = "";  // set default for host if not provided

        const cryptoObj = (window.crypto || window.msCrypto);
        if (cryptoObj === undefined) {
            throw "browser does not support necessary cryptographic API";
        }
        const salt = new Uint8Array(32);
        cryptoObj.getRandomValues(salt);

        // generate a password and make sure the end character is suitable for messaging apps
        let password;
        do {
            password = generatePassword(keyLength);
        } while (",.".includes(password[password.length-1]));



        let keyPair;
        try {
            keyPair = await CryptoPair.fromPassword(password, salt);
        } catch (e) {
            console.log(e);
            throw "failed to construct encryption pair";
        }

        progressHandler({statusText: "encrypting filename"});
        let encryptedFilename;
        try {
            encryptedFilename = await keyPair.encryptFilename(this.file.name);
        } catch (e) {
            console.log(e);
            throw "failed to encrypt filename";
        }

        progressHandler({statusText: "encrypting file"});
        let encryptedData;
        try {
            encryptedData = await this._getEncryptedBlob(keyPair, progressHandler);
        } catch (e) {
            console.log(e);
            throw "failed to encrypt file contents";
        }

        progressHandler({statusText: "uploading file"});
        const response = await this._sendRequest(
            host,
            encryptedData,
            encryptedFilename,
            Array.from(salt),
            progressHandler
        );

        return {
            uuid: response.uuid,
            revocationToken: response.revocation_token,
            password
        };

    }

    /**
     * Encrypts the contents of the file and returns a blob
     * @param {CryptoPair} keyPair
     * @param {ProgressHandler} progressHandler
     * @returns {Promise<Blob>}
     * @private
     */
    async _getEncryptedBlob(keyPair, progressHandler) {
        let outputBlob = new Blob([]); // preparing output blob, needs to be blob to not crash the browser
        for (let offset = 0; offset < this.file.size; offset += BLOCK_SIZE) {
            const blockData = new Uint8Array(await this.file.slice(offset, offset + BLOCK_SIZE).arrayBuffer());

            const cipher = await keyPair.encryptBlock(blockData);

            outputBlob = new Blob([outputBlob, cipher]);

            progressHandler({progress: Math.min(offset, this.file.size) / this.file.size * 0.5});
        }
        return outputBlob;
    }

    /**
     * Sends a POST request with encrypted file data
     * @param {string} host
     * @param {Blob} encryptedData
     * @param {string} encryptedFilename
     * @param {Array<number>} saltArray array of ints, each representing a byte
     * @param {ProgressHandler} progressHandler
     * @returns {Promise<Object>} success response from the server
     * @private
     */
    async _sendRequest(host, encryptedData, encryptedFilename, saltArray, progressHandler) {
        let promise = new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            // response handler
            xhr.addEventListener("readystatechange", function () {
                if (this.readyState === this.DONE) {
                    if (this.status === 200) {
                        resolve(JSON.parse(this.responseText))
                    } else {
                        reject({code: this.status, message: "Non 200 status from server"});
                    }
                }
            });
            // update progress bar
            xhr.upload.addEventListener("progress", p => progressHandler({progress: 0.5 + (p.loaded / p.total / 2)}));

            progressHandler({status: "neutral", statusText: "uploading..."})
            xhr.open("POST", `${host}/new`);
            xhr.setRequestHeader("Content-Type", "application/octet-stream");

            // setting metadata header to send salt and file name encoded in json, then in base64
            xhr.setRequestHeader("X-Metadata", window.btoa(JSON.stringify({
                filename: encryptedFilename,
                salt: saltArray
            })));
            xhr.send(encryptedData);
        });
        return await promise;
    }
}


/** Represents an uploaded file */
class ForeignFile {

    /**
     * @readonly
     * @type string
     */
    host;

    /**
     * @readonly
     * @type string
     */
    id;

    /**
     * @readonly
     * @type string
     */
    filename;

    /**
     * @readonly
     * @type CryptoPair
     * @private
     */
    _keyPair;

    /**
     * @param {string} host
     * @param {string} id
     * @param {CryptoPair} keyPair
     * @param {string} filename
     */
    constructor(host, id, keyPair, filename) {
        this.host = host;
        this.id = id;
        this._keyPair = keyPair;
        this.filename = filename;
    }

    /**
     * Constructs an instance from a host and an ID
     * @param {string} host host
     * @param {string} id id
     * @param {string} password password for key derivation
     */
    static async fromIDPair(host, id, password) {
        const resp = await fetch(`${host}/${id}/meta`);
        if (!resp.ok) throw "could not fetch information";
        const resp_json = await resp.json();

        let keyPair;
        try {
            keyPair = await CryptoPair.fromPassword(password, new Uint8Array(resp_json.salt));
        } catch (e) {
            console.log(e);
            throw "failed to create key pair";
        }

        let filename;
        try {
            filename = await keyPair.decryptFilename(resp_json.filename);
        } catch (e) {
            console.log(e);
            throw "failed to decrypt file name, bad key?";
        }
        return new ForeignFile(host, id, keyPair, filename);
    }

    /**
     * Get size of the file
     * @returns {Promise<number>}
     */
    async getSize() {
        const resp = await fetch(`${this.host}/${this.id}/raw`, {method: "HEAD"});
        if (!resp.ok) return -1;
        return Number(resp.headers.get("content-length"));
    }

    /**
     * Decrypted file contents
     * @param {ProgressHandler} progress
     * @returns {Promise<Blob>} file data
     */
    async getData(progress) {
        progress({statusText: "Downloading file"});
        let cipher;
        try {
            cipher = await this.getRawData(progress);
        } catch (e) {
            progress({status: "error", statusText: `failed to fetch data (code: ${e})`});
        }
        progress({statusText: "Decrypting file"});
        let output_blob = new Blob([]); // working with blobs to not crash the browser with big files
        try {
            let offset = 0;
            while (offset < cipher.size) {
                const block = await cipher.slice(offset, offset + 5242928).arrayBuffer();
                const d_block = await this._keyPair.decryptBlock(block);

                output_blob = new Blob([output_blob, d_block]);

                offset += 5242928;
                progress({progress: Math.min(0.5 + offset / cipher.size, 1)});
            }
        } catch (e) {
            console.log(e);
            progress({
                status: "error",
                statusText: "Decryption error"
            });
        }
        return output_blob;
    }

    /**
     * Fetches encrypted data
     * @param {ProgressHandler} progress
     * @returns {Promise<Blob>}
     */
    async getRawData(progress) {
        const xhr = new XMLHttpRequest();
        const promise = new Promise((resolve, reject) => { // fuck callbacks
            xhr.addEventListener("readystatechange", function () {
                if (this.readyState === this.DONE) {
                    if (this.status === 200) {
                        resolve(this.response);
                    } else {
                        reject(this.status);
                    }
                }
            });
            xhr.addEventListener("progress", function (p) {
                progress({progress: 0.10 + p.loaded / p.total * 0.40});
            })
            xhr.open("GET", `${this.host}/${this.id}/raw`);
            xhr.responseType = "blob";
            xhr.send();
        });
        return await promise;
    }
}