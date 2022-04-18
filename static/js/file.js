const KEY_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$-_.+!*'(,";
const PBKDF2_ITERATIONS = 500000;

// this is the block size if UNENCRYPTED data (+48 if encrypted to account for IV and tag)
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
    let output = "";
    while (output.length < length) {
        window.crypto.getRandomValues(array);
        for (let i = 0; i < array.length; i++) {
            // skip values that are larger than the biggest multiple of KEY_ALPHABET.length
            // otherwise we wouldn't have a good distribution
            if (array[i] > Math.floor(255 / KEY_ALPHABET.length) * KEY_ALPHABET.length) continue;
            output += KEY_ALPHABET[Math.abs(array[i] % KEY_ALPHABET.length)];
            if (output.length === length) break;
        }
    }
    return output;
}


async function wait(milliseconds) {
    await new Promise((res, _) => setTimeout(() => res(), milliseconds));
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

    /** @type Uint8Array */
    _rollbackIV;

    constructor(password, key, ogBlockIV, filenameIV) {
        this.password = password;
        this.key = key;
        this.ogBlockIV = ogBlockIV;
        this.filenameIV = filenameIV;
        this._filenameEncrypted = false;
        this._currentIV = ogBlockIV;
        this._rollbackIV = ogBlockIV;
    }

    /**
     * Constructs a CryptoPair from a password and salt. The password is utf8 encoded.
     * @param {string} password
     * @param {Uint8Array} salt 32 bytes of salt
     * @constructs
     * @returns {Promise<CryptoPair>}
     */
    static async fromPassword(password, salt) {
        const subtle = window.crypto.subtle;

        const importedPassword = await subtle.importKey(
            "raw",
            new TextEncoder().encode(password),
            "PBKDF2",
            false,
            ["deriveBits"]
        );
        const strengthened = await subtle.deriveBits(
            { name: "PBKDF2", hash: "SHA-256", salt: salt, iterations: PBKDF2_ITERATIONS },
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

        let enc_bytes = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: this.filenameIV, tagLength: 128 },
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
        const newIv = new Uint8Array(32);
        window.crypto.getRandomValues(newIv);

        let block = new Uint8Array(newIv.byteLength + blockData.byteLength);
        block.set(newIv, 0);
        block.set(blockData, 32);

        const cipher = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: this._currentIV, tagLength: 128 },
            this.key,
            block
        );

        this._rollbackIV = this._currentIV;
        this._currentIV = newIv;

        return cipher;
    }

    /**
     * Rollback IV to the previous block (used when connection drops)
     */
    async rollbackIV() {
        this._currentIV = this._rollbackIV;
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

        return new TextDecoder().decode(await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: this.filenameIV, tagLength: 128 },
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
        const d_block = await window.crypto.subtle.decrypt(
            { "name": "AES-GCM", "iv": this._currentIV, "tagLength": 128 },
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

        if (window.crypto === undefined) {
            throw "browser does not support necessary cryptographic API";
        }
        const salt = new Uint8Array(32);
        window.crypto.getRandomValues(salt);

        // generate a password and make sure the end character is suitable for messaging apps
        let password;
        do {
            password = generatePassword(keyLength);
        } while (",.".includes(password[password.length - 1]));


        let keyPair;
        try {
            keyPair = await CryptoPair.fromPassword(password, salt);
        } catch (e) {
            console.log(e);
            throw "failed to construct encryption pair";
        }

        progressHandler({ statusText: "encrypting filename" });
        let encryptedFilename;
        try {
            encryptedFilename = await keyPair.encryptFilename(this.file.name);
        } catch (e) {
            console.log(e);
            throw "failed to encrypt filename";
        }

        progressHandler({ statusText: "creating session" });
        const contentLength = Math.ceil(this.file.size / BLOCK_SIZE) * 48 + this.file.size;
        const session_token = await this._createUploadSession(host, encryptedFilename, salt, contentLength);
        const response = await this._uploadWithSession(host, session_token, keyPair, progressHandler);

        return {
            uuid: response.uuid,
            revocationToken: response.revocation_token,
            password
        };

    }

    /**
     * Creates a session
     * @param {string} host
     * @param {string} encryptedFilename
     * @param {Uint8Array} saltArray
     * @param {number} contentLength
     * @returns {Promise<string>}
     * @private
     */
    async _createUploadSession(host, encryptedFilename, saltArray, contentLength) {
        const response = await fetch(`${host}/upload`, {
            method: "POST", body: JSON.stringify({
                filename: encryptedFilename,
                salt: Array.from(saltArray),
                content_length: contentLength
            }),
            headers: { "content-type": "application/json" }
        });
        if (response.status === 422) {
            let error = await response.json();
            let error_msg = "";
            for (let e of error.detail) {
                error_msg += e.loc + ": " + e.msg + "\n";
            }
            throw error_msg
        }
        if (!response.ok) throw "failed to create session";
        return (await response.json()).session_token
    }

    /**
     * Uploads the file with a session
     * @param {string} host
     * @param {string} sessionToken
     * @param {CryptoPair} keyPair
     * @param {ProgressHandler} progressHandler
     * @param {number} retry
     * @returns {Promise<{uuid: string, revocation_token: string}>}
     * @private
     */
    async _uploadWithSession(host, sessionToken, keyPair, progressHandler, retry = 0) {
        let promise = new Promise((resolve, reject) => {
            let socket = new WebSocket(`wss://${host ? new URL(host).host : location.host}/upload/${sessionToken}`);
            let last_timeout = null;
            socket.onopen = (_) => {
                retry = 0; // we have successfully connected -> reset the counter
                progressHandler({ status: "neutral", statusText: "uploading file" });
            };

            socket.onmessage = async (event) => {
                if (last_timeout != null) clearTimeout(last_timeout);
                last_timeout = setTimeout(socket.onerror, 60000);
                const data = JSON.parse(event.data);
                switch (data.code) {
                    case 201:
                        // upload complete
                        resolve(data);
                        break;
                    case 100:
                        // encrypt the required block
                        const offset = data.block * BLOCK_SIZE;
                        if (offset > this.file.size) {
                            socket.close(1000);
                            reject("server requested more data than anticipated");
                            return;
                        }
                        const blockData = new Uint8Array(await this.file.slice(offset, offset + BLOCK_SIZE).arrayBuffer());
                        const cipher = await keyPair.encryptBlock(blockData);
                        socket.send(cipher);
                        progressHandler({ progress: offset / this.file.size });
                        break;
                    case 414:
                    case 401:
                        // error in communication
                        reject(data.detail);
                        break;
                }
            };

            const f = this;
            socket.onerror = (_) => {
                if (retry == 3) {
                    reject("failed to connect");
                } else {
                    // prevent revival of old socket
                    socket.onmessage = null;
                    socket.onerror = null;

                    progressHandler({ status: "error", statusText: "encountered an error, reconnecting" });
                    keyPair.rollbackIV();
                    f._uploadWithSession(host, sessionToken, keyPair, progressHandler, retry + 1).then(e => resolve(e), e => reject(e));
                }
            };
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
     * @readonly
     * @type number
     */
    size;

    /**
     * @param {string} host
     * @param {string} id
     * @param {CryptoPair} keyPair
     * @param {string} filename
     */
    constructor(host, id, keyPair, filename, size) {
        this.host = host;
        this.id = id;
        this._keyPair = keyPair;
        this.filename = filename;
        this.size = size;
    }

    /**
     * Constructs an instance from a host and an ID
     * @param {string} host host
     * @param {string} id id
     * @param {string} password password for key derivation
     */
    static async fromIDPair(host, id, password) {
        const resp = await fetch(`${host}/${id}/meta`);
        if (!resp.ok) throw "failed to fetch information";
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
            throw "failed to decrypt. bad password?";
        }
        return new ForeignFile(host, id, keyPair, filename, resp_json.content_length);
    }

    /**
     * Decrypted file contents
     * @param {ProgressHandler} progressHandler
     * @param {number} offset file offset
     * @param {number} retry
     * @returns {Promise<Blob>} file data
     */
    async getData(progressHandler) {
        let done = false;
        let offset = 0;
        let blob = new Blob([]);
        while (!done) {
            const promise = new Promise((resolve, reject) => {
                const socket = new WebSocket(`wss://${this.host || location.host}/${this.id}/raw`);

                let first_msg = true;

                socket.onopen = _ => {
                    progressHandler({ statusText: "Downloading", status: "neutral", progress: offset / this.size });
                }

                socket.onmessage = async event => {
                    const data = event.data;

                    if (first_msg) {
                        // this is the first message that sends information
                        // about the requested file
                        const json = JSON.parse(data);
                        if (json.code != 200) {
                            done = true; // do not retry
                            reject("File was not found");
                            return;
                        }
                        socket.send(JSON.stringify({ "read": BLOCK_SIZE + 48, "seek": offset }));
                        first_msg = false;
                        return;
                    }

                    try {
                        blob = new Blob([blob, await this._keyPair.decryptBlock(await data.arrayBuffer())]);
                    } catch (e) {
                        done = true; // do not retry, how would we recover?
                        reject(e);
                        return;
                    }
                    offset += data.size;

                    progressHandler({ progress: offset / this.size });
                    if (offset == this.size) {
                        done = true;
                        socket.close(1000);
                        resolve(blob);
                        return;
                    }

                    socket.send(JSON.stringify({ "read": BLOCK_SIZE + 48 }));
                }

                socket.onclose = _ => {
                    if (!done) reject("closed before finished");
                }

                socket.onerror = event => {
                    console.log(event);
                    reject("error while downloading");
                }
            });
            try {
                return await promise;
            } catch (e) {
                if (done) throw e;
                else console.log(e);
            }
            progressHandler({ statusText: "Reconnecting in 10s", status: "error" });
            await wait(10000);
            progressHandler({ statusText: "Reconnecting...", status: "error" });
        }
    }

    /**
     * Deletes the file from remote server
     * @param {string} revocationToken
     * @returns {Promise<boolean>} boolean signifying if the file was deleted
     */
    async delete(revocationToken) {
        let resp = await fetch("/" + this.id, {
            method: "DELETE", headers: { authorization: revocationToken }
        });
        return resp.status === 200;
    }

    /**
     * Expiration property
     * @param {string} revocationToken
     * @returns {Promise<number>} time at which the file expires (unix seconds timestamp); -2 if an error occured
     */
    async expires_at(revocationToken) {
        let resp = await fetch(`/${this.id}/expire`, {
            headers: { authorization: revocationToken }
        });
        if (resp.ok) {
            let contents = await resp.json();
            return contents.expires_at;
        } else {
            return -2;
        }
    }

    /**
     * Set new expiration date
     * @param {string} revocationToken
     * @param {number} timestamp unix seconds timestamp at which the file should expire
     * @returns {Promise<boolean>} booleans signifying if the new expiration date was set
     */
    async set_expires_at(revocationToken, timestamp) {
        let resp = await fetch(`/${this.id}/expire`, {
            method: "PUT",
            body: JSON.stringify({ "expires_at": timestamp }),
            headers: { authorization: revocationToken, "content-type": "application/json" }
        });
        return resp.status === 200;
    }
}
