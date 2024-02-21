const KEY_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const CIPHER_VERSION = "v1";

// block size of unencrypted data (encrypted +16 bytes for GCM tag)
const BLOCK_SIZE = 1024 * 1024;  // 1 MiB
const PBKDF2_ITERATIONS = 1_000_000;

/**
 * Progress handler
 * @callback ProgressHandler
 * @param {Object} progressEvent
 * @returns {void}
 */

/**
 * Generates a password for encryption. 
 *
 * The current alphabet has 65 letters to chose from, which means log2(65) (~6.0) bits of 
 * entropy per letter. That means for any password of length n, the entropy will be
 * n*log2(65)
 * @param {number} length character length of the password
 * @returns {string}
 */
function generatePassword(length) {
    let array = new Uint8Array(length);
    let output;
    output = "";
    while (output.length < length) {
        window.crypto.getRandomValues(array);
        for (let i = 0; i < array.length; i++) {
            // skip values that are larger than the biggest multiple of KEY_ALPHABET.length
            // otherwise we wouldn't have an even distribution
            if (array[i] > Math.floor(255 / KEY_ALPHABET.length) * KEY_ALPHABET.length) continue;
            output += KEY_ALPHABET[Math.abs(array[i] % KEY_ALPHABET.length)];
            if (output.length === length) break;
        }
    }
    return output;
}


function wait(milliseconds) {
    return new Promise((res, _) => setTimeout(() => res(), milliseconds));
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
    blockIVBase;
    /**
     * @type ArrayBuffer
     * @readonly
     */
    filenameIVBase;

    /** @type boolean */
    _filenameEncrypted = false;

    /** 
     * @type Number
     * @readonly
     */
    blockNumber = 0;

    /** 
     * @type boolean
     * @readonly
     */
    rolledBack = false;

    constructor(password, key, blockIVBase, filenameIVBase) {
        this.key = key;
        this.password = password;
        this.blockIVBase = blockIVBase;
        this.filenameIVBase = filenameIVBase;
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
        // strengthened password for 1 key (128 bits) and 2 IVs (both 64 bits)
        const strengthened = await subtle.deriveBits(
            { name: "PBKDF2", hash: "SHA-256", salt: salt, iterations: PBKDF2_ITERATIONS },
            importedPassword,
            256
        );

        const key = await subtle.importKey(
            "raw",
            strengthened.slice(0, 16),
            "AES-GCM",
            false,
            ["encrypt", "decrypt"]
        );

        return new CryptoPair(password, key, strengthened.slice(16, 24), strengthened.slice(24, 32));
    }

    /**
     * Generate a full IV from a 8 byte base and a 4 byte unsigned integer
     * @param {Uint8Array} ivBase 
     * @param {Number} n 
     * @returns {Uint8Array}
     */
    genFullIV(ivBase, n = 0) {
        let iv = new Uint8Array(12);
        iv.set(ivBase, 0);
        // converting n to little Uint little endian
        const n_bytes = new Uint8Array([n >> 24 & 0xff, n >> 16 & 0xff, n >> 8 & 0xff, n & 0xff]);
        iv.set(n_bytes, 8);
        return iv;
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
            { name: "AES-GCM", iv: this.genFullIV(this.filenameIVBase, 0), tagLength: 128 },
            this.key,
            new TextEncoder().encode(filename)
        );
        return btoa(
            new Uint8Array(enc_bytes)
                .reduce((data, byte) => data + String.fromCharCode(byte), '')
        );
    }

    /**
     * Encrypts a block (BLOCK_SIZE bytes) according to the f.bain protocol.
     * @param {Uint8Array} blockData BLOCK_SIZE sized block of data
     * @returns {Promise<ArrayBuffer>} ciphertext
     */
    async encryptBlock(blockData) {
        const cipher = await window.crypto.subtle.encrypt({
            name: "AES-GCM",
            iv: this.genFullIV(this.blockIVBase, this.blockNumber++),
            tagLength: 128
        },
            this.key,
            blockData
        );

        this.rolledBack = false;

        return cipher;
    }

    /**
     * Rollback IV to the previous block (used when connection drops)
     */
    async rollbackIV() {
        if (!this.rolledBack) {
            this.blockNumber--;
            this.rolledBack = true;
        }
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
            { name: "AES-GCM", iv: this.genFullIV(this.filenameIVBase, 0), tagLength: 128 },
            this.key,
            decoded_cipher
        ));
    }

    /**
     * Decrypts a block of BLOCK_SIZE bytes according to the f.bain protocol.
     * @param {ArrayBuffer} cipher
     * @returns {Promise<ArrayBuffer>} block
     */
    async decryptBlock(cipher) {
        return await window.crypto.subtle.decrypt({
            "name": "AES-GCM",
            "iv": this.genFullIV(this.blockIVBase, this.blockNumber++),
            "tagLength": 128
        },
            this.key, cipher
        );
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
     * @param {ProgressHandler} progressHandler optional handler for progress updates
     * @param {string} host file host in format <protocol>://<host> leave undefined to
     * use the current address as the host, notice no / at the end
     *
     * @return {Promise<{uuid: string, revocationToken: string, password: string}>}
     *  object containing the uuid, revocationToken, and password
     */
    async upload(keyLength, progressHandler, host = "") {
        if (window.crypto === undefined) {
            throw "browser does not support necessary cryptographic API";
        }
        const salt = new Uint8Array(32);
        window.crypto.getRandomValues(salt);

        let password = generatePassword(keyLength);

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
        const contentLength = Math.ceil(this.file.size / BLOCK_SIZE) * 16 + this.file.size;
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
            throw error_msg;
        }
        if (!response.ok) throw "failed to create session";
        return (await response.json()).session_token;
    }

    /**
     * Uploads the file with a session
     * @param {string} host
     * @param {string} sessionToken
     * @param {CryptoPair} keyPair
     * @param {ProgressHandler} progressHandler
     * @returns {Promise<{uuid: string, revocation_token: string}>}
     * @private
     */
    async _uploadWithSession(host, sessionToken, keyPair, progressHandler) {
        let done = false;
        while (!done) {
            let promise = new Promise((resolve, reject) => {
                let socket = new WebSocket(`wss://${host ? new URL(host).host : location.host}/upload/${sessionToken}`);

                socket.onopen = (_) => {
                    progressHandler({ status: "neutral", statusText: "uploading file" });
                };

                socket.onmessage = async (event) => {
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
                                done = true; // do not retry, how would we recover?
                                reject("server requested more data than anticipated");
                                return;
                            }
                            let cipher;
                            try {
                                const blockData = new Uint8Array(await this.file.slice(offset, offset + BLOCK_SIZE).arrayBuffer());
                                cipher = await keyPair.encryptBlock(blockData);
                            } catch (e) {
                                done = true;
                                reject(e);
                                return;
                            }
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

                socket.onclose = _ => {
                    if (!done) reject("closed before finished");
                };

                socket.onerror = event => {
                    console.log(event);
                    reject("error while uploading");
                };
            });
            try {
                return await promise;
            } catch (e) {
                if (done) throw e;
                else {
                    console.log(e);
                    await keyPair.rollbackIV();
                }
            }
            progressHandler({ statusText: "Reconnecting in 10s", status: "error" });
            await wait(10000);
            progressHandler({ statusText: "Reconnecting...", status: "error" });
        }
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
            throw "failed to decrypt";
        }
        return new ForeignFile(host, id, keyPair, filename, resp_json.content_length);
    }

    /**
     * Decrypted file contents
     * @param {ProgressHandler} progressHandler
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
                };

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
                        socket.send(JSON.stringify({ "read": BLOCK_SIZE + 16, "seek": offset }));
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

                    socket.send(JSON.stringify({ "read": BLOCK_SIZE + 16 }));
                };

                socket.onclose = _ => {
                    if (!done) reject("closed before finished");
                };

                socket.onerror = event => {
                    console.log(event);
                    reject("error while downloading");
                };
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
     * Deletes a file from remote server
     * @param {string} file_id
     * @param {string} revocationToken
     * @returns {Promise<boolean>} boolean signifying if the file was deleted
     */
    static async delete(file_id, revocationToken) {
        let resp = await fetch("/" + file_id, {
            method: "DELETE", headers: { authorization: revocationToken }
        });
        return resp.status === 200;
    }

    /**
     * Expiration property
     * @param {string} file_id
     * @param {string} revocationToken
     * @returns {Promise<number>} time at which the file expires (unix seconds timestamp); -2 if an error occured
     */
    static async expires_at(file_id, revocationToken) {
        let resp = await fetch(`/${file_id}/expire`, {
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
     * @param {string} file_id
     * @param {string} revocationToken
     * @param {number} timestamp unix seconds timestamp at which the file should expire
     * @returns {Promise<boolean>} booleans signifying if the new expiration date was set
     */
    static async set_expires_at(file_id, revocationToken, timestamp) {
        let resp = await fetch(`/${file_id}/expire`, {
            method: "PUT",
            body: JSON.stringify({ "expires_at": timestamp }),
            headers: { authorization: revocationToken, "content-type": "application/json" }
        });
        return resp.status === 200;
    }
}
