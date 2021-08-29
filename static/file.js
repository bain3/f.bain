const BASE73 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$–_.+!*'(),";
const PBKDF2_ITERATIONS = 50000;
const BLOCK_SIZE = 5242880;

/**
 * Progress handler
 * @name ProgressHandler
 * @function
 * @param {Object} progressEvent
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
            // skip values that are larger than the biggest multiple of 73
            // otherwise we would have a higher probability of getting values between 0 and 36
            if (array[i] > 219) continue;
            output += BASE73[Math.abs(array[i] % 73)];
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
     * Encrypts a block of 5242880 (5MiB) of bytes according to the f.bain protocol.
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
     * @return {Object} object containing the uuid, revocationToken, and password
     */
    async upload(keyLength, host, progressHandler) {
        if (host === undefined) host = "";  // set default for host if not provided

        const cryptoObj = (window.crypto || window.msCrypto);
        if (cryptoObj === undefined) {
            throw "browser does not support necessary cryptographic API";
        }
        const salt = new Uint8Array(32);
        cryptoObj.getRandomValues(salt);

        const password = generatePassword(keyLength);

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

            // noinspection JSValidateTypes
            progressHandler({progress: Math.min(offset, this.file.size) / this.file.size * 0.5});
        }
        return outputBlob;
    }

    /**
     * Sends a POST request with encrypted file data
     * @param {string} host
     * @param {Blob} encryptedData
     * @param {string} encryptedFilename
     * @param {Array} saltArray array of ints, each representing a byte
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
            // noinspection JSValidateTypes
            xhr.upload.addEventListener("progress", p => progressHandler({progress: 0.5 + (p.loaded / p.total / 2)}));

            // noinspection JSValidateTypes
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