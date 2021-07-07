let timeout_running = false;
let downloaded = false;

function start_timeout() {
    if (downloaded) return;
    new Progress({}).update({
        status: "neutral",
        statusText: "waiting for 2 seconds...",
        progress: 0
    });
    if (!timeout_running) {
        timeout_running = true;
        setTimeout(() => {
            timeout_running = false;
            if (document.visibilityState === "visible") ol();
        }, 2000);
    }
}

async function getMeta(progress, id) {
    let xhr = new XMLHttpRequest();
    let meta = undefined;
    let promise = new Promise(resolve => { // fuck callbacks
        xhr.addEventListener("readystatechange", function () {
            if (this.readyState === this.DONE) {
                if (this.status === 200) {
                    meta = JSON.parse(this.responseText);
                } else {
                    progress.update({
                        status: "error",
                        statusText: "failed to download file information (status code:" + this.status + ")"
                    });
                }
                resolve(true);
            }
        });
        xhr.open("GET", "/" + id + "/meta");
        xhr.send();
    });
    await promise;
    return meta;
}

async function getKeyFromCrypto(crypto, url_key, salt) {
    let te = new TextEncoder();
    let password;
    try {
        password = decodeURI(url_key);
    } catch (e) {
        console.log(e);
        return {error: "could not parse key from url."}
    }

    let wc_password = await crypto.importKey(
        "raw",
        te.encode(password),
        "PBKDF2",
        false,
        ["deriveBits"]
    );
    let strengthened = await crypto.deriveBits(
        {name: "PBKDF2", hash: "SHA-256", salt: new Uint8Array(salt), iterations: 50000},
        wc_password,
        768
    );
    let wc_key = await crypto.importKey(
        "raw",
        strengthened.slice(0, 32),
        "AES-GCM",
        false,
        ["decrypt"]
    );
    return {key: wc_key, strengthened: strengthened}
}

async function getRawData(progress, id) {
    let raw = undefined;
    let xhr = new XMLHttpRequest();
    let promise = new Promise(resolve => { // fuck callbacks
        xhr.addEventListener("readystatechange", function () {
            if (this.readyState === this.DONE) {
                if (this.status === 200) {
                    raw = this.response;
                } else {
                    progress.update({
                        status: "error",
                        statusText: "failed to download encrypted file. (status code:" + this.status + ")"
                    });
                }
                resolve(true);
            }
        });
        xhr.addEventListener("progress", function (p) {
            progress.update({progress: 0.05 + p.loaded / p.total * 0.45});
        })
        xhr.open("GET", "/" + id + "/raw");
        xhr.responseType = "blob";
        xhr.send();
    });
    await promise;
    return raw;
}

async function ol() {
    downloaded = true;
    let progress = new Progress({
        status: "neutral",
        statusText: "fetching file information and verifying decryption key",
        progress: 0.01
    });

    let url = new URL(location.href);
    let id_pair = [url.pathname.substring(url.pathname.lastIndexOf('/') + 1), url.hash.substring(1)];

    if (id_pair.length === 1 || id_pair[1] === "") {
        progress.update({
            status: "error",
            statusText: "link is incorrect, missing key"
        });
        return;
    }

    // -- request meta --
    let meta = await getMeta(progress, id_pair[0]);
    if (meta === undefined) return;
    progress.update({progress: 0.05});

    // -- derive keys --
    let cryptoObj = window.crypto || window.msCrypto; // for IE 11
    let crypto;
    if (cryptoObj !== undefined) crypto = cryptoObj.subtle;
    if (crypto === undefined) {
        progress.update({
            status: "error",
            statusText: "could not get cryptography API from your browser, try using a different one"
        });
        return;
    }
    let keys = await getKeyFromCrypto(crypto, id_pair[1], meta.salt);
    if (keys.error !== undefined) {
        progress.update({
            status: "error",
            statusText: keys.error
        });
        return;
    }
    let iv = keys.strengthened.slice(32, 64); // setting iv (second 256 bits)

    // -- decrypt filename --
    progress.update({statusText: "decrypting filename"})
    let filename;
    try {
        let b64 = atob(meta.filename);
        let len = b64.length;
        let bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = b64.charCodeAt(i);
        }
        filename = new TextDecoder().decode(await crypto.decrypt(
            {name: "AES-GCM", iv: keys.strengthened.slice(64, 96), tagLength: 128},
            keys.key, bytes
        ));
    } catch (e) {
        progress.update({
            status: "error",
            statusText: "failed to decrypt filename, usually caused by an invalid decryption key"
        });
        console.log(e);
        return;
    }

    // -- getting raw encrypted data --
    progress.update({statusText: "fetching raw encrypted data"});
    let raw = await getRawData(progress, id_pair[0]);
    if (raw === undefined) return;
    progress.update({progress: 0.5});

    // -- decrypt file contents --
    progress.update({statusText: "decrypting file contents"});
    let output_blob = new Blob([]); // working with blobs to not crash the browser with big files
    try {
        let offset = 0;
        while (offset < raw.size) {
            // getting data
            let block = await raw.slice(offset, offset + 5242928).arrayBuffer();

            // decrypting
            let d_block = await crypto.decrypt(
                {"name": "AES-GCM", "iv": iv, "tagLength": 128},
                keys.key, block);

            output_blob = new Blob([output_blob, d_block.slice(32, d_block.byteLength)]);

            // setting next iv
            iv = new Uint8Array(d_block.slice(0, 32));

            offset += 5242928;
            progress.update({progress: 0.5 + offset / raw.size});
        }
    } catch (e) {
        console.log(e);
        progress.update({
            status: "error",
            statusText: "error while decrypting file"
        });
    }
    if (output_blob.size === 0) return;

    progress.update({progress: 1})

    // -- create download for the plaintext --
    const link = document.createElement('a');
    link.href = URL.createObjectURL(output_blob);
    link.download = filename;
    document.body.append(link);
    link.click();
    link.remove();
    progress.update({
        status: "success",
        statusText: "successfully downloaded \"" + filename + "\""
    });
    setTimeout(() => URL.revokeObjectURL(link.href), 7000);
}

