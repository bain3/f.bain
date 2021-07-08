// all available characters in a url
let base73 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$–_.+!*'(),";
let strength = 12;
let host = window.location.host;
let max_file_size = 0;
let response = "";

// from @mrkelvinli on github, pathing Blob.arrayBuffer for safari.
(function () {
    File.prototype.arrayBuffer = File.prototype.arrayBuffer || myArrayBuffer;
    Blob.prototype.arrayBuffer = Blob.prototype.arrayBuffer || myArrayBuffer;

    function myArrayBuffer() {
        // this: File or Blob
        return new Promise((resolve) => {
            let fr = new FileReader();
            fr.onload = () => {
                resolve(fr.result);
            };
            fr.readAsArrayBuffer(this);
        });
    }
})();

function inputHandler(ev) {
    ev.preventDefault();
    let el = document.getElementById('inp');
    sendRequest(el.files[0]);
}

function dropHandler(ev) {
    ev.preventDefault();
    let toSend;
    if (ev.dataTransfer.items) {
        toSend = ev.dataTransfer.items[0].getAsFile();
    } else {
        toSend = ev.dataTransfer.files[0];
    }
    sendRequest(toSend);
}

/**
 * Generates a random string constructed from a base73 alphabet
 * @param number {int} number of characters
 * @returns {string}
 */
function random_chars(number) {
    let array = new Uint8Array(number);
    let cryptoObj = window.crypto || window.msCrypto;
    cryptoObj.getRandomValues(array);
    let output = "";
    while (output.length < number) {
        for (let i = 0; i < array.length; i++) {
            // skip values that are larger than the biggest multiple of 73
            // otherwise we would have a higher probability of getting values between 0 and 36
            if (array[i] > 219) continue;
            output += base73[Math.abs(array[i] % 73)];
            if (output.length === number) break;
        }
    }
    return output;
}


async function encrypt(file, progress_bar) {

    progress_bar.update({
        status: "neutral",
        statusText: "encrypting...",
    });
    // generate random password in base73
    let password;
    do {
        password = random_chars(strength);
    } while ([".", ",", ")"].includes(password[password.length - 1])); // last character cannot be ")", "," or ".", discord doesn't like it

    // get crypto objects
    let cryptoObj = window.crypto || window.msCrypto; // for IE 11
    let crypto = cryptoObj.subtle;

    // password and salt generation
    let te = new TextEncoder();
    let salt = new Uint8Array(32);
    cryptoObj.getRandomValues(salt);
    let wc_pass = await crypto.importKey(
        "raw",
        te.encode(password),
        "PBKDF2",
        false,
        ["deriveBits"]
    );
    let strengthened = await crypto.deriveBits(
        {name: "PBKDF2", hash: "SHA-256", salt: salt, iterations: 50000},
        wc_pass,
        768
    );
    let key = await crypto.importKey(
        "raw",
        strengthened.slice(0, 32),
        "AES-GCM",
        false,
        ["encrypt"]
    );
    let iv = strengthened.slice(32, 64); // setting iv (second 256 bits)
    let name_iv = strengthened.slice(64, 96); // using third 256 bits of our stretched key

    let output_blob = new Blob([]); // preparing output blob, needs to be blob to not crash the browser
    let offset = 0;
    while (offset < file.size) {
        // getting a block of data (5mb)
        let block_data = new Uint8Array(await file.slice(offset, offset + 5242880).arrayBuffer());

        // generating new iv
        let new_iv = new Uint8Array(32);
        cryptoObj.getRandomValues(new_iv);

        // concatenating iv and data into the same block
        let block = new Uint8Array(new_iv.byteLength + block_data.byteLength);
        block.set(new_iv, 0);
        block.set(block_data, 32);

        // encryption of the block using aes in gcm mode
        let cipher = await crypto.encrypt(
            {name: "AES-GCM", iv: iv, tagLength: 128},
            key,
            block
        )
        output_blob = new Blob([output_blob, cipher]);

        offset += 5242880;
        iv = new_iv; // changing the iv for the next block to not weaken the encryption
        progress_bar.update({
            progress: offset / file.size * 0.5
        });
    }

    // encrypt filename
    let enc_bytes = await crypto.encrypt(
        {name: "AES-GCM", iv: name_iv, tagLength: 128},
        key,
        te.encode(file.name)
    );
    // convert filename to base64
    let filename = btoa(
        new Uint8Array(enc_bytes)
            .reduce((data, byte) => data + String.fromCharCode(byte), '')
    );
    return {output_blob, key: password, salt: Array.from(salt), filename};
}


async function sendRequest(file) {

    // make center clickable, disable file input, hide welcome screen, and show progress information
    document.getElementsByClassName('center')[0].classList.remove('click-through');
    document.getElementById('inp').disabled = true;
    document.getElementById('welcome-div').hidden = true;
    let progress_div = document.getElementById('progress-div');
    let success_div = document.getElementById('success-div');
    progress_div.style.visibility = 'initial';


    let progress_bar = new Progress(
        {status: "neutral", statusText: "", progress: 0},
        document.getElementsByClassName('progress-value')[0],
        document.getElementById('status')
    );

    if (file.size >= max_file_size) {
        progress_bar.update({
            status: "error",
            statusText: "The file is too large"
        });
        return;
    }

    // encrypt the file
    let encrypted;
    encrypted = await encrypt(file, progress_bar);

    // send post request with data and metadata
    const xhr = new XMLHttpRequest();

    // response handler
    xhr.addEventListener("readystatechange", function () {
        if (this.readyState === this.DONE) {
            if (this.status === 200) {
                let json = JSON.parse(this.responseText);
                progress_div.style.visibility = 'hidden';
                progress_div.hidden = true;
                document.getElementById('success').innerHTML =
                    `https://${host}/<span style="color: var(--bright)">${json.uuid}#${encrypted.key}</span>`;
                success_div.hidden = false;
                window.history.pushState("", "", "https://" + host + "/" + json.uuid + '#' + encrypted.key);
                response = json;
                showRevocationDiv();
            } else {
                let status_messages = {
                    413: "The file is too large.",
                    429: "The server is dealing with too much traffic, please try again later."
                }
                progress_bar.update({
                    status: "error",
                    statusText: status_messages[this.status] || ("Server returned error code: " + this.status)
                });
            }
        }
    });

    // update progress bar
    xhr.upload.addEventListener("progress", function (p) {
        progress_bar.update({
            progress: 0.5 + (p.loaded / p.total / 2)
        });
    })

    progress_bar.update({
        status: "neutral",
        statusText: "uploading..."
    });
    xhr.open("POST", "/new");
    xhr.setRequestHeader("Content-Type", "application/octet-stream");

    // setting metadata header to send salt and file name encoded in json, then in base64
    xhr.setRequestHeader("X-Metadata", window.btoa(JSON.stringify({
        filename: encrypted.filename,
        salt: encrypted.salt
    })));
    xhr.send(encrypted.output_blob);
}

function copyToClipboard(el) {
    navigator.clipboard.writeText(el.innerText);
    document.getElementById("copied-box").hidden = false;
    setTimeout(() => {
        document.getElementById("copied-box").hidden = true
    }, 3000)
}

function showRevocationDiv() {
    let rt = document.getElementById('revocation-token');
    rt.innerText = response.revocation_token;
    let s = window.localStorage.getItem("s");
    if (s === null) {
        window.localStorage.setItem("s", "yes");
        s = "yes"
    }
    if (s === "yes") {
        document.getElementById("store-rt").checked = true;
        storeRevocationToken(true);
    }
}

async function storeRevocationToken(v) {
    if (v) {
        window.localStorage.setItem("revocation-" + encodeURI(response.uuid), response.revocation_token);
        document.getElementById("rt-show").hidden = true;
    } else {
        window.localStorage.removeItem("revocation-" + encodeURI(response.uuid));
        document.getElementById("rt-show").hidden = false;
    }
    window.localStorage.setItem("s", v ? "yes" : "no");
}

async function getMaxFileSize() {
    let resp = await fetch("/max-filesize");
    if (resp.ok) {
        let json = await resp.json();
        let size = json.max;
        max_file_size = json.max;
        let magnitudes = ["", "K", "M", "G", "T"];
        let current_mag = 0;
        while (size >= 1000 && current_mag < 4) {
            size /= 1000
            current_mag++;
        }
        document.getElementById('max-filesize').innerText = Math.round(size * 10) / 10 + magnitudes[current_mag] + "B";
    }
}

window.onload = getMaxFileSize;