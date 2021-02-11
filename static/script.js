// all available characters in a url
let base73 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$–_.+!*'(),";
let strength = 12;
let host = "https://f.bain.cz/";
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
        })
    }
})();

function inputHandler(ev) {
    ev.preventDefault();
    let el = document.getElementById('inp');
    sendRequest(el.files[0]);
}

function dropHandler(ev) {

    // Prevent default behavior (Prevent file from being opened)
    ev.preventDefault();

    let toSend;
    if (ev.dataTransfer.items) {
        let file = ev.dataTransfer.items[0].getAsFile();
        toSend = file;
    } else {
        toSend = ev.dataTransfer.files[0];
    }

    sendRequest(toSend);
}

function random_chars(number) {
    let array = sjcl.random.randomWords(number, 0);
    let output = "";
    for (let i = 0; i < array.length; i++) {
        output += base73[Math.abs(array[i] % 73)];
    }
    return output
}

async function encrypt(file) {

    // generate random password in base73
    let password;
    do {
        password = random_chars(strength);
    } while ([".", ",", ")"].includes(password[password.length - 1])); // last character cannot be ) , or ., discord doesn't like it

    // password stretching to 512 bits and strengthening
    let salt = sjcl.random.randomWords(2, 0);
    let strengthened = sjcl.misc.pbkdf2(password, salt, 50000, 768);

    // create aes instance using our generated key (first 256 bits)
    let prp = new sjcl.cipher.aes(strengthened.splice(0, 8));

    let iv = strengthened.splice(0, 8); // setting iv (second 256 bits)

    let output_blob = new Blob([]); // preparing output blob, needs to be blob to not crash the browser
    let offset = 0;
    while (offset < file.size) {
        // getting a block of data (5mb)
        let block_data = new Int8Array(await file.slice(offset, offset + 5242880).arrayBuffer());
        // getting iv IN THE RIGHT FORM, UGHHH
        let new_iv = sjcl.random.randomWords(8, 0);
        let new_iv_int8 = new Int8Array(new Int32Array(new_iv).buffer);

        // concatenating iv and data into the same block
        let block = new Int8Array(new_iv_int8.byteLength + block_data.byteLength);
        block.set(new_iv_int8, 0);
        block.set(block_data, new_iv_int8.byteLength);

        // encryption of the block using aes in gcm mode
        let cipher = sjcl.mode.gcm.encrypt(prp, sjcl.codec.arrayBuffer.toBits(block.buffer), iv);

        output_blob = new Blob([output_blob, sjcl.codec.arrayBuffer.fromBits(cipher, false)]);

        offset += 5242880;
        iv = new_iv; // changing the iv for the next block to not weaken the encryption
        document.getElementsByClassName('progress-value')[0].style.width = offset / file.size * 50 + '%';
    }

    // encrypt filename
    let name_iv = strengthened.splice(0, 8); // using third 256 bits of our stretched key
    let enc_bits = sjcl.mode.gcm.encrypt(prp, sjcl.codec.utf8String.toBits(file.name), name_iv);
    let filename = sjcl.codec.base64.fromBits(enc_bits, false);

    return {output_blob, key: password, salt, filename}
}

async function sendRequest(file) {

    let error_el = document.getElementById('errors');
    let success_el = document.getElementById('success');
    let upload_icon = document.getElementById('upload-icon');
    let input_el = document.getElementById('inp');
    let progress_el = document.getElementsByClassName('progress')[0];
    input_el.disabled = true;
    input_el.style.zIndex = '-1';
    progress_el.style.visibility = 'initial';

    // encrypt the file
    let encrypted;
    encrypted = await encrypt(file);

    // send post request with data and metadata
    const xhr = new XMLHttpRequest();

    // response handler
    xhr.addEventListener("readystatechange", function () {
        if (this.readyState === this.DONE) {
            if (this.status === 200) {
                let json = JSON.parse(this.responseText);
                success_el.innerHTML = `${host}<span style="color: #fefefe">${json.uuid}#${encrypted.key}</span>`;
                upload_icon.hidden = true;
                success_el.hidden = false;
                window.history.pushState("", "", host + json.uuid + '#' + encrypted.key);
                response = json;
                showRevocationDiv();
            } else {
                error_el.innerText = "Failed to upload. (status:" + this.status + ")";
                upload_icon.hidden = true;
                error_el.hidden = false;
            }
            progress_el.style.visibility = 'hidden';
        }
    });

    // update progress bar
    xhr.upload.addEventListener("progress", function (p) {
        document.getElementsByClassName('progress-value')[0].style.width = 50 + (p.loaded / p.total * 86) + '%';
    })

    xhr.open("POST", "/n");
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
    let div = document.getElementById('revocation-div');
    let rt = document.getElementById('revocation-token');
    div.hidden = false;
    rt.innerText = response.revocation_token;
    let s = window.localStorage.getItem("s");
    if (s === null) {window.localStorage.setItem("s", "yes"); s="yes"}
    if (s === "yes") {
        document.getElementById("store-rt").checked = true;
        storeRevocationToken(true);
    }
}

async function storeRevocationToken(v) {
    console.log(v);
    if (v) {
        window.localStorage.setItem("revocation-"+encodeURI(response.uuid), response.revocation_token);
        document.getElementById("rt-show").hidden = true;
    }
    else {
        window.localStorage.removeItem("revocation-"+encodeURI(response.uuid));
        document.getElementById("rt-show").hidden = false;
    }
    window.localStorage.setItem("s", v ? "yes" : "no");
}
