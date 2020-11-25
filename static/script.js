// all available characters in a url
let base73 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$–_.+!*‘(),";
let strength = 12;

function inputHandler(ev) {
    ev.preventDefault();
    let el = document.getElementById('inp');
    // console.log(el.files[0]);
    sendRequest(el.files[0]);
}

function dropHandler(ev) {
    // console.log(ev);

    // Prevent default behavior (Prevent file from being opened)
    ev.preventDefault();

    let toSend;
    if (ev.dataTransfer.items) {
        let file = ev.dataTransfer.items[0].getAsFile();
        // console.log(file);
        toSend = file;
    } else {
        // console.log(ev.dataTransfer.files[0]);
        toSend = ev.dataTransfer.files[0];
    }
    // console.log(toSend);

    sendRequest(toSend);
}

function random_chars(number) {
    let array = sjcl.random.randomWords(number, 0);
    // console.log(array);
    let output = "";
    for (let i = 0; i < array.length; i++) {
        output += base73[Math.abs(array[i]%73)];
    }
    return output
}

async function encrypt(file) {

    // generate random password in base73
    let password;
    do {
        password = random_chars(strength);
    } while ([".", ",", ")"].includes(password[password.length-1])); // last character cannot be ) , or ., discord doesn't like it

    // password stretching to 512 bits and strengthening
    let salt = sjcl.random.randomWords(2,0);
    let strengthened = sjcl.misc.pbkdf2(password, salt, 50000, 768);

    // create aes instance using our generated key (first 256 bits)
    let prp = new sjcl.cipher.aes(strengthened.splice(0, 8));

    let iv = strengthened.splice(0,8); // setting iv (second 256 bits)

    let output_blob = new Blob([]); // preparing output blob, needs to be blob to not crash the browser
    let offset = 0;
    while (offset < file.size) {
        // getting a block of data (5mb)
        let block_data = new Int8Array(await file.slice(offset, offset+5242880).arrayBuffer());
        // getting iv IN THE RIGHT FORM, UGHHH
        let new_iv = sjcl.random.randomWords(8,0);
        let new_iv_int8 = new Int8Array(new Int32Array(new_iv).buffer);

        // concatenating iv and data into the same block
        let block = new Int8Array(new_iv_int8.byteLength+block_data.byteLength);
        block.set(new_iv_int8, 0);
        block.set(block_data, new_iv_int8.byteLength);

        // encryption of the block using aes in gcm mode
        let cipher = sjcl.mode.gcm.encrypt(prp, sjcl.codec.arrayBuffer.toBits(block.buffer), iv);

        // this takes a shit ton of time, sadly can't do anything about that
        // (please help if you know how to work around this issue)
        output_blob = new Blob([output_blob, sjcl.codec.arrayBuffer.fromBits(cipher, false)]);

        offset += 5242880;
        iv = new_iv; // changing the iv for the next block to not weaken the encryption
        document.getElementsByClassName('progress-value')[0].style.width = offset/file.size*50+'%';
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
    let uuid_el = document.getElementById('uuid');
    let key_el = document.getElementById('key');
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
    xhr.addEventListener("readystatechange", function () {
        if (this.readyState === this.DONE) {
            if (this.status === 200) {
                let json = JSON.parse(this.responseText);
                uuid_el.innerText = json.uuid;
                key_el.innerText = encrypted.key;
                upload_icon.hidden = true;
                success_el.hidden = false;
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
        document.getElementsByClassName('progress-value')[0].style.width = 50+(p.loaded/p.total*86)+'%';
    })

    xhr.open("POST", "http://localhost:3333/");
    xhr.setRequestHeader("Content-Type", "application/octet-stream");

    // setting metadata header to send salt and file name encoded in json, then in base64
    xhr.setRequestHeader("X-Metadata", window.btoa(JSON.stringify({filename: encrypted.filename, salt: encrypted.salt})));
    xhr.send(encrypted.output_blob);
}

function copyToClipboard() {
  let copyText = document.getElementById("success");
  navigator.clipboard.writeText(copyText.innerText);
  document.getElementById("copied-box").hidden = false;
  setTimeout(() => {document.getElementById("copied-box").hidden = true}, 3000)
}