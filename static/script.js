// all available characters in a url
let strength = 12;
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
    sendRequest(ev.target.files[0]);
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

async function sendRequest(file) {

    // make center clickable, disable file input, hide welcome screen, and show progress information
    R('container').classList.remove('click-through');
    R('screen.0').hidden = true;
    R('screen.1').style.visibility = 'initial';
    R('fileInput').disabled = true;

    let progress_bar = new Progress(
        {status: "neutral", statusText: "", progress: 0},
        R('prgrs.value'),
        R('prgrs.status')
    );

    if (file.size >= max_file_size) {
        progress_bar.update({
            status: "error",
            statusText: "The file is too large"
        });
        return;
    }

    // upload file
    const localFile = new LocalFile(file);
    let resp;
    try {
        resp = await localFile.upload(strength, "", p => progress_bar.update(p));
    } catch (e) {
        progress_bar.update({status: "error", statusText: e})
        return;
    }

    R('out.url').innerHTML =
        `https://${window.location.host}/<span style="color: var(--white)">${resp.uuid}#${resp.password}</span>`;
    response = resp;
    showRevocationDiv();
    R('screen.1').style.visibility = 'hidden';
    R('screen.2').hidden = false;
}

function copyToClipboard(el) {
    navigator.clipboard.writeText(el.innerText);
    document.getElementById("copied-box").hidden = false;
    setTimeout(() => {
        document.getElementById("copied-box").hidden = true
    }, 3000)
}

function showRevocationDiv() {
    R('out.rt.value').innerText = response.revocationToken;
    let s = window.localStorage.getItem("s");
    if (s === null) {
        window.localStorage.setItem("s", "yes");
        s = "yes";
    }
    if (s === "yes") {
        R('out.rt.store').checked = true;
        storeRevocationToken(true);
    }
}

async function storeRevocationToken(v) {
    if (v) {
        window.localStorage.setItem("revocation-" + encodeURI(response.uuid), response.revocationToken);
        R('out.rt.show').hidden = true;
    } else {
        window.localStorage.removeItem("revocation-" + encodeURI(response.uuid));
        R('out.rt.show').hidden = false;
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
        R('filesize').innerText = Math.round(size * 10) / 10 + magnitudes[current_mag] + "B";
    }
}

R.preload().then(getMaxFileSize);