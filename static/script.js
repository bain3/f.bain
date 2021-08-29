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

    const localFile = new LocalFile(file);
    let resp;
    try {
        resp = await localFile.upload(strength, "", p => progress_bar.update(p));
    } catch (e) {
        progress_bar.update({status: "error", statusText: e})
        return;
    }
    document.getElementById('success').innerHTML =
        `https://${window.location.host}/<span style="color: var(--bright)">${resp.uuid}#${resp.password}</span>`;
    document.getElementById('revocation-token').innerText = resp.revocationToken;
    response = resp;
    showRevocationDiv();
    progress_div.style.visibility = 'hidden';
    success_div.hidden = false;
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
    rt.innerText = response.revocationToken;
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
        window.localStorage.setItem("revocation-" + encodeURI(response.uuid), response.revocationToken);
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