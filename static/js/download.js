let downloaded = false;
let revocationToken = '';
let fileObject = null;
let expire_index = 0;

function secondsToDays(seconds) {
    return Math.ceil(seconds / 60 / 60 / 24);
}

function getSizeHumanReadable(size) {
    let magnitudes = ["", "K", "M", "G", "T"];
    let current_mag = 0;
    while (size >= 1000 && current_mag < 4) {
        size /= 1000
        current_mag++;
    }
    return `${Math.round(size * 10) / 10} ${magnitudes[current_mag]}B`;
}

function getRevocationToken(url, id) {
    const urlRevToken = url.searchParams.get('rt');
    if (urlRevToken !== null) {
        window.history.replaceState(null, 'Download', `${url.pathname}${url.hash}`);
        window.localStorage.setItem(`revocation-${id}`, urlRevToken);
    }
    return urlRevToken || window.localStorage.getItem(`revocation-${id}`) || '';
}

async function on_load() {


    R('button').style.display = 'flex';
    let progress = new Progress({
        status: "neutral",
        statusText: "Fetching file metadata"
    },
        R('prgrs.value'),
        R('prgrs.status'),
        (p) => `calc(${12 * p}rem + ${20 * p}px)`
    );

    // -- parse url --
    const url = new URL(location.href);
    const id_pair = [
        decodeURI(url.pathname.substring(url.pathname.lastIndexOf('/') + 1)),
        decodeURI(url.hash.substring(1))
    ];

    revocationToken = getRevocationToken(url, id_pair[0]);
    if (revocationToken === '') {
        R('settings.exportToken').innerText = 'Import token';
        R('settings.exportToken').onclick = importToken;
        R('settings.deleteFile').disabled = true;
        R('settings.revocationToken').hidden = false;
    }

    if (id_pair.length === 1 || id_pair[1] === "") {
        progress.update({
            status: "error",
            statusText: "Invalid link"
        });
        return;
    }

    let file;
    try {
        file = await ForeignFile.fromIDPair("", id_pair[0], id_pair[1]);
    } catch (e) {
        progress.update({
            status: "error",
            statusText: e
        });
        return;
    }
    fileObject = file;
    R('settings.button').hidden = false;

    R('file.name').innerText = file.filename;
    R('file.size').innerText = getSizeHumanReadable(file.size);

    const filenameLower = file.filename.toLowerCase();
    // if the file is smaller than 10mb
    if (file.size <= 10000000 && (filenameLower.endsWith(".jpg") || filenameLower.endsWith(".png"))) {
        downloaded = true;
        const blob = await file.getData(p => progress.update(p));
        progress.update({
            status: "success",
            statusText: "Save"
        });
        const downloaded_url = URL.createObjectURL(blob);
        R('preview.image').src = downloaded_url;
        R('preview.image').hidden = false;
        let saved = false;
        R('button').addEventListener('click', () => {
            if (!saved) {
                saved = true;
                downloadBlobURL(downloaded_url, file.filename);
                progress.update({
                    status: "success",
                    statusText: "File saved"
                });
            }
        })
    } else {
        progress.update({
            statusText: "Download"
        });
        // -- set event handler on button --
        R('button').addEventListener('click', async () => {
            if (!downloaded) {
                downloaded = true;
                const blob = await file.getData(p => progress.update(p));
                downloadBlobURL(URL.createObjectURL(blob), file.filename);
                progress.update({
                    status: "success",
                    statusText: "File downloaded"
                });
            }
        });
    }
}

function downloadBlobURL(blobUrl, filename) {
    const link = document.createElement('a');
    link.href = blobUrl;
    link.download = filename;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(blobUrl), 7000);
}

function toggleSettings() {
    R('settings.container').hidden = !R('settings.container').hidden;
    if (R('settings.container').hidden === false && revocationToken.length > 0) {
        loadExpire()
    }
}

function importToken() {
    let token = R('settings.revocationToken.input').value;
    if (token === '') return;
    window.localStorage.setItem(`revocation-${fileObject.id}`, token);
    revocationToken = token;
    R('settings.exportToken').innerText = 'Export token';
    R('settings.exportToken').onclick = exportToken;
    R('settings.deleteFile').disabled = false;
    R('settings.revocationToken').hidden = true;
    R('settings.text').innerText = "";
    loadExpire();
}

function exportToken() {
    R('settings.revocationToken').hidden = false;
    R('settings.revocationToken.input').value = window.localStorage.getItem(`revocation-${fileObject.id}`) || '';
    R('settings.text').innerText =
        "Removed revocation token from internal storage. You won't be able to delete this file without it.";
    R('settings.exportToken').innerText = "Import token";
    R('settings.exportToken').onclick = importToken;
}

function deleteFile() {
    R('settings.deleteFile').innerText = "Are you sure?";
    R('settings.deleteFile').onclick = async () => {
        console.log(revocationToken);
        if (await fileObject.delete(revocationToken)) {
            window.localStorage.removeItem(`revocation-${fileObject.id}`);
            window.location = "/";
        } else {
            R('settings.deleteFile').innerText = "Delete file";
            R('settings.deleteFile').onclick = deleteFile;
            R('settings.text').innerText = "File deletion failed";
        }
    };
}

async function setExpire() {
    let now = Math.round(new Date().getTime() / 1000);
    let expirations = [now + 7 * 24 * 60 * 60, now + 30 * 24 * 60 * 60, -1];
    let expire_in = expirations[(expire_index++) % 3];
    if (await fileObject.set_expires_at(revocationToken, expire_in)) {
        if (expire_in > 0) R('settings.expiration').innerText = `Expires in: ${secondsToDays(expire_in - now)} days`;
        else R('settings.expiration').innerText = "Expires in: never";
    }
}

async function loadExpire() {
    let now = Math.round(new Date().getTime() / 1000);
    let expiration = await fileObject.expires_at(revocationToken);
    if (expiration === -2) {
        R('settings.text').innerText = "Failed to fetch expiration data";
    } else if (expiration === -1) {
        R('settings.expiration').innerText = "Expires in: never";
    } else {
        R('settings.expiration').innerText = `Expires in: ${secondsToDays(expiration - now)} days`;
    }
}

R.preload().then(on_load);

