let downloaded = false;

function getSizeHumanReadable(size) {
    let magnitudes = ["", "K", "M", "G", "T"];
    let current_mag = 0;
    while (size >= 1000 && current_mag < 4) {
        size /= 1000
        current_mag++;
    }
    return `${Math.round(size * 10) / 10} ${magnitudes[current_mag]}B`;
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
    R('file.name').innerText = file.filename;
    const cipher_size = await file.getSize();
    R('file.size').innerText = getSizeHumanReadable(cipher_size);

    // if the file is smaller than 10mb
    const filenameLower = file.filename.toLowerCase();
    if (cipher_size <= 10000000 && (filenameLower.endsWith(".jpg") || filenameLower.endsWith(".png"))) {
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

R.preload().then(on_load);

