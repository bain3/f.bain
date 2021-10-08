let downloaded = false;

async function getSizeHumanReadable(size) {
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
    }
    R('file.name').innerText = file.filename;
    R('file.size').innerText = await getSizeHumanReadable(await file.getSize());

    progress.update({
        statusText: "Download"
    });
    // -- set event handler on button --
    R('button').addEventListener('click', async () => {
        if (!downloaded) {
            downloaded = true;
            const blob = await file.getData(p => progress.update(p));
            // -- create download for the plaintext --
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = file.filename;
            document.body.append(link);
            link.click();
            link.remove();
            progress.update({
                status: "success",
                statusText: "File downloaded"
            });
            setTimeout(() => URL.revokeObjectURL(link.href), 7000);
        }
    });
}

R.preload().then(on_load);

