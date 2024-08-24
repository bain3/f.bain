// all available characters in a url
let strength = 14;
let max_file_size = 0;

// from @mrkelvinli on github, pathing Blob.arrayBuffer for safari.
(function() {
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
    sendRequest(ev.target.files);
}

function dropHandler(ev) {
    ev.preventDefault();
    sendRequest(ev.dataTransfer.files);
}

async function sendRequest(files) {
    // make center clickable, disable file input, hide welcome screen, and show progress information
    R('container').classList.remove('click-through');
    R('screen.0').hidden = true;
    R('screen.1').style.visibility = 'initial';
    R('fileInput').disabled = true;

    let progress_bar = new Progress(
        { status: "neutral", statusText: "", progress: 0 },
        R('prgrs.value'),
        R('prgrs.status')
    );

    if (files.length === 0) {
        // I'm not sure if this is possible, but just in case
        progress_bar.update({
            status: "error",
            statusText: "No file selected"
        });
        setTimeout(() => {
            R('container').classList.add('click-through');
            R('screen.0').hidden = false;
            R('screen.1').style.visibility = 'hidden';
            R('fileInput').disabled = false;
        }, 1500);
        return;
    }

    let file;
    
    if (files.length === 1) {
        file = files[0];
    } else {
        let filesArray = Array.from(files);
        progress_bar.update({ statusText: "zipping files" });
        // Get the total size of all files
        let totalSize = filesArray.map(f => f.size).reduce((a, b) => a + b);
        // Zip files
        let zip = new JSZip();
        let zipped_size = 0;
        filesArray.forEach(f => {
            console.log(f);
            zip.file(f.name, f);
            zipped_size += f.size;
            progress_bar.update({ progress: zipped_size / totalSize });
        });
        file = await zip.generateAsync({ type: "blob" });
        // Generate a name for the zip file
        uuid = make_id();
        file.name = `files-${uuid}.zip`;
    }

    if (file.size >= max_file_size) {
        progress_bar.update({
            status: "error",
            statusText: "The file is too large"
        });
        return;
    }

    // upload file
    progress_bar.update({ statusText: "generating key" });
    const localFile = new LocalFile(file);
    let resp;
    try {
        resp = await localFile.upload(strength, p => progress_bar.update(p));
    } catch (e) {
        progress_bar.update({ status: "error", statusText: e });
        console.log(e);
        return;
    }
    progress_bar.update({ status: "success", statusText: "redirecting to uploaded file..." });

    // redirect user to the file. pass revocation token in url parameter
    // (safe because its generated server side anyways)
    setTimeout(() => {
        window.location = `https://${window.location.host}/${resp.uuid}?rt=${resp.revocationToken}#${resp.password}`;
    }, 1500);
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
            size /= 1000;
            current_mag++;
        }
        R('filesize').innerText = Math.round(size * 10) / 10 + magnitudes[current_mag] + "B";
    }
}

function make_id() {
    // Generate a base64 6-character string
    // This function is not cryptographically secure, but it doesn't need to be
    // because it's just for generating a file name
    return btoa(Math.random().toString()).slice(0, 6);
}

R.preload().then(getMaxFileSize);
