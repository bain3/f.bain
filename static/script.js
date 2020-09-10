function inputHandler(ev) {
    ev.preventDefault();
    let formData = new FormData();
    let el = document.getElementById('inp');
    formData.append('file', el.files[0]);
    sendRequest(formData);
}

function dropHandler(ev) {
    console.log(ev);

    // Prevent default behavior (Prevent file from being opened)
    ev.preventDefault();
    let formData = new FormData();

    if (ev.dataTransfer.items) {
        // Use DataTransferItemList interface to access the file(s)
        let file = ev.dataTransfer.items[0].getAsFile();
        console.log(file);
        formData.append('file', file);
    } else {
        // Use DataTransfer interface to access the file(s)
        console.log(ev.dataTransfer.files[0]);
        formData.append('file', ev.dataTransfer.files[0]);
    }
    console.log(formData);
    sendRequest(formData);
}

function sendRequest(formData) {
    let error_el = document.getElementById('errors');
    let success_el = document.getElementById('success');
    let uuid_el = document.getElementById('uuid');
    let upload_icon = document.getElementById('upload-icon');
    let input_el = document.getElementById('inp');
    let progress_el = document.getElementsByClassName('progress')[0]
    console.log(formData);

    var xhr = new XMLHttpRequest();

    xhr.addEventListener("readystatechange", function () {
        if (this.readyState === this.DONE) {
            if (this.status === 200) {
                let json = JSON.parse(this.responseText);
                uuid_el.innerText = json.uuid;
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

    xhr.upload.addEventListener("progress", function (p) {
        document.getElementsByClassName('progress-value')[0].style.width = p.loaded/p.total*100+'%'
    })

    xhr.open("POST", "http://localhost:3333/");

    xhr.send(formData);
    progress_el.style.visibility = 'initial';
    input_el.disabled = true;
    input_el.style.zIndex = '-1';
}

function copyToClipboard() {
  let copyText = document.getElementById("success");
  navigator.clipboard.writeText(copyText.innerText);
  document.getElementById("copied-box").hidden = false;
  setTimeout(() => {document.getElementById("copied-box").hidden = true}, 3000)
}