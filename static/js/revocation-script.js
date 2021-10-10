
function getID(url) {
    let id = "";
    if (url.length === 5) {
        id = url;
    } else {
        try {
            let url_object = new URL(encodeURI(url));
            id = url_object.pathname.substring(url_object.pathname.lastIndexOf('/') + 1);
        } catch (e) {
        }
    }
    return id;
}

async function revokeFile() {
    let err = R("errors");
    let id = getID(R('input.url').value);
    if (id === "") {
        err.innerText = "Error: Could not find a valid ID in input.";
        err.hidden = false;
    }
    let rt = R('input.token').value;
    if (rt === "") {
        err.innerText = "Error: No revocation token was found.";
        err.hidden = false;
    }
    let resp = await fetch("/"+id, {method: "DELETE", body: JSON.stringify({revocation_token: rt})});
    switch (resp.status) {
        case 401:
            err.innerText = "Error: Unauthorized (bad revocation key & ID combination).";
            err.hidden = false;
            break;
        case 404:
            err.innerText = "Error: Invalid ID/File was not found on the server.";
            err.hidden = false;
            break;
        case 500:
            err.innerText = "Error: Internal server error.";
            err.hidden = false;
            break;
        case 200:
            R("btn").style.background = "#52B788";
            R("btn").innerText = "Revoked!";
            err.hidden = true;
            window.localStorage.removeItem("revocation-" + id);
            setTimeout(()=> {
                R("btn").style.background = "#DB324D";
                R("btn").innerText = "Revoke";
            }, 5000);
            break;
        default:
            err.innerText = "Error: Server returned unknown status code: "+resp.status;
            err.hidden = false;
    }
}

function findRt(url) {
    if (url.includes("%")) {
        url = decodeURI(url);
        R('input.url').value = url;
    }
    let id = getID(url);
    if (id === "") return;

    let rt = window.localStorage.getItem("revocation-" + id);
    if (rt === null) return;
    R('input.token').value = rt;
}

R.preload();