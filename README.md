# [f.bain](https://f.bain.cz/)
Sources for my end to end encrypted file sharing website. The server has no knowledge about the file uploaded,
except for its size.

Using f.bain as a website was always the intended way, but to increase the security even further a native
command line utility was created ([fget](https://github.com/bain3/fget)). By using a native application you
remove the risk of being served malicious javascript from a potentially compromised server.

## Deployment
Deploying this website isn't very complicated.
1. Clone this repo
2. Take a look at `docker-compose.yml` and change the environment variables if you want to
3. Use docker-compose to build and run the api
4. Install a reverse proxy (for example nginx or Caddy) and set it up like so:
   - try responding with a file from `/static` (e.g. index.html)
   - if the file can't be found, reverse proxy the request to the API.
   - if the API returns an error, return the static file corresponding to the error.
     Although you can find countless tutorials online on how to do this, 
     here are some examples:

<details><summary>Nginx configuration example</summary>

```nginx
server {
    root /path/to/static;
    error_log off;
    access_log off;
    index index.html;

    client_max_body_size 0;

    server_name example.com;

    error_page 404 /404.html;
    error_page 429 /429.html;

    location / {
        try_files $uri $uri/ @proxy_pass;
    }

    location @proxy_pass {
        proxy_intercept_errors on;
        proxy_pass http://localhost:3333;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
    }

    listen [::]:443 ssl http2;
    listen 443 ssl http2;
    # SSL configuration
}

server {
    if ($host = example.com) {
        return 301 https://$host$request_uri;
    }

    server_name example.com;
    listen [::]:80;
    listen 80;
    return 404;
}
```
</details>

<details><summary>Caddy configuration example</summary>

[//]: # (While Caddyfiles are not Python, it is the closest highlighting we can get.)

```python
# Replace f.example.com with your (sub) domain.
f.example.com {
    # copy or mount the static directory of the repo to /srv/f-bain
    root * /srv/f-bain
    encode gzip
    file_server

    @reverse_proxy {
        not file {
            try_files {path} {path}/index.html
        }
    }
	
    # Forward requests that are not for static files to the API
    # (change hostname & port if needed)
    reverse_proxy @reverse_proxy f-bain-api:80 {
        @error status 404 429
        handle_response @error {
            rewrite * /{rp.status_code}.html
            file_server
        }
    }

}
```
</details>

5. Set up HTTPS for basic security
   
## How does it work?
### Short description
Your browser encrypts the file locally before sending it to the server. The key is carefully placed inside the url,
so it isn't sent when you request the file back. This way the server has no knowledge about the contents of the file
and only you have the key to decrypt the data.

### Long description
#### Upload
Once the user selects a file, the javascript will generate a random string as a password from a key alphabet.
The special key alphabet maximises density of data in the url without sacrificing security.
It will also generate "salt" for the PBKDF2 key derivation function. This salt will be later sent to
the server as metadata. It is essentially to protect other files on the server. This way an attacker
can't steal all the files stored on the server and break all the passwords in bulk.

The next step (still in the browser) is to strengthen and stretch the password using the mentioned [PBKDF2][pbkdf2]
key derivation function. The result of this function will be a 768 bit key.

We split this 768 bit key into three 256 bit parts which we will be using as our key, iv and filename iv.

Next up is encrypting the file using [AES in GCM mode][aesgcm]. Since we want to support bigger files, we
split it into blocks of 5 megabytes, and generate new ivs for every new block, which we add to the start 
of the previous block.
```
[iv1 + data (encrypted using og iv)][tag]
[iv2 + data (encrypted using iv1)  ][tag]
[iv3 + data (encrypted using iv2)  ][tag]
...
```
Each block will end up being `5242928` bytes long.
All of this is periodically added to a blob to not make the browser crash, and is the longest part.

The last step is to encrypt the filename in AES-GCM with our last iv and encode it in base64.

The encrypted file, filename and the salt is sent to the server, which then responds with an id.
The browser constructs the final url locally.
```
https://f.bain.cz/<id>#<password>
```

Since the password is set as a fragment (after the `#`) it is not sent to the server when you request the file
back.

#### Download
*(I recommend reading the upload part to fully understand the download)*

Download is simpler than upload. First off the browser parses the url for the id and password.

Using the id it gathers metadata about the file (the encrypted file name and the salt) from `/<id>/meta`. 
It then derives the 768 bit key from the password.

After that the browser downloads the encrypted data (from `/<id>/raw`)(everything stored as a 
blob to prevent browser crashing), and starts to decrypt the `5242928` byte long blocks. 
Each time splitting the block into the next iv and decrypted data, setting the next iv, and 
storing the decrypted data into an output blob.

Then it quickly decrypts the file name, and creates a fake link element with it pointing to the output
blob, containing the decrypted data. At last it invokes a click on the element which makes the browser save 
the file.

GGs if you actually read all of it!

## Help appreciated! (and a disclaimer)
I am just an amateur who wanted to make myself a pretty secure website where to drop off my files (and
to practice some cryptography). I am in no way certified in this field, so if you know how all of this
works and/or have found out that I badly implemented parts of this, please contact me on [keybase][kb],
or by any other means (contact info at bain.cz). Thank you!


# Changing max file size
```
POST /max-filesize/{new_max} (ex. 5K, 500M, 2G)
Authorization: TOKEN

(empty body)
```
 

[pbkdf2]: https://en.wikipedia.org/wiki/PBKDF2
[aesgcm]: https://en.wikipedia.org/wiki/Galois/Counter_Mode
[kb]: https://keybase.io/bain3
