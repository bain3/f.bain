# [f.bain](https://f.bain.cz/)
Sources for my end to end encrypted file sharing website. The server has no knowledge about the file uploaded,
except for its size.

## Deployment
Deploying this website isn't very complicated.
1. Clone this repo
2. Sdd folder "upload" here `mount/upload`
3. Use docker-compose to build and run the api
4. Change all of the links in the javascript (`static/script.js`, `mount/static/index.html`) to your
   website
5. Install nginx and set it up to reverse proxy anything that hasn't been found in `static`. You can find
   countless tutorials online on how to do this.
   
### How does it work?
#### Upload
Once the user selects a file, the javascript will generate a random custom base73 string as a password.
The custom base73 format makes it so the urls are as dense as possible without sacrificing security.
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
[iv1][data (encrypted using og iv)][tag]
[iv2][data (encrypted using iv1)  ][tag]
[iv3][data (encrypted using iv2)  ][tag]
...
```
Each block will end up being `5242928` bytes long.
All of this is periodically added to a blob to not make the browser crash. Unfortunately recreating
a blob is very time consuming, so the whole encryption process isn't very fast. If someone is willing to
help me improve the file handling, contact me on discord `bain#5038` (or on [keybase][kb]).

The last step is to encrypt the filename in AES-GCM with our last iv and encode it in base64.

The encrypted file, filename and the salt is sent to the server, which then responds with a id.
The browser constructs the final url locally.
```
https://f.bain.cz/<id>#<password>
```

Since the password is set as a fragment (after the `#`) it is not sent to the server when you request the file
back.

### Download
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
works and/or have found out that I badly implemented parts of this, please contact me on discord `bain#5038`,
or on [keybase][kb]. Thank you!
 

[pbkdf2]: https://en.wikipedia.org/wiki/PBKDF2
[aesgcm]: https://en.wikipedia.org/wiki/Galois/Counter_Mode
[kb]: https://keybase.io/bain3
