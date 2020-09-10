# f.bain
Sources for my simple website for file uploading. I didn't like how many sites are
complicated so i created my own. At least i don't have to worry about someone spying
on me.

## Deployment
You can start the back end with the docker compose file located in the root directory.
I recommend using a web server like nginx to proxy all the connections from outside and
handle all the static files. (index.html, script.js)