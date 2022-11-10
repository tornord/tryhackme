# Read Me

Author: Ben Spring

Instructions to set up on server:

1. Install node and npm
2. Run `npm install -g pm2`
3. Run `npm install`
4. Run `pm2 start server.js -i max`
5. For running on startup, execute crontab -e, then add `cd <location of web server folder> && pm2 start server.js -i max`
6. Restart the server to ensure it works on startup

When you make the text files to store number of packets, and if the user has won, it will need to have the right permissions for the web server to read it.
