curl -sL https://deb.nodesource.com/setup_16.x | sudo -E bash -
sudo apt-get install -y nodejs
git clone https://github.com/tornord/tryhackme.git
cd tryhackme
npm run server
