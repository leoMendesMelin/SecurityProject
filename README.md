Lancer le serveur et le client : 


1. LD_LIBRARY_PATH=/usr/local/lib
2. export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./
3. make
4. ./server | ./client

openssl aes-256-cbc -a -salt -in credentials.txt -out credentials.txt.enc pour encrypter le fichier

mdp : totoMdp