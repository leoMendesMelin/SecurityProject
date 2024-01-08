# PROJET SECURITE

## 1. Compilation programme
Dans chaque dossier, un Makefile a été mis à disposition afin de facilité la compilation des programmes.
Dans chaque dossier la simple commande `make` suffit.

/!\ ajouter au path de librairie le fichier courant : 
1. `LD_LIBRARY_PATH=/usr/local/lib`
2. `export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./` 

\+ Avoir installer openssl \
1. `sudo apt-get update`
2. `sudo apt-get install openssl`

## 2. Credential
identifiant : admin \
mot de passe : totoMdp

## 3. Chiffrement des crédentials
Dans le dossier `Serveur/configuration/` \
`openssl aes-256-cbc -a -salt -in credentials.txt -out credentials.txt.enc` 

/!\ Le fichier encrypté n'est pas utilisé dans cette version du code

## 4. Problème avec OpenSSL
Il est possible d'avoir des crash `segmentation fault` à cause de OpenSSL et plus exactement avec la méthode `BIO_write(...)` de la bibliothèque. Nous n'avons pas su corriger l'erreur.