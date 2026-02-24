#!/bin/bash

if [! -f "/bin/gcc" ]; then
    echo "gcc n'est pas installé. Installation..."
    sudo apt-get install gcc
fi

sudo apt-get install libnatpmp-dev
gcc serveur.c chacha20-c/chacha20.c -o serveur -lnatpmp
mv serveur Tchatooine
sudo cp Tchatooine /bin
