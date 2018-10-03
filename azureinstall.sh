#!/bin/bash

#go to home directory
cd

#download go binary
wget https://storage.googleapis.com/golang/go1.9.7.linux-amd64.tar.gz

#unzip and remove
sudo tar -C /usr/local -xzf go1.9.7.linux-amd64.tar.gz
rm go1.9.7.linux-amd64.tar.gz

#export path
export PATH=$PATH:/usr/local/go/bin
echo "" >> .profile
echo "#export go path" >> .profile
echo "export PATH=$PATH:/usr/local/go/bin" >> .profile

#make root directory and set GOPATH
mkdir go
export GOPATH=$HOME/go
echo "" >> .profile
echo "#set GOPATH" >> .profile
echo "export GOPATH=$HOME/go" >> .profile

#export workspace bin
export PATH=$PATH:$GOPATH/bin
echo "" >> .profile
echo "#set local bin" >> .profile
echo "export PATH=$PATH:$GOPATH/bin" >> .profile

#install mercurial
sudo apt-get install mercurial

# install GoVector to boot strap directories
# go get github.com/arcaneiceman/GoVector

source .profile
source ~/.profile

go get golang.org/x/net/html
