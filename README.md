# SAFEX

## Build Instructions

### MacOS

Check if you have Developer Tools Installed
```
xcode-select -p
```
If you don't have Developer Tools, install it. If you do, skip this step
```
xcode-select --install
```
Clone the git repository with recursive
```
git clone https://github.com/safex/safexcore.git --recursive
```
Go into safexcore folder
```
cd safexcore
```
Check if brew is installed
```
which brew
```
If you don't have brew installed, install it. If you have it, skip this step
```
brew install wget
```
Install all libraries
```
brew tap jmuncaster/homebrew-header-only
brew install cmake boost zmq czmq zeromq jmuncaster/header-only/cppzmq libzmq openssl pkg-config
```
You will need to have MacPorts installed. If you don't have it install it from here https://www.macports.org/install.php. Then install readline using MacPorts
```
sudo port install readline
```
Build it and insert the number of cores you have
```
make -j<Your number of cores> debug-all
```


Copyright (c) 2018 The Safex Project.

Portions Copyright (c) 2014-2018 The Monero Project.

Portions Copyright (c) 2012-2013 The Cryptonote developers.
