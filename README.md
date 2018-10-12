# SAFEX


## Releases

Current active release branch with up to date hotfixes is [release-v0.1](https://github.com/safex/safexcore/tree/release-v0.1). Official releases are available [here](https://github.com/safex/safexcore/releases).

## Build Instructions

### MacOS

Check if you have Developer Tools Installed
```
$ xcode-select -p
```
If you don't have Developer Tools, install it. If you do, skip this step
```
$ xcode-select --install
```
Clone the git repository with recursive
```
$ git clone https://github.com/safex/safexcore.git --recursive
```
Go into safexcore folder
```
$ cd safexcore
```
Check if brew is installed
```
$ which brew
```
If you don't have brew installed, install it. If you have it, skip this step
```
$ brew install wget
```
Install all libraries
```
$ brew tap jmuncaster/homebrew-header-only
$ brew install cmake boost zmq czmq zeromq jmuncaster/header-only/cppzmq openssl pkg-config
$ brew install libzmq
```
You will need to have MacPorts installed. If you don't have it install it from here https://guide.macports.org/. Download the package for your OS version from the website. Open **new** terminal window and check if MacPorts are installed
```
$ port version
```
If the installation was successful, install readline using MacPorts
```
$ sudo port install readline
```
Build it and insert the number of cores you have
```
$ make -j<Your number of cores> debug-all
```

### Ubuntu 18.04

A one liner for installing all dependencies on Ubuntu 18.04 is

```
$ sudo apt update && sudo apt install build-essential cmake pkg-config \
    libboost-all-dev libssl-dev libzmq3-dev libunbound-dev libminiupnpc-dev \
    libunwind8-dev liblzma-dev libreadline6-dev libldns-dev libexpat1-dev \
    doxygen graphviz libpcsclite-dev
```

To build a debug version, just run `$ make debug-all` (or `make -j <Your number of cores> debug-all` to use all cores).

To build a release version, just run `$ make release-all` (or `make -j <Your number of cores> release-all` to use all cores).

## Running

Built binaries are located in the `build/debug/bin` and/or `build/release/bin` (depending upon which build was used).

To run the node: `$ /path/to/binaries/safexd --testnet`

To run the wallet: `$ /path/to/binaries/safex-wallet-cli --testnet <other wallet parameters>`

For a list/reference of all wallet parameters use `$ /path/to/binaries/safex-wallet-cli --testnet --help`

<br/><br/><br/>
Copyright (c) 2018 The Safex Project.

Portions Copyright (c) 2014-2018 The Monero Project.

Portions Copyright (c) 2012-2013 The Cryptonote developers.
