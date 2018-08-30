# Safex Project

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
$ git clone --recursive https://github.com/safex/safexcore.git
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
    libgtest-dev doxygen graphviz libpcsclite-dev
```

To build a debug version run:
```
make -j <Your number of cores> debug-all > build.log
```
to use all cores.

To build a release version run:
```
make -j <Your number of cores> release-all > build.log
```
to use all cores.

### Docker

        # Build using all available cores
        docker build -t safex . > docker_build.log

        # or build using a specific number of cores (reduce RAM requirement)
        docker build --build-arg NPROC=1 -t safex . > docker_build.log

        # either run in foreground
        docker run -it -v /monero/chain:/root/.bitmonero -v /monero/wallet:/wallet -p 18080:18080 safex

        # or in background
        docker run -it -d -v /monero/chain:/root/.bitmonero -v /monero/wallet:/wallet -p 18080:18080 safex


## Testing

To test the code, run:

```
$ cd build/debug/tests
$ ctest -j <Your number of cores> -VV > tests.log
```

## Running

Built binaries are located in `build/debug/bin` and/or `build/release/bin`, depending upon which build was used.

To run the node:
```
$ ./build/debug/bin/safexd --testnet
```

To run the wallet:
```
$ /path/to/binaries/safex-wallet-cli --testnet <other wallet parameters>
```

To list all wallet parameters use:
```
$ /path/to/binaries/safex-wallet-cli --testnet --help
```

---

Copyright (c) 2018 The Safex Project.

Portions Copyright (c) 2014-2018 The Monero Project.

Portions Copyright (c) 2012-2013 The Cryptonote developers.
