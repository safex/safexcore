# SAFEX







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

### On Windows:

Binaries for Windows are built on Windows using the MinGW toolchain within
[MSYS2 environment](https://www.msys2.org). The MSYS2 environment emulates a
POSIX system. The toolchain runs within the environment and *cross-compiles*
binaries that can run outside of the environment as a regular Windows
application.

**Preparing the build environment**

* Download and install the [MSYS2 installer](https://www.msys2.org), either the 64-bit or the 32-bit package, depending on your system.
* Open the MSYS shell via the `MSYS2 MSYS` shortcut
* Update packages using pacman:

        pacman -Syuu

* Exit the MSYS shell using Alt+F4
* Start `MSYS2 MinGW 64-bit` shell and update packages again using pacman:

        pacman -Syuu

* Install dependencies:

    To build for 64-bit Windows:

        pacman -S mingw-w64-x86_64-toolchain make mingw-w64-x86_64-cmake mingw-w64-x86_64-boost mingw-w64-x86_64-openssl mingw-w64-x86_64-zeromq mingw-w64-x86_64-libsodium

    To build for 32-bit Windows:

        pacman -S mingw-w64-i686-toolchain make mingw-w64-i686-cmake mingw-w64-i686-boost mingw-w64-i686-openssl mingw-w64-i686-zeromq mingw-w64-i686-libsodium

* Open the MingW shell via `MSYS2 MinGW 64-bit` shortcut on 64-bit Windows
  or `MSYS2 MinGW 32-bit` shortcut on 32-bit Windows. Note that if you are
  running 64-bit Windows, you will have both 64-bit and 32-bit MinGW shells.

**Cloning**

* To git clone, run:

        git clone --recursive https://github.com/safex/safexcore.git

**Building**

* Change to the cloned directory, run:

        cd monero

* If you would like a specific [version/tag](https://github.com/safex/safexcore/tags), do a git checkout for that version. eg. 'v0.1.0'. If you don't care about the version and just want binaries from master, skip this step:

        git checkout

* If you are on a 64-bit system, run:

        make release-static-win64

* If you are on a 32-bit system, run:

        make release-static-win32

* The resulting executables can be found in `build/release/bin`

## Running

Built binaries are located in the `build/debug/bin` and/or `build/release/bin` (depending upon which build was used).

To run the node: `$ /path/to/binaries/safexd --testnet`

To run the wallet: `$ /path/to/binaries/safex-wallet-cli --testnet <other wallet parameters>`

For a list/reference of all wallet parameters use `$ /path/to/binaries/safex-wallet-cli --testnet --help`

Copyright (c) 2018 The Safex Project.

Portions Copyright (c) 2014-2018 The Monero Project.

Portions Copyright (c) 2012-2013 The Cryptonote developers.
