# SAFEX CASH MINING



## CPU solo mining


Download and build safex core blockchain client:

```
$ sudo apt update && sudo apt install build-essential cmake pkg-config \
    libboost-all-dev libssl-dev libzmq3-dev libunbound-dev libminiupnpc-dev \
    libunwind8-dev liblzma-dev libreadline6-dev libldns-dev libexpat1-dev \
    doxygen graphviz libpcsclite-dev
$ git clone https://github.com/safex/safexcore.git --recursive
$ cd safexcore
$ make -j<CPUNUM>
```
Start safex blockchain node, wait for it to sync:

```
$ /path/to/directory/safexcore/build/release/bin/safexd
```

Start mining to the target address:

```
start_mining <addr> [<threads>]
```


## GPU solo mining

### Ubuntu 18.04

Download and build safex core blockchain client and shared libraries:

```
$ git clone https://github.com/safex/safexcore.git --recursive
$ cd safexcore
$ cmake -D CMAKE_BUILD_TYPE=Release -D BUILD_SHARED_LIBS=ON .
$ make
```

Sync Safex blockchain

```
$ /path/to/directory/safexcore/bin/safexd
```


Build local Startum proxy:

```
$ sudo apt-get install golang
$ git clone https://github.com/sammy007/monero-stratum.git
$ cd monero-stratum
$ MONERO_DIR=/path/to/directory/safexcore cmake .
$ make
$ cp -v ./config.example.json ./build/bin/config.json
```

Setup configuration for monero-startum to target local Safex node. Also set address that will receive block reward.

```
"address": "Safex5zN1S4dFF6LP2zzxy3BtFsKJZ2Q8jLpqNEr46ENhVLtxasf6rahe3hpjWXiVFWNdues5z22x8U69AC7WZqZDgu3rnQjJmQ2K",
...
"upstream": [
		{
			"name": "Mainnet",
			"host": "127.0.0.1",
			"port": 17402,
			"timeout": "10s"
		}
```

With local safexd node running and synced, run monero-startum
```
$ cd /path/to/monero-stratum/build/bin
$ ./monero-stratum ./config.json
```

#### NVidia Graphic Cards

Install latest NVidia driver if it is not installed:

```
$ sudo add-apt-repository ppa:graphics-drivers/ppa
$ sudo apt update
$ sudo apt-get install nvidia-driver-396
```

Install Cuda Toolkit
```
$ sudo apt-get install nvidia-cuda-toolkit
```

Download and build xmrig-nvidia
```
$ sudo apt-get install git build-essential cmake libuv1-dev libmicrohttpd-dev gcc-6 g++-6
$ git clone https://github.com/xmrig/xmrig-nvidia.git
$ cd xmrig-nvidia
$ mkdir build
$ cd build
$ cmake -D CMAKE_C_COMPILER=gcc-6 -D CMAKE_CXX_COMPILER=g++-6 ..
$ make
$ cp -v ./src/config.json ./build/
```
Configure xmrig-nvidia by editing xmrig-nvidia/build/config.json

```
"algo": "cryptonight/1",
"donate-level": 1,
...
"pools": [
        {
            "url": "127.0.0.1:1111",
            "user": "anything.rigname",
            "pass": "x",
            "rig-id": null,
            "nicehash": false,
            "keepalive": true,
            "variant": 1
        }
    ],
```

Start mining
```
$ cd /path/to/xmrig-nvidia/build
$ ./xmrig-nvidia
```

Note: xmrig-nvidia should be customized to support Safex Cash donation, currently that is not the case and donation will be wasted.
xmrig-nvidia successfull mining printout:

```
$ ./xmrig-nvidia 
   * VERSIONS     XMRig/2.7.0-beta libuv/1.18.0 CUDA/9.10 gcc/6.4.0
   * CPU          Intel(R) Celeron(R) CPU G3930 @ 2.90GHz x64 AES
   * GPU #0       PCI:0000:03:00 GeForce GTX 1070 Ti @ 1683/4004 MHz 34x57 0x0 arch:61 SMX:19
   * ALGO         cryptonight/1, donate=1%
   * POOL #1      127.0.0.1:1111 variant 1
   * COMMANDS     hashrate, health, pause, resume
  [2018-08-15 17:39:32] use pool 127.0.0.1:1111 127.0.0.1
  [2018-08-15 17:39:32] new job from 127.0.0.1:1111 diff 8000 algo cn/1
  [2018-08-15 17:39:40] new job from 127.0.0.1:1111 diff 8000 algo cn/1
  [2018-08-15 17:39:45] accepted (1/0) diff 8000 (81 ms)
  [2018-08-15 17:39:45] new job from 127.0.0.1:1111 diff 8000 algo cn/1
  [2018-08-15 17:40:06] accepted (2/0) diff 8000 (0 ms)

```



#### AMD Graphic Cards

Download and Install latest AMD GPU drivers from [AMD Drivers and Support](https://www.amd.com/en/support), [Radeon Software for Linux Installation](https://www.amd.com/en/support/kb/release-notes/amdgpu-installation).


Download and build xmr-stack-amd
```
$ sudo apt-get install ocl-icd-libopencl1 ocl-icd-opencl-dev libopencl1-amdgpu-pro opencl-amdgpu-pro
$  wget https://github.com/fireice-uk/xmr-stak/archive/2.4.7.tar.gz
$ tar xf 2.4.7.tar.gz
$ cd xmr-stack-2.4.7
$ mkdir build
$ cd build
$ cmake ../ -DCUDA_ENABLE=OFF -DOpenCL_ENABLE=ON
$ make
```

To prevent *Error: MEMORY ALLOC FAILED: mmap failed* follow instruction on https://github.com/fireice-uk/xmr-stak/blob/master/doc/FAQ.md#error-memory-alloc-failed-mmap-failed. 

Configure xmrig-stack by running it:
```
miner@rig01-lin:~/mining/xmr-stak-2.4.7/build/bin$ ./xmr-stak 
Please enter:
- Do you want to use the HTTP interface?
Unlike the screen display, browser interface is not affected by the GPU lag.
If you don't want to use it, please enter 0, otherwise enter port number that the miner should listen on
0
Configuration stored in file 'config.txt'
Please enter:
- Please enter the currency that you want to mine: 
	- aeon7
	- bbscoin
	- bittube
	- cryptonight
	- cryptonight_bittube2
	- cryptonight_masari
	- cryptonight_haven
	- cryptonight_heavy
	- cryptonight_lite
	- cryptonight_lite_v7
	- cryptonight_lite_v7_xor
	- cryptonight_v7
	- cryptonight_v7_stellite
	- graft
	- haven
	- intense
	- masari
	- monero7
	- ryo
	- stellite
	- turtlecoin

monero7
- Pool address: e.g. pool.usxmrpool.com:3333
127.0.0.1:1111
- Username (wallet address or pool login):
marko
- Password (mostly empty or x):
x
- Rig identifier for pool-side statistics (needs pool support). Can be empty:

- Does this pool port support TLS/SSL? Use no if unknown. (y/N)
N
- Do you want to use nicehash on this pool? (y/n)
n
- Do you want to use multiple pools? (y/n)
n
Pool configuration stored in file 'pools.txt'

```

Start mining
```
$ cd /path/to/xmr-stak-2.4.7/build/bin
$ ./xmr-stak
```

Printout of successfull mining:
```
-------------------------------------------------------------------
xmr-stak 2.4.7 c5f0505d

Brought to you by fireice_uk and psychocrypt under GPLv3.
Based on CPU mining code by wolf9466 (heavily optimized by fireice_uk).
Based on OpenCL mining code by wolf9466.

Configurable dev donation level is set to 2.0%

You can use following keys to display reports:
'h' - hashrate
'r' - results
'c' - connection
-------------------------------------------------------------------
[2018-08-17 13:46:46] : Mining coin: monero7
[2018-08-17 13:46:46] : Compiling code and initializing GPUs. This will take a while...
[2018-08-17 13:46:46] : Device 0 work size 8 / 32.
[2018-08-17 13:46:47] : OpenCL device 0 - Load precompiled code from file /home/miner/.openclcache/8979c28ee48993be74e0dff567217807eb53d517c4620575576267503777c566.openclbin
[2018-08-17 13:46:47] : Starting AMD GPU (OpenCL) thread 0, no affinity.
[2018-08-17 13:46:47] : Starting 1x thread, affinity: 0.
[2018-08-17 13:46:47] : hwloc: memory pinned
[2018-08-17 13:46:47] : Fast-connecting to 127.0.0.1:1111 pool ...
[2018-08-17 13:46:47] : Pool 127.0.0.1:1111 connected. Logging in...
[2018-08-17 13:46:47] : Difficulty changed. Now: 8000.
[2018-08-17 13:46:47] : Pool logged in.
[2018-08-17 13:47:03] : Result accepted by the pool.
[2018-08-17 13:47:03] : New block detected.
```

### Windows 10

//TODO write how to compile node client and monero-stratum

Download xmr-stack for Windows [here](https://github.com/fireice-uk/xmr-stak/releases).

//TODO write how to configure and start mining





