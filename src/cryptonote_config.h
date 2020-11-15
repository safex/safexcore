// Copyright (c) 2018, The Safex Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers
// Parts of this file are originally copyright (c) 2014-2018 The Monero Project

#pragma once

#include <string>
#include <vector>
#include <boost/uuid/uuid.hpp>

#define CRYPTONOTE_DNS_TIMEOUT_MS                       20000

#define CRYPTONOTE_MAX_BLOCK_NUMBER                     500000000
#define CRYPTONOTE_MAX_BLOCK_SIZE                       500000000  // block header blob limit, never used!

#define CRYPTONOTE_MAX_TX_SIZE                          1000000000
#define CRYPTONOTE_PUBLIC_ADDRESS_TEXTBLOB_VER          0
#define CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW            60
#define CURRENT_BLOCK_MAJOR_VERSION                     1
#define CURRENT_BLOCK_MINOR_VERSION                     0
#define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT              60*60*2
#define CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE             10

#define BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW               60

#define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V2           500
#define BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V2            12

// COIN - number of smallest units in one coin
#define COIN                                            ((uint64_t)10000000000) // pow(10, 10)
#define SAFEX_CASH_COIN                                 COIN
#define SAFEX_TOKEN                                     COIN

// MONEY_SUPPLY - number coins to be generated
#define MONEY_SUPPLY                                    ((uint64_t)(1000000000) * SAFEX_CASH_COIN) // 1 billion Safex Cash supply in 20 years
#define MAX_MONEY_SUPPLY                                ((uint64_t)(-1)) // uint64_t maximum money supply
#define FINAL_SUBSIDY_PER_MINUTE                        ((uint64_t)3) //after 1 billion, emit constant small block reward

#define CRYPTONOTE_REWARD_BLOCKS_WINDOW                 100
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1    20000 //size of block (bytes) after which reward for block is calculated using block size
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2    60000
#define CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE          600
#define CRYPTONOTE_DISPLAY_DECIMAL_POINT                10


#define AIRDROP_SAFEX_CASH_AMOUNT                       (10000000 * SAFEX_CASH_COIN) //10 million coins
#define AIRDROP_TOKEN_TO_CASH_REWARD_RATE               (0.00232830643) //migration token to cash rate

#define TOKEN_TOTAL_SUPPLY                              ((uint64_t)2147483647) //Token total supply, without decimals
#define MAX_TOKEN_SUPPLY                                ((uint64_t)(-1)) // uint64_t maximum token supply


#define FEE_PER_KB                                      ((uint64_t)100000000) // 1 * pow(10,8)
#define DYNAMIC_FEE_PER_KB_BASE_FEE                     ((uint64_t)100000000) // 1 * pow(10,8)
#define DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD            ((uint64_t)600000000000) // 60 * pow(10,10)

#define ORPHANED_BLOCKS_MAX_COUNT                       100


//Difficulaty related constants
#define DIFFICULTY_TARGET                               120  // seconds for 1 block
#define DIFFICULTY_WINDOW                               720 // blocks
#define DIFFICULTY_LAG                                  15  // !!!
#define DIFFICULTY_CUT                                  60  // timestamps to cut after sorting
#define DIFFICULTY_BLOCKS_COUNT                         DIFFICULTY_WINDOW + DIFFICULTY_LAG

#define DIFFICULTY_WINDOW_V2                            60
#define DIFFICULTY_LAG_V2                               0  // just for refrence
#define DIFFICULTY_CUT_V2                               0  // just for refrence
#define DIFFICULTY_BLOCKS_COUNT_V2                      DIFFICULTY_WINDOW_V2

#define DIFFICULTY_SECONDS_PER_YEAR                     ((uint64_t)31557600)
#define DIFFICULTY_BLOCKS_PER_YEAR                      ((uint64_t)DIFFICULTY_SECONDS_PER_YEAR/DIFFICULTY_TARGET)


#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS      DIFFICULTY_TARGET * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS
#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS       1


#define DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN             DIFFICULTY_TARGET //just alias; used by tests


#define BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT          10000  //by default, blocks ids count in synchronizing
#define BLOCKS_SYNCHRONIZING_DEFAULT_COUNT              100     //by default, blocks count in blocks downloading
#define BLOCKS_SYNCHRONIZING_MAX_COUNT                  2048   //must be a power of 2, greater than 128, equal to SEEDHASH_EPOCH_BLOCKS

#define CRYPTONOTE_MEMPOOL_TX_LIVETIME                    (86400*3) //seconds, three days
#define CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME     604800 //seconds, one week
#define CRYPTONOTE_MEMPOOL_SAFEX_TX_LIVETIME              3600 //seconds, 1 hour

#define COMMAND_RPC_GET_BLOCKS_FAST_MAX_COUNT           1000

#define P2P_LOCAL_WHITE_PEERLIST_LIMIT                  1000
#define P2P_LOCAL_GRAY_PEERLIST_LIMIT                   5000

#define P2P_DEFAULT_CONNECTIONS_COUNT                   8
#define P2P_DEFAULT_HANDSHAKE_INTERVAL                  60           //secondes
#define P2P_DEFAULT_PACKET_MAX_SIZE                     50000000     //50000000 bytes maximum packet size
#define P2P_DEFAULT_PEERS_IN_HANDSHAKE                  250
#define P2P_DEFAULT_CONNECTION_TIMEOUT                  5000       //5 seconds
#define P2P_DEFAULT_PING_CONNECTION_TIMEOUT             2000       //2 seconds
#define P2P_DEFAULT_INVOKE_TIMEOUT                      60*2*1000  //2 minutes
#define P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT            5000       //5 seconds
#define P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT       70
#define P2P_DEFAULT_ANCHOR_CONNECTIONS_COUNT            2

#define P2P_FAILED_ADDR_FORGET_SECONDS                  (60*60)     //1 hour
#define P2P_IP_BLOCKTIME                                (60*60*24)  //24 hour
#define P2P_IP_FAILS_BEFORE_BLOCK                       10
#define P2P_IDLE_CONNECTION_KILL_INTERVAL               (5*60) //5 minutes

#define P2P_SUPPORT_FLAG_FLUFFY_BLOCKS                  0x01
#define P2P_SUPPORT_FLAGS                               P2P_SUPPORT_FLAG_FLUFFY_BLOCKS

#define ALLOW_DEBUG_COMMANDS

#define CRYPTONOTE_NAME                         "safex"
#define CRYPTONOTE_POOLDATA_FILENAME            "poolstate.bin"
#define CRYPTONOTE_BLOCKCHAINDATA_FILENAME      "data.mdb"
#define CRYPTONOTE_BLOCKCHAINDATA_LOCK_FILENAME "lock.mdb"
#define P2P_NET_DATA_FILENAME                   "p2pstate.bin"
#define MINER_CONFIG_FILE_NAME                  "miner_conf.json"

#define THREAD_STACK_SIZE                       5 * 1024 * 1024

#define HF_VERSION_TBD                          100 //some hard fork version in the future, to be determined

#define HF_VERSION_DYNAMIC_FEE                  1
#define HF_VERSION_MIN_MIXIN_REQUIRED           HF_VERSION_TBD
#define HF_VERSION_MIN_MIXIN_4                  HF_VERSION_TBD
#define HF_VERSION_MIN_MIXIN_6                  HF_VERSION_TBD
#define HF_VERSION_ENFORCE_RCT                  HF_VERSION_TBD //enforce RingCT transactions
#define HF_VERSION_FORBID_DUST                  HF_VERSION_TBD //forbid dust and compound outputs
#define HF_VERSION_ALLOW_BULLETPROOFS           HF_VERSION_TBD
#define HF_VERSION_DIFFICULTY_V2                3
#define HF_VERSION_VALID_DECOMPOSED_MINER_TX_1  3
#define HF_VERSION_VALID_DECOMPOSED_MINER_TX_2  4
#define HF_VERSION_ALLOW_LESS_BLOCK_REWARD      2
#define HF_VERSION_MINER_TX_MAX_OUTS            11
#define HF_VERSION_CHANGE_MINER_DUST_HANDLING   5

#define HF_VERSION_STOP_COUNTERFEIT_TOKENS      6

#define HF_VERSION_ALLOW_TX_VERSION_2           7
#define HF_VERSION_MINER_DUST_HANDLE_DIGIT      7

constexpr uint8_t MIN_SUPPORTED_TX_VERSION = 1;
constexpr uint8_t MAX_SUPPORTED_TX_VERSION = 2;

//Safex related constants
constexpr uint64_t SAFEX_COMMAND_PROTOCOL_VERSION                   = 1;

//Safex token stake constants
constexpr uint64_t SAFEX_MINIMUM_TOKEN_STAKE_AMOUNT                      = 10000 * SAFEX_TOKEN;
constexpr uint64_t SAFEX_DEFAULT_TOKEN_STAKE_EXPIRY_PERIOD               = 500000;
constexpr uint64_t SAFEX_DEFAULT_INTERVAL_PERIOD_FAKECHAIN               = 10; //blocks
constexpr uint64_t SAFEX_DEFAULT_INTERVAL_PERIOD_TESTNET                 = 10; //blocks
constexpr uint64_t SAFEX_DEFAULT_INTERVAL_PERIOD_STAGENET                = 100; //blocks
constexpr uint64_t SAFEX_DEFAULT_INTERVAL_PERIOD                         = 1000; //blocks
constexpr uint64_t SAFEX_DEFAULT_MINUMUM_TOKEN_STAKE_PERIOD_FAKECHAIN    = SAFEX_DEFAULT_INTERVAL_PERIOD_FAKECHAIN*3; //blocks
constexpr uint64_t SAFEX_DEFAULT_MINUMUM_TOKEN_STAKE_PERIOD_TESTNET      = SAFEX_DEFAULT_INTERVAL_PERIOD_TESTNET*1; //blocks
constexpr uint64_t SAFEX_DEFAULT_MINUMUM_TOKEN_STAKE_PERIOD_STAGENET     = SAFEX_DEFAULT_INTERVAL_PERIOD_STAGENET*10; //blocks
constexpr uint64_t SAFEX_DEFAULT_MINUMUM_TOKEN_STAKE_PERIOD              = SAFEX_DEFAULT_INTERVAL_PERIOD*10; //blocks

//Safex network fee constants
constexpr uint64_t SAFEX_DEFAULT_NETWORK_FEE_PERCENTAGE             = 5;

//Safex create account token lock constants
constexpr uint64_t SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_FEE              = 100*SAFEX_TOKEN;
constexpr uint64_t SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_PERIOD_FAKECHAIN = 1;
constexpr uint64_t SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_PERIOD_TESTNET   = 10;
constexpr uint64_t SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_PERIOD_STAGENET  = 300;
constexpr uint64_t SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_PERIOD           = 1500;// TBD

//Safex account constants
constexpr uint64_t SAFEX_ACCOUNT_USERNAME_MAX_SIZE                  = 32;
constexpr uint64_t SAFEX_ACCOUNT_DATA_MAX_SIZE                      = 2048;

//Safex offer constants
constexpr uint64_t SAFEX_OFFER_NAME_MAX_SIZE                        = 80;
constexpr uint64_t SAFEX_OFFER_DATA_MAX_SIZE                        = 2048;
constexpr uint64_t SAFEX_OFFER_MINIMUM_PRICE                        = SAFEX_CASH_COIN/10000; // 0.0001 SFX

//Safex price peg constants
constexpr uint64_t SAFEX_PRICE_PEG_NAME_MAX_SIZE                    = 60;
constexpr uint64_t SAFEX_PRICE_PEG_CURRENCY_MAX_SIZE                = 8;
constexpr uint64_t SAFEX_PRICE_PEG_DATA_MAX_SIZE                    = 2048;

//Safex feedback constants
constexpr uint64_t SAFEX_FEEDBACK_MAX_RATING                        = 3;
constexpr uint64_t SAFEX_FEEDBACK_DATA_MAX_SIZE                     = 2048;

#define DEFAULT_MIX                             6 //default wallet mix for transactions

#define PER_KB_FEE_QUANTIZATION_DECIMALS        6

#define HASH_OF_HASHES_STEP                     256
#define HASH_CN_VARIANT                         2

#define DEFAULT_TXPOOL_MAX_SIZE                 648000000ull // 3 days at 300000, in bytes

// New constants are intended to go here
namespace config
{
  uint64_t const DEFAULT_FEE_ATOMIC_XMR_PER_KB = 500; // Just a placeholder!  Change me!
  uint8_t const FEE_CALCULATION_MAX_RETRIES = 10;
  uint64_t const DEFAULT_DUST_THRESHOLD = ((uint64_t)20000000); // 2 * pow(10, 7)
  uint64_t const DEFAULT_TOKEN_DUST_THRESHOLD = ((uint64_t)20000000); // 2 * pow(10, 7)
  uint64_t const BASE_REWARD_CLAMP_THRESHOLD = ((uint64_t)1000000); // pow(10, 6)
  std::string const P2P_REMOTE_DEBUG_TRUSTED_PUB_KEY = "0000000000000000000000000000000000000000000000000000000000000000";

  uint8_t const MIGRATION_GENESIS_PUBKEY_INDEX = 0;
  uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 0x10003798; // Safex
  uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 0xa90a03798; // Safexi
  uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 0x10e03798; // Safexs
    uint16_t const P2P_DEFAULT_PORT = 17401;
    uint16_t const RPC_DEFAULT_PORT = 17402;
    uint16_t const ZMQ_RPC_DEFAULT_PORT = 17403;
    boost::uuids::uuid const NETWORK_ID = { {
        0x73, 0x61, 0x66, 0x65 , 0x78, 0x6d , 0x6F, 0x6F, 0x6E, 0x6C, 0x61, 0x6D, 0x62, 0x6F, 0x34, 0x78
                                            } };
    std::string const GENESIS_TX = "013c01ff00018080a8ec85afd1b10100028ff33b5dc7640ad6333405a875f9a92cd69e99fc15d208ea2eb990203d1348dc8301011d22a19d7aa99b11c1143fd40e200760de6caa90eab16bd12d0188d6db8537611103c23aed713351b8b88e15bb213983aa03f26aca95da4e77384654153d50a55fc78dcc65a751789b60e816e3710d448b05f56777e66aff4c6228472e6a41e122dc9ab470e5997573adea910e70c4c3a04e3957e33c099848f0fd2d12dc6b84eca3";
    uint32_t const GENESIS_NONCE = 10000;
    uint64_t const HARDFORK_V4_INIT_DIFF = 330000000;
    uint64_t const HARDFORK_V4_START_HEIGHT = 330000;

    std::vector<std::string> const PROBLEMATIC_TOKEN_OUTPUTS{
            "194cb649cdb2bc6169a2f69da1de2eb85842ed1fbb5fc12c8f712f9e51dcaba2","60f5bfa4d87131176e94d4b12224d502a0ba389bf975a73cdd27476181019f6f",
            "00f195e5aaa28abf95f7a7398ccd0e48138f607f318444658ed7390263c971a3","031a56087d76158ac6ddc19bfd352a69784f2053e98f9fd2a681bbbb34c8f831",
            "4554113fb38691364bdcde8a413f4e4d3b5d3ce95bbe961b9a2f5d598a33fcff","952b973ccfba778db9622746dc837c1487ec05c94d2760b208c2609032155d6c",
            "311f14601dca4171d6e9a6eff503b78be23a6ae771f3d7425797c1652e8b2972","3fd47702fc31cc99053dbd4a414e7ccc87409b1075250a062dcef242f7b290d3",
            "c4c7121c2b30eb5203c5953035198990b655c6fcd5722beeeb5a8ff9fad12727","99cf9f822df020ad87e61275706cb896190e023aedab0b71842948007997df2c",
            "d7221db6117620fc204312ff2fd8c36c23859e2e3bc334f6412cd00300de3a8f","617866e93e2036759c3723be0bfe42be9364a69ba4c6c1f61d6104ab9f43b6fe",
            "76cb8eb947fcb86f86bf28d01d1ce791c1b09e7825893e6be3fafba19b1b3d0f","33f964dc91b96547fa1452f25cd39c797bcebc13a88c4a650af524be4974d03d",
            "66588942f6c89d4e23d1abe7477b7e3a816aae81c726a326e0610aa95b56eb6b","c67aaf0ea197bc3b67d38050e36aed459726db93b4771550b92bb689b7149972",
            "07023f89fe8af1191815408193b4bce7988ac084150b8c2172040b3be18192f4","ca7f01aed0054502f0c58ff6ef34b962e54df2dc3fbb26fb585c91d0253fb1ec",
            "d0fe199544256a18ca4f5184c78778e9e9f196d0635865c26d7a38775c730337","b35742f195c750ece0fe71e9e4363d67488bae4dea6537188d6a0a49151ba062",
            "43c25cc2f2da5f72c158165a680fb82159d25d5763a3ef1b2f1bd42b4d2dc10c","3d46bee4dd9f1f552ded018d950ae40bd41de6d33d7968a6be69bd7db4c6deef",
            "ce92d179dc3e0879ce898a95b6ce1b2c2f3477e26e0ac13669c6594c36b8f92b","f343d19f0f68d5a62a46df78247fa090e7f56dc3424772251fe1a270987d1186",
            "5791c42c721c73c0bc4cbacc2346824ed04a057cca7b7258266cf01e60d72325","c8306f361dbcc059a8311e209e850449d3facd2ff02d8b832ccadbb90f3bd44b",
            "33510a8e9489e28f9ef8ead196b0c21a9e1b6ebcf2c07e081a0a10d951d6be29","dd4cab7f19fb878a5516e6258fb625dde94a66d0348dcfad283038d2e023ae42",
            "cf1898cb85560d88b89643c0170f5914c957932faa275c0579db5748051c496c","f7bea78001ecaef799ca19d666eeeb03dcd1b0844486e93f17b0b568fef120d7",
            "473c6fc94da767cc4a0d5f4fba2b8d47f9a99a193aa91a6acdd8036b8e3db123","7c1bfa95023730dfb8809b29b7ab77d34a4e3e5558e583d8b3d22415fd340f0a",
            "cc48427de3319b35aa8e59cc25324f381a1ff7a83b2e46e2cb974d8714ae439b","df190c9ee522b7092683bc65307e4042391175103fb0fbe73cfc7abb1ead7b9e",
            "be5cfd3a8d4ad05f795296478083c1249aa465e64c4ed15e1fc36a0e4828aa98","63af8e04bc4ee59c4f19cbaf7827fb93af4959f4919c4867c222dd715fe6d332",
            "86b51317a3f93032255ccc4771021833213e8bff4ca9b3baba70f7ac11d6c3eb","2eca12889f7b6f03a91c1034378b899e612656b473c8d26ffba9585827ee484a",
            "28a79e3ad3a054cd119623969b1c91f261f40c9e598e90cf06e7b7201db0f1b2","a9157e1c95caa9144b8a7028066e62b86e93e7742d789f59837151f053cafb0f",
            "342e56e868d4ab9bf972ffd15826bbad8b0ebeb3cfbd985b4a2d0ac095772ca0","f5c75e6ae2301b313347bab69910f28b9a91d1afd58ccd71dd776e6c8850a41d",
            "0e884397097c936bb1d14ef3bc5a0e9e0fe8def5b0ee287566545d0cb8332921","6d4e6cc2299871b505d9b12c7583194350e63c84798d2285e0735b32e7f4a4cb",
            "cf059d36d318365af7ca592ae0439ddd18b8f26dfdb9e87ad35c611b9c7c90f8","db12dccbf946b3a83192fad4779e4506d3998091a798b16be1e70e76ef655d29",
            "1af8122d204918d75c1818a74ee4fd1dfd56e78653e2f0d2978bb8c9e15a2661","e7d626f0a5308fd704439356c0891eafd934221a61073abb6735f1d807271d7f",
            "4ac505f3e8112da00f7078e0dedd80b6d2159ad7e4504a195dbcab77c2b81d4d","200d2e46eab0a347c1af38c611e6349c3284d5edb84a276e569a075311298e88",
            "2be0d30946c909f0f4c43a00f41711459e3723feee74ff3ba8ec75b01422f903","eacaac6c6b0ba344ba35ce55c779abe4c06bd6fcc00fd370cc287e8f83c1176d",
            "dc67327222d179a781cfcdc6299f8b8260948c5b79438979e8469edff2fa05d0","40fb725d6f668d5713d075e2111727386b5adb1101fd7f2d7553a08070b66f10",
            "97e003e3acefa5dfd109c0d12e1281cc24bbeb4e78f5a0f9fc897ed2bdaa76a8","40d980a7f574444817300b96abe75fec228887d3298afd0e0364cb067980d2e0",
            "9421a5399ef81ee410c77e7ee90ab7f58fc1cc7e33b7c7964e7e083e5764d2a4","1481cca61c169f391a48e2859ea2d61634e87e02190481ea1aee7cf7f3cd60ae",
            "4edb1f8c4fd8a00d4f2a409f2db0729f81ccc91b52fdb7b6455bc7df951eed0a","39d0e6886d74f7c8f0c9b47635fa3b79d99eee4663ea4c5e0a5ebeb5c67e1352",
            "14a0a12e5c52787161dbf254b913573d840c355298d218c5f7864ce3d12c821f","12f5664e130752146c4cc96444e734e535c67a3058752b53679cd3c48f85d8c8",
            "1dcb1c3b242fef3206ae2f6cda5708cb6f3001bda88f4947aa5fdd6d0e8c8e97","63ca4cfb821741d78f3386194b1c909881573783a5bebfe16ed4c0a7246e4174",
            "582a6296a70b69f04d596668ebe8c1e1ad93e55ffb1d637cc124309ea3c6907c","cbcc1cf6fc22b38f726fd464faa62a2860c87382473efb81cc68ff50f43c3c08",
            "ab2b8ea7805e69bb05f2af2768440e26a76525b91006f667d2a3a152269f3f9f","46f20f58f5a23c7ede0383ca4876e4fe9f246f0b3c8da7010be8b82953a001ff",
            "a23947a583eaa7c71c83dcab4bbdde99f2108141a96f90b07da0b8e61d1d9a8e","6354d9115fb009f7eeb512659dbdee05c7b0f3aa90b13d6dd8d5c77c1bea506b",
            "2c1d3ae50a69c450307f975d4924b0bafcaa388e7f7ec0b514788b06253d7579","5ffe1e4ac141b544f8b03d6af82c142ca5cfb4760544c90e784ec9d53be2d209",
            "8114e26da6c5c2c949917081bbc3d29c7c5d9c751d265fd9e0828637a7985c40","6c1d762f646c492bbf7b69e25d0e7f93c08b748ef6968b00689acf6e02fbe407",
            "2f5368d011ab94cfec5c57a476d1dcfa1b469664390ecb1e2f1cc780c4315500","c0ea9d2dc3d6ae166a2d279245fdb35d085273d31515f1532135d2410cb4655d",
            "ef3380804b2cb5aed38e98ae322860593214470ac8dc3af51bb6a97543ddc3cc","559a2cc9f973d89fc24b805331f35707147efd0ad5c28d2404a8d3d65e9d7d21",
            "46d5ae7c33520ef54f6ef127320fdda5971134a656bed93893a154bb504685ae","c77ef0fc1d6f928ca8cbbea7a07326a9bfcce95f739207d1e3374d7e1e5a8c8c",
            "91578de322ee5d6b2e91eeac3f5a8127a75875dd89f5bd27df99c71e379e231b","72d43b7099b3bbec6e5b7d7c85b46ad907d9c82354227541b5a5642b3a6710ae",
            "5e68c8e895bd2de86eb395f8854153797f37029e791ed9d67a427af96635c0b4","54ab7a01f552d6a4aa7310b1bb857b582b45eac2ca10f0e6f3bb03e2a2adb36f",
            "c655fdb9f429b8217e0b2d3beaa9c1d0d8ef21aa10268a3fe7f539c8133bf340","835dbea0efb685e219318fdd4468a3c062474bc119594a692bfeaa50e3f6caf5",
            "1f6d1827cbd11e2ddfc2776cf9d75d895b72bc6a6dbd5fffa1673ccea29eba9d","a77e65d77be85a933d485057169f0c7b60fd3cb012ec9d653f9a9e5a72967d6e",
            "e47148d35a753f2d431ea48493affd59bca179d9daf0e3eddf16f0e7600f332d","293d2b82a7ab10571647ad76a9503416becef899d45fa1f9a226d558e54e339a",
            "d0fd2898006c6c7dc31103dbc0c717bd11d80ba466bfef7a1b53ba33ef2892df","92e661bbc6f1e4a30517bcc98be937548ca29e63d965fc9fc086116bdab946ec",
            "69b48fc49d042214466785e5f86c4e107411eb3eeed6001c49364f62d7c3ef15","deae6138d51ff99696762f22d0c4fc9f307b3c5b3715f2301fa099d255163d26",
            "d89803d5bc869ef2315f9c7e7db0d15ffb77cb4e28bb8b8c30b46540c43af344","01cf792b750853bee28c7802b01372e92ed879e05d2ed49ff66565ebb4ea2b71",
            "cd5dd5db3d60dacb0c6cd74dbd4997091542042929cebf26df9e294257fca862","ed6a5e59330ce9cdf33ecd38634440a68d19e2d15d71e13ae22cb9fb83ca19a9",
            "89a57549da28f39eea78360bf1ffb929eda65e208b7437e3f1f9b75bdd3a6db5","0bd94b23ca2aa1551bd5beccb8ab781e2325aba9f733d76fea0d1c7d34006ce2",
            "4f10ff7945b62d63815f5dd1e9c7840f4b9ac3eb25b29d530e78cc1afb455350","e4d8f374b6e45a83360d2553279ffbb9278e31e5131ee6c8f9455d0b5b7636e2",
            "8195a03cd1698aca0779d6c8084f23cbe6345a85a72c42f16d80339ce1c7996e","6f91481ee3270569a7c08e828ca5b7bc828f4f53ba051137212c0a16390d3ac6",
            "94e26eb5fc79331d97801b7ab5565d2c92480a359116b9592056e389b42f5912","6229cc4b183172eb640c46516e01682ea661f0ea4c3865d0192866a67ea76c5c",
            "8a921eebf4aaedc2bd0ac6c45c6c1255686bc787a80ea50c22d787196de677f7","2aa7baa21d84eb7e18eb5ed39b703bba20cdfed0a68e13e71a2d4ba3e59983c3",
            "6643ed1624917c74bbdc79537676281617bb513262e24200474d4a4fb6e076b5"};

  namespace testnet
  {
    uint8_t const MIGRATION_GENESIS_PUBKEY_INDEX = 0;
    uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 0x263b16; // SFXt
    uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 0xe05fb16; // SFXti
    uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 0x1905fb16; // SFXts
    uint16_t const P2P_DEFAULT_PORT = 29392;
    uint16_t const RPC_DEFAULT_PORT = 29393;
    uint16_t const ZMQ_RPC_DEFAULT_PORT = 29394;
    boost::uuids::uuid const NETWORK_ID = { {
        0x13 ,0x31, 0xF1, 0x71 , 0x61, 0x04 , 0x47, 0x65, 0x37, 0x31, 0x00, 0x73, 0x61, 0x61, 0x2A, 0x31
      } };
    std::string const GENESIS_TX = "013c01ff00018080a8ec85afd1b1010002d4372ec2272690ccd59880807d1fa00f7bd2fa67f7abb350cafbdc24a4ba372c8301011a1ca7d7e74037e4d000a0fc2cc61389ac7d8b0a6b600c62e77374477c4c414d1103a83b4a507df5b0dc5af701078828a1372d77761339a28a7ebb1ff450622f7456d1083f35430eba3353a9e42514480a0cbccbda5ee6abb2d856f8a9aae056a92a6ece1020496a36a4b68341e3b401653139683f8dc27d76ff9eb9c26c2528c26a";
    uint32_t const GENESIS_NONCE = 10003;
    uint64_t const HARDFORK_V4_INIT_DIFF = 1;
    uint64_t const HARDFORK_V4_START_HEIGHT = 1260;
  }

  namespace stagenet
  {
    uint8_t const MIGRATION_GENESIS_PUBKEY_INDEX = 0;
    uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 0x25bb16; // SFXs
    uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 0xdc57b16; // SFXsi
    uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 0x18c57b16; // SFXss
    uint16_t const P2P_DEFAULT_PORT = 30392;
    uint16_t const RPC_DEFAULT_PORT = 30393;
    uint16_t const ZMQ_RPC_DEFAULT_PORT = 30394;
    boost::uuids::uuid const NETWORK_ID = { {
        0x12 ,0x30, 0xF1, 0x71 , 0x61, 0x04 , 0x41, 0x61, 0x17, 0x31, 0x00, 0x73, 0x61, 0x66, 0x65, 0x90
      } };
    std::string const GENESIS_TX = "013c01ff00018080a8ec85afd1b1010002cd3249adde7fce93280c3a87db72648b7e47eeb08a5e6ff8e926f86e4aa9ffa283010126cb71e5ddd6461fea5d5b00644c5fb9711a2951e1345ba95c648b00ca08e23d1103ab3e85348739c5348f5dd7a61de6e1d30c0a81389ba9ce533da1e65df03f6a71f2df17d26217fb61bd2e8bc65197bf535904d9f5d75e531712f7fd3e255c5ad5308d1ee2cc4166b8effafd2f75d9c8483bb264ed7539cbc2921c580b40b1218b";
    uint32_t const GENESIS_NONCE = 10002;
    uint64_t const HARDFORK_V4_INIT_DIFF = 1000;
    uint64_t const HARDFORK_V4_START_HEIGHT = 87200;
  }
}

namespace cryptonote
{
  enum network_type : uint8_t
  {
    MAINNET = 0,
    TESTNET,
    STAGENET,
    FAKECHAIN,
    UNDEFINED = 255
  };
}
