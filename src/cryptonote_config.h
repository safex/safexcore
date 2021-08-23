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
constexpr uint64_t SAFEX_MINIMUM_TOKEN_STAKE_AMOUNT_FAKECHAIN            = 10000 * SAFEX_TOKEN;
constexpr uint64_t SAFEX_MINIMUM_TOKEN_STAKE_AMOUNT_TESTNET              = 10000 * SAFEX_TOKEN;
constexpr uint64_t SAFEX_MINIMUM_TOKEN_STAKE_AMOUNT_STAGENET             = 10000 * SAFEX_TOKEN;
constexpr uint64_t SAFEX_MINIMUM_TOKEN_STAKE_AMOUNT                      = 25000 * SAFEX_TOKEN;
constexpr uint64_t SAFEX_DEFAULT_TOKEN_STAKE_EXPIRY_PERIOD               = 500000;
constexpr uint64_t SAFEX_DEFAULT_INTERVAL_PERIOD_FAKECHAIN               = 10; //blocks
constexpr uint64_t SAFEX_DEFAULT_INTERVAL_PERIOD_TESTNET                 = 10; //blocks
constexpr uint64_t SAFEX_DEFAULT_INTERVAL_PERIOD_STAGENET                = 100; //blocks
constexpr uint64_t SAFEX_DEFAULT_INTERVAL_PERIOD                         = 1000; //blocks
constexpr uint64_t SAFEX_DEFAULT_MINUMUM_TOKEN_STAKE_PERIOD_FAKECHAIN    = SAFEX_DEFAULT_INTERVAL_PERIOD_FAKECHAIN*3; //blocks
constexpr uint64_t SAFEX_DEFAULT_MINUMUM_TOKEN_STAKE_PERIOD_TESTNET      = SAFEX_DEFAULT_INTERVAL_PERIOD_TESTNET*1; //blocks
constexpr uint64_t SAFEX_DEFAULT_MINUMUM_TOKEN_STAKE_PERIOD_STAGENET     = SAFEX_DEFAULT_INTERVAL_PERIOD_STAGENET*10; //blocks
constexpr uint64_t SAFEX_DEFAULT_MINUMUM_TOKEN_STAKE_PERIOD              = SAFEX_DEFAULT_INTERVAL_PERIOD*8; //blocks

//Safex network fee constants
constexpr uint64_t SAFEX_DEFAULT_NETWORK_FEE_PERCENTAGE             = 5;

//Safex create account token lock constants
constexpr uint64_t SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_FEE              = 1000*SAFEX_TOKEN;
constexpr uint64_t SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_PERIOD_FAKECHAIN = 1;
constexpr uint64_t SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_PERIOD_TESTNET   = 10;
constexpr uint64_t SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_PERIOD_STAGENET  = 300;
constexpr uint64_t SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_PERIOD           = 22000;// 30 days

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

    std::vector<std::string> const ADDITIONAL_PROBLEMATIC_TOKEN_OUTPUTS{
        "92990cacf75d60d941bd816362d28824f95e97734d85495c755f203349a39512",
        "38f40027613693048014c4787be19cc787eee8dc17b4fe0f7f9d850f04bb734e",
        "c6502e6cb3ef05c10c14b1bd0f2717386448a6ce8f2c3439e9247303f23cf87e",
        "6699f3e72a3fc094bb66e8f3ce418b7ec9b74c36a82b21993c4103f74a088a68",
        "f066880cf7d2234b5a3b2d78f9044fdabb8540bee1bed89741ec2d956382d7d4",
        "a56bf1102470d21409f5763c897069dcb95685a93553c8d54dd216c279451002",
        "82988192279fa409464681e6099968c357d0800cd943369fcedebe9f5e95e51b",
        "0e8b583eb344f00e9209841bb82e895caac4372a32e05850241d02759d925c90",
        "f48366e907d5dbee9d565743fc7a57848e35fcc67865ddcb771f940967f5699c",
        "34f0bec0542989f698fd430d73c0a577c5d2472620bf9f0e36f5c510be06406d",
        "d3c880671cbbf3b6ad405cb7f1837df03a9de47d6be0286fe3e39288b5cd6dd7",
        "2aa03e683b4ab328de7503aed9f2821e66eb1c94c1b687adb700f23a237f8a17",
        "e5c7ef3ef0eaa420db4bc1a748a9899dce223e86ad5de985590f06ec20a5eab2",
        "069246e6f2451fa02a22a7a5fbceff1a112d89dc237882add7044e40ef83210f",
        "5059613517ec72437c3789cad1bbc743dce083b1cef229c1d00ee40778584262",
        "938089023c677e74ca79310a6f290c7255919e6b6c7ac0609e2048f31448dd20",
        "53d8a48f45007319d4c4e44f1339657f589422d36eabb952388d02257f6117e6",
        "bbbccf20492a13e1fb5ad28d6e3fea84ea1923645e49f63d13c8fc04e1f2724c",
        "3bca04e674d718283369be3f2e46a78a1601b3903bbc2386ebe6cbcae662a5ff",
        "d4d276fcfbd188f66b164ece3ae024f6bb6f3dc12fd0354fc3a72a2c4405d3ae",
        "574c26eb8e62a78fb809669e734f3da219a234f6ab686ae8b50553d1d679fa96",
        "9a87a33882f2f898ab5df5b6ddcc096f299a52a169cb3afecd544714bfe6cb8d",
        "52b1edc4e59732905011e9cbe6bfd3affae974c1cdb15c34ba0606d815bf28d4",
        "d91db0e2ee29612420ac3add11a40c0ce320d4b86f347670db40de9756597a33",
        "3161e43344e532cbdea8c001b586765c38a17e766c25603ea11092bacd77e757",
        "245435343de2203ee8f3123b5a22cdf611f60b429d505e861ad03acdbaea6712",
        "bfc119b94eff34db39243053f0fdfd4eb2d66547c0b9979c025b055d9cb39fb4",
        "b2bc04e467071d39cbf76aee64f0ca201c507e23deefaf6b5617092825c47ec2",
        "d5e50b9b6b6c805ed338e662024ae03e6e5565a9464b87cd67f04d4be6594d6e",
        "8946b7716a8c88dad36461fc015c297931d4fe3b34e39fb4135c0e333aa8cfb4",
        "5e3904f3ea91377b6b89f2475059aaa9086fa1434fa4bbb8afc239110a56b6ef",
        "3de2c8d72bc8e0778552d6de0b51bb4990b50a1cdfc03d2e0b96483c1a9aa7b7",
        "5b78f8eabf946b7e1e82803b444c0bab799d833156ba02ee4f671ac75ca35509",
        "36af792199cab7f581c1832f91c67b8950aeee32cbabe1775d23949c6f36527a",
        "1e4cb80ef85a188bb85ccda7663e24469411405b6db83d2c0556c6e8d6a9facd",
        "5756d83b78906f55ebbbe5390d8a3db82c3e94bba7def1c9cccb706984047cd9",
        "24878fefe009e5c2bd0ac6d3b5f4508f5be922fb2cce9813486bbbc2b898e3f1",
        "0f309458c055026cb0f8080b872ba366f8c4280794d0677a9cf8fb0d16e534a9",
        "f70d8cdcd0de63cc9a5436528328f636db510d1ee3377658d3cf1a818a81d230",
        "259a8503aa10a85a873c454ad1016b9d669e00a36d240ef6e9852abd2a47dd7c",
        "3a3ad50ae16304f456889959c2fa602bf036d45a59c47c8fb42a4070b67ca206",
        "5d5a60d0833e6239cbaa20290425985f9709b474eea658dca62bc114a8e49549",
        "f17c8f0ca11ec9be7834545ca90b2f04c307efb5f38cab108befd20a7d3d7125",
        "60c1393f16e493745210ebcd71c611cb9bcd390bceeac0261610705bc041d818",
        "070b4fd9d84b21c27f4c9f8131469845916394b0478777fbd87ee218782cddf2",
        "e5ef8be5148edc73a10cbe024d71bfbde3b8682e3ba8508c667cd18e635f2f6c",
        "08f110fe38cbd1c2174ba544bd1ac4e9e807be7790e2bc4d8ab3549824a49f0a",
        "1b975974a2baec363e2fdd392cf94dc4e382583edc9ecdcb5d7e48c5460d5119",
        "46b15e6acd70f3d784150e88bf72f5e6f252bf3b0e2d55ba3f9f5924ffbd4384",
        "218bbc8658cf7a7e95674b9126038511ae7766bc07a091aecf8ab27a7a7faadf",
        "756c20802b1a3c95e3f2cc9d9b6f50d77a7cf974d87a3c6d2684cea56dd702ce",
        "65afd96e38d5bc6ef3af1d96e13c0c2380a59f9c9e78a3d5e175bc129a8fb0fe",
        "711c80dc4dea8c34e291ac81b13e13d74c7591be50c49e52b03b15036dfa7553",
        "81cf22503c88370932be08c97ccbf341b8b6f2c111978da172e3c7f289acbad6",
        "376e6bcfa5da5189dbcb39d74f9384fbbf2492b3880856017073f309200f2a92",
        "636f3cbea9f0c700ecaeff0d9a395c83b8d7529035f299123ee7ffa4161cc75a",
        "6f6daf781c336e04cf97beb08bf9b56930baab1920f982359bbdcdbd23a20b57",
        "6b25559b9b094e6096705a221f7830f1a40ff990a2b0d274249c316dd87ee8d7",
        "b16da6f8fc0f3248e0972ec07dfa00b4fdae7e5186fb1a379fed47d4e92c367b",
        "bbc4e8676eda9b397c842a5dae80eb11e5c47a649f88942b309e5211c212aa64",
        "10a46eab3c197ecdd28d2a55eeff76428e0ca349fe041ce3fea9f51fdb2fbc6c",
        "c54c390b651d89a502430287d5e2a95d60e7c812e976b469dd5a02d23a290e0d",
        "52464e7fd18bfb54060ea1d8a865a2a076d0a0ce5c00713fe560f3cf7fe9d8df",
        "33ed046d74e47e4e8f024c587d4e8007fdc57448a1a3b7864994c0600dab6c39",
        "367fcfe6fb4a02ca6a47b88fc3e1b7e946b19eadf1e33c0ed45228d58d029672",
        "1a83ce94652501337208d311869a7fc71af983d15179c4c8249f635a3f5d52ce",
        "e50385d6fb5b8b88f89021c00021becc799f2df579a35d1152e742458605510b",
        "a8f11d2c6fc369c25a68f6edd7544a24f74a03f679b552ea223f7cdaf2aa828e",
        "c15c4c740409c515c6082a0741135b047b9ed76450e504c7d85a129036246d03",
        "73a82379f52615187afe71a085bff1648389b2b9682636dc0730da721a76bff0",
        "abc53e77976e757f4396404b5da39311bd3f7c6860ce6663b97615cafd7f1b23",
        "009cd73f529e5c49ff98896f4795e847d233c003dc56c75de22f58cc69768e92",
        "5859d214ec171d3841acee2f54208bc933be4b35d1f85258152f25d8d0afeef0",
        "c44461a372c71cc666d43bcf94582b01396a52351f68a98f8e6b7e709ba117c5",
        "c141807c088727eeb2566830895d31391af1aa6720398f1560ecba9f5865540a",
        "86a777f3a3a271483e0732b072ab4ec27d995bdc6fe24a72f6c3e4a19f2382a4",
        "b93cdda4cd9f68338abbbdb9508991938c6ba331749fd430f073e210dd2c3370",
        "dd7e8243337a5054edb3db5f4075cc5fb96ba83ae5281789d7466155c3624bd4",
        "f31f87fcb81276558ad214ec535fa097ab46ac0884d181a84c1b2d5aa33fc57d",
        "774f4135dcec6b892d8bc2f4062991fd4abb7d190ad8f866a66dea56a5586dd0",
        "e46e10b67d672829c5c5c60936dc913ee5b3e52cf1679be5bab48a817948aa27",
        "8775533b62568b63fd9733c951e09cf4de57c9f1a723b2d09a3467a2a970a81d",
        "e9c46e6a50b3ea1ca52e3f364dc9386455c0a364191d060a58ad0301b7a1f23a",
        "f8f49334640ea412507eb90891fb0c58e2b1d1f0d46f439c7deca0356fc754c3",
        "564c9159173c25a01ad9ab6db661bbeb39c03a73c0de4f6948ae66849bf9a80f",
        "31e9043299b3eb733928554d1a2fb3a64c78685d06cbd938d1d7741323f8ac0f",
        "903e85014b309bf81a73109106f465ef1c17015d9971c5bd59e668d8906ccac1",
        "58906c0d56bf8b626d4da540b3d82a1f9ec9b3c9b28bc588b68852daaac98b75",
        "1be0c2a70899cafa7e7746b04fb5c3fc89a5d0a83eb40a8acfb158358fe87690",
        "530ac8e7e05c8a6575d21df6b5dfab33b71feaedc1637a010d5c2439b8747dde",
        "b00a4f2ebf79751fbcefe3ba575f255d031781417c196007d590735a83392ac5",
        "bdb4b63a6fa7969d5ac4c8306586bcb79cd8b428c6133cab0e8799bc3fa5d832",
        "3079352a64edf5e9fce52f05bc8836225daf127661aab9c5d74afb4b73220d46",
        "be3980aa2f4b67cab28fe1d0565dda5486140c6a8a745b9cb02d1e49a4e345a1",
        "7e7394cb31867d2fc2c190739d517a8ce005268c7ec9d77101ddbbb319b7c53b",
        "78afe0513954aa9827fc5000bb8a0b4857fad1d0b257fe11fdb22d4424e875f5",
        "f8e0df3d621a2df9407e494c5ba31525a74845ce76f23df734c0842aeb6da0ac",
        "042ae37c24fc0ccfed00ef6fb0548a64f7ed3706df8bc273eee8a053e6028142",
        "4d621316d9b7e5b5eadc656ae5860a0103b82df928675b186f022b7b941a2eeb",
        "1cac5d4d73075c5f8aa8c2559456cc49552ff6edc72aaef0c27fa9cb8fae547f",
        "238f5e0a1228785db90fece634fe80039b6815545bb75ffc01d995327c259211",
        "51c951512596216bf19c39709ece3228534c284d68d39766641e1f45357e70bb",
        "f38ad18e610fe19d8eca3e7d0e5883f59cb79ef59dffe0e3a350f3846ee4b29c",
        "08f0f16905557e00fccdb13e48406f0921c7724964fdd7d9bfc58765d2b2ae3e",
        "da41efd5477e11815cb475b2ef22a217b3d57d210c582a3c8247abf51d36d0e7",
        "f2ce8c6438b52d1f2f0cbf0f4005630b7dfa39fff454f5f357e70d0d006109e0",
        "5118e373efd97daed8219dcce9be9e392af452aea2d2063e67a0aefa56f161df",
        "8e8607a3028860f90d1a7a087c18405ebfb2f1aaf3347d89ba86e3e99abf2e5a",
        "145a3368da1bae15abbcf69fb53f694d0040764aef56c648855051b398c6ec07",
        "9ccdffcd58bac657e40e915d9e08dcca3aa9ecbb6900f894660afb853ea2e8c2",
        "227e55abf30e8dea9de4764dc55443f3ae78077f419fc62561bf5360b82192d0",
        "45d1cb1b0b710c2c25aae6fea2393d2d710e8614dca6cd1258f59a38c26de6dd",
        "0fb3d65ddfd0ac671f05a475433a94eccb91ba8eb2bcaae3a2e2b1764d533f8d",
        "ff2374a29b788345804cbcdce4ae099e10ceb7219c4229dd4846a48b21f01d59",
        "34e48efe07bae7c110ae9b23762e24418f3729751638fd7c02f2ef70b01f8825",
        "45d30b4fa40f26dd698b9ed9fa0aa8fbe0a2b146a034bab9defbbef319b20995",
        "458f1b97e9e5200934b998787a1ca1d65ff5c929996fff8c90f57244b76a2505",
        "4ba5bcf55ac65db227645b12c3258fc19d46748440a15bfeea2a255d2fa2e437",
        "33553885e44feddc5b00a7df50161722ff1284aae14927de05cabfadc2ac8280",
        "8c8b97b2b83539dc278ea52688a47a4f948525691bd4182ea0fbaf0b640d2feb",
        "c9af08ff7d36d2d1126a5ef9224fec56be62d274daa05c8c7731ea1fa6708a52",
        "eb7d9381f7c4e015f1271a9a4b9846a7baea86c8d96cadb6cb82d4460cefe9a6",
        "c160c0940e219ec7f630e2427fc6c8cf1f369920d0b66d14ec2a9a4110e167dc",
        "f709b13516b82595eade89b91019ebd84b2496425e54ce5999a9cb47b9725ba8",
        "da2c180bdde3179ffe2cfc4c7a9723b41af6c14e741bfe71c605ea02b901ecb1",
        "35fb58d6e90cb5f37ad9a2447f88e208582451c91de8aeb74b76a0469084c352",
        "1c4d9697465005ed74e6e7994626181e9f7becea3dcacc0046eb938c2fb23a0a",
        "ba076db968336db3e4ba683c8542da3513265c65310e3bab35b0ccd661c8b9d8",
        "a002af7dd1fb539228defb74667a238ac1dd80f4ddbe0ca088ab8f45484ac3e6",
        "7a2ef81b1bba151ac68ab0adee3905f8dd63eef70da33dcfadbdb82243718f7c",
        "ccdd3d5d132683fe08daa341c2295828ce19c9dddca3dca7153a15bffbc1b596",
        "b3ff56e734954ce9f9beb9f39702fc353e7f9c072d109eb5cd6e003fc6b3000e",
        "dca057b152db463632804b54da1f99efb2479fe70f360a3a9c37c4d566a3a9cc",
        "30814e13d8c9f62fcf3a1e5ec61e62d41cb7977294f73a01b6f7aee28bdbad99",
        "6fc576c53341c505d4ccb7c253bc701440bb8f37e25710dda3904dfd0c2f2ebe",
        "a351d55ca4231345ceb17624882594383dd91f8320c44b8e6a9b22646d0662c3",
        "99667682673183159aa4d2ad650d66a430ca31a783857b17b5d33c1607b80b39",
        "7b7e2d411e02971ca3119188c63f7742cadcffabed8c4680d5a565b1f0190a23",
        "fb710fa5e7e4434b067332fefb2c5a9b4109abb4c6ef3221e064f6c370d5d58c",
        "741a35cba25e3e5104bee0d061fbed4f7ae07e04c95cc00e90a8fe375a296ca4",
        "ab01815daf25547b3886f633dfd28382c5ab80f0f5a7722dabf22d2bf9ac29ef",
        "383d1736ad7e38e2f6de617304b2816a879fa764d5802cd180fb1a03236305d5",
        "bdad683e7d66b385e1b812ebc66ae0d8bfe37083ab75b0efc5e14468568228d8",
        "4de75d938b4e56ecc0a0ce7e652ac821d9178a53804cf27692663acf41321c33",
        "81523d4b966cf0ed25e257effa9caac78562cee497d432e7ba46214c0f5e63c2",
        "93179acf00410ac9c489841c7ef07753ae3b6b198d6eff9f4ed1a239c062bf5b",
        "8c3692343ac0bd25a61b48941bfe579452c6818a0797d4e4945f6ef7691bf015",
        "9f5c088733fb1627f4df8eebbce07c38c37e225950aafe0d48ee8e87a1b1d25c",
        "57084a8d715213f766a682317e0a3635535dff9c57e8cfa0ae2824ea2aa0d9fc",
        "ae1d7c6dcf7fd60d3bd4d8bdb05f7516e3576b593916e768e11f4caa9b17d24f",
        "dbeb7ed59bcd898b52dd8889dd088c710cfaa586ad16969119806cb845e0c577",
        "3a9bc4c67a49469c0a242747ea2d3632286a1dda3eba9ff31cc446bf3b95611c",
        "87b4ee7d9a80c4f5a5ae63ed478a4734d5c6193eac61a1a951db2318b8bbc44e",
        "9e8b1203526ffe058ab144c71c74d2535f7a59c96d40de9fb85f624a845d29a4",
        "b61d0bde10e85dc0122f1b20127d49357f0bbd5c395bacc67d6fd05b19681296",
        "b07d01aeceb1a0b01d0669d15c12f3df1dcbd9b1522a748edf8405034b4672bd",
        "0ed59d103b791f09040cbe21fd7cfe4a9bf71ab3af54dcf90110c04daa5424a9",
        "42542d9111b72e6333872629f1aa3b553cd80ef25cb62da7739f7e1071674f12",
        "4b683b226dcdecbf5cbb78592c2b380a757a7496596790ce525685ffe15c5459",
        "4ef07794bb0d2d668b2ce37ebeda439d4ad8182ad0e1afb2befb6faca933856e",
        "82ff68717d9f6b838dbad3f6649ea8ce4236ab6efe99b1515855e50cf99821bb",
        "87936a5081b9d244b9a86f7f699fee9744d2ce5d3b9775df9a4ca6b1d1def133",
        "cb5d96d5c9fae2038ca67668f9fcd6a16976cc1e0cca9dd6e171140b9e10d0dc",
        "c4bbfd07f984721fddd311c317484d0c5c206be1b700e7b3e1fc2a3a6bdb0f0e",
        "135e4246d60bae7ef18a7395368e7b0cbd50a4210638a4e60ff8bd863ab9e95c",
        "b1ece3415413735e54dd789dd743a6820c1276e37a5baed614f8cfaab85bd1df",
        "c57248ba93715b527cb9d277498fd1d2f87552da9c20768d1e4cecf98eccc495",
        "0c681384be7b49324a0ee46845032f98e05cd081470b7c5e702c95220f0f0e27",
        "64f9431601a895966c31955d94250d3e982cf333b9cfc58b474911750f94de1b",
        "e77eda1467706babaa7462a6c486e4136eeb182d3261019a9a148670fbc66975",
        "2cb800985763cb7fca9f1b8cd3c6b2b3aaf8ba35cfe6828e5c9b5d11c1234983",
        "974a772f58d3f4c646c9472c78d8fe0d3317a99840dfa4f7ee48f5d13b63b21e",
        "2f3b548e0239b12daadd98ecf4080089cc37211e29d4ccaff16b95bc839d0ccb",
        "9ae6f71d58ef04bdc1bc97be062120acac90d1b100de9b3e20ef06b2e4b602c4",
        "d777a68dc9feb52ffb9b71441dd6a98c713bb5d33eb3e8286528443e13fe71de",
        "0392a7dcd9cd61e2d01d9c9b7be134f995a3bd260c7618c7f63b6892723ee715",
        "d6e84aa4f7af10a5beecbae01c120847359ab5a0ffc102bddbb95d38297e39d0",
        "dcf082d4fa0a7c0aa640a3448baa28987a5c86b2dc75adaee18e9d9d39c371b2",
        "12e2e8d2c9bdd211bf8926f5efb9be8265779ad1e6b7ce329440f546c7227da8",
        "5d35e67455d911fdfda09eb60d9806d9ef3a3640b7eced838725031b113967d0",
        "54eba39878f6b0cb7c678b3a89cdd191a12ec87d90d881940df1f5b06ec270ea",
        "a71f62bea653c455fbe97d55b9102b8bf6e4bbe28b79f6fc28d37cf5726e8e31",
        "c611e666b12adb7f46e9ba2829b6c9c771ed4ad093a20a3a964d65a07bb9afc8",
        "1da9cb88281dafcde59a9166f3202b38916a1ac4f209954d1b96170eb1cac1bb",
        "0cbbfe1f9481a982f1584f2d83a21a96bd92fc712876a3fe53610e33ab76d582",
        "0e33bbc7a5905e12ac4571028af3d2bb92ac89f6e55ae2b6305e51338b1c479a",
        "6c2660925e90f9a1ef88024781330ff000d6250435dfa33e8f74ed0b1c798f1b",
        "e2371abd8b268ba520978daec6372d988bf7b8a5f5c488f4a6507d0351a4e634",
        "85a45cc45cca087ace11151add57c68dc3255842f84e3dbc79f627a37cdcdff9",
        "ab640818ec15b52960e76b216a12ee76999b09593f96f67f40aa1a4bc4616397",
        "b49b02aeaff18efbfd654a9a7952e026d3c746460f89c83c5f759586efab1563",
        "781807bb9d23140766954ed3ee5df3870ec506439eb29e94b37b1ac4c409325f",
        "940b38b8c52731149a6dd758642dc0a18ba94b4cf363226e659c25a2b339b9fd",
        "3549684783a70c679e3c6890c053d6c456bf422c9f62c7debde4c5331aa0fa3c",
        "4604a8b0644d0025dd417c6bf0f72826e1f991982254d587580e1c0084f98018",
        "283ab213bce19a8998e2d77560aeea3d30c18b30f7f661bf4a75cdea40dfccbf",
        "698d1afba45de6ea07cf4738fc63e6af3acedbbb92647ac5dab4031ff651b7bd",
        "8ea64ae6e9698b2a03a0fb4382d86ddb22ca4a1e1e666f19c112e7a5c7c7d5e7",
        "81760bdc4e5a1e137c525fabed43cd7d9540b52e81b4d7ffefd160c19eacdb13",
        "a4d0bbe499ee1dff51796dbe569927f296dc25edbb2a6eb7edf34c50f84966f1",
        "87bd143e6e8bede2d9686103480960c7510b0342ff94b80668f629cf3d19e04d",
        "635547007709169b96f09ce8ac3426059077d0962cf006e34cfd1e1e7e2063bd",
        "8f0168afe23c40ae87ab02a04976b80273acfa9acffeeb3cac268a2a241eda6e",
        "623e12fc397e7ea924b26bc2950fea8c1c8988d081bc1d9ca355351dc882681d",
        "c738b523e7c7400cb8e5ce2472aa12a6844b1ec0f189f24e81456076003807c7",
        "bd385502d0b436eacd61868a253ace8fc0f827c828f384ab6b831426572c0572",
        "d600076d2e2976a84c11f2fd114b0b747976f558a22ddeec9c7216c08e527937",
        "1297efc5a17cc9fd538b40527ea451d895564082572df6b67c0e286fd37ef4c7",
        "92da666e52fdf63410b5a8741fdd0f22f00b36812b274406f69ba2c97d6710e2",
        "6dd999b619ef9907d4d11d754da11416e1cfe20342190de8ac933b5e3b8fb004",
        "8997d949a6c9bed5c984ff13ea42907a56db11896290d27475a3d23a53ce1785",
        "b9fe5481563e127f72b82db48712a709a6a282792765f9112b13e85925ead67f",
        "342a359393607a7d3fcf5c398494a4fc4e4808885305f2b3d66a28c43aff465e",
        "bf984b044f9e0c7eb289d5c4b918991f156032029e55e2c3ffb9a3c323b04989",
        "303551ba204f85217396d4446c19bc622ac3dd5955a80035645c4b0f3f754ed0",
        "800a380fd39919ce2446e19c2ae7d97f7e66161debc15a70b08b4af81c75dc81",
        "c987b79a87de8e0ff9abdb595178cceec7f851512d28c1d4d230b49b1115b440",
        "4e94cc79e0f1d971b112f25dd296ae3283c06eae549af8f5c8ed2b4f564bc152",
        "5ab574eda2bba1ffb224a29fda4316dffb3497f90a88267064534ecd21f61d6e",
        "2215903d034c1768590c53ccb5585e37a68e33bd3b643c2b508a4163a18625e3",
        "470889a3e9b06b3886e383033fc2dae2633139d3e3eee874758af8a6370008ef",
        "83fb01f1f05bdc5da651ee42905ad77051517292d1ce5c1db82d8ff0959fda5c",
        "c37ffe8f2bc074ccdd3551b9ca4c0c47a51fa4f990263e4350560f7ceeaee332",
        "005e07d0bc6c91de52bdf2a1557a540fc073771b87a9ff8045945ec64319c279",
        "2e4f9b0d629a27b73d90eeed9ba41583c8f8cd5ab5d3340b261588b78a0cdb5c",
        "f749face1c0553a63d8e0a0f05f35c42f3e4a3f43308faaf6bfc8541f7d7c883",
        "55e93b570459e4480569a550d18690cdb0b7b521a00481026ed737bc2ff91b87",
        "0f6002fede02d5b8757e727eb6c75a36a1bd98c107e907dde0f653f224a86907",
        "963680f5386e9cdcd56d116d424135511722e89ccce45b62675e94e7742c7d27",
        "90934d6ef7b3d872cb9d84ff4177ea9dfafbb097c7b33c794833c9e9a7b6f96b",
        "052e7e0e929599baa0a2c220a30d4f6e3c83daa9db413a1c496d3b2a44098477",
        "c2163e96b01472999a1511c1b55c4769dc22fe40abc66c9b751e4ba33ebd6551",
        "3c1c148740ff4d04ce5531462292b9a1d1a8642455b05422f5441591f659a253",
        "7de14eb425c31b9cea5327c428a0d9e287c8e218271934913850f2427be366ae",
        "2168b8e53df52bc7d17e4d23258d0a588bc5f80c22a5fe801c5bee2ac6af36d5",
        "ef59f54460f9b9ac4d6820c1de001f537c7861c15ccddc27cb11a5b1c523bfe2",
        "3b741f42b177c3bb1e1dcef2d6ec936e4c47c37203e599ccd6fae0c65642f23c",
        "dba30bcf7eee5dce4e4b6ab99ee50ea6333d0c825845b403983564504a3b52dc",
        "49f17416e64a7b9b60c58db9ff81bd4f474c5097aa76480b454ddce1f58a5314",
        "8130b3b5fdbfcfd8f2b5a010838fd0404205f6e351ae138083b90c4428ff27f0",
        "4402c68b8ed78188652ea00191ebb6c6c711fd99728839484c2c7cfa2b57d0e0",
        "abd8e5a990c39a536035719d16ee0bd27eba593e00a93ac51b0a2525b4b5f23a",
        "c90743dcc067ca92073c88f82d6e159fba4baf19db4e37af9b0f577034a361ea",
        "52dd2e2f67bc1b6bc3859b659778b3d83e14b6c64b706dd8331f66e34830197b",
        "9e5ec0800d81c68c2de4cad0d92947f7371853d18e8b5f7f181f1627f5f474c6",
        "bfdc698b07c1824c9fc831824706c0cfee11bcbbfe3a8c728bfc8914bb8102f8",
        "94bc54389e9c196b75435cfef626595f6456c9dcb813b50c1b97318295d03789",
        "cf5b78e46386bdd9566e0fc00c859ffcac3df5408bae3f94db9320295fe9f475",
        "0c917f3f8fbe39bccabae56258657bd050e9f9c183d33617e2943e55a7d8137e",
        "6d6dc47c62a20a1e76814ca0c8f1d2faaa450ca6460971342779d8d6a7b0ce30",
        "e71ec86a19da3d23d2d2173471982d9d597e9b5a45e53b45db58c22ebc6f18c2",
        "903a07a8a59379349bc56151647218822aba5d00c6c378300f605a58af60949e",
        "b5027721d305fea559f113018b06c9ac4a10c4b7aa30ca539a323e1f93c4dc2d",
        "104791328f31784a3b462d65b8d5e8d56f9b829bc1faf96e7ae37baf96c48f70",
        "841e6d42b51694417a831bfb218f268383ec78d06da7f1e86ae5d7275938a72e",
        "cefe5501077c460ac5a95e25be3ea9ec70224baf7e34e9de77c127291339fbd3",
        "146d4169ae431585faa1de61fa2ff40875f38a89e341e2f873be156888db02c3",
        "ec8cb3edf5f55f1fd2246217279fe86dfdcf215189467f3a1812e2cbdac3dfa4",
        "e50293affd78b6e7158e1f6d2e6161417604226c720f7e6a4f8e622ed6c2d713",
        "156cd8e5976acfd54c0d4f45bcf55eac7ab40cbd3e7d8726019520e3d4e63ad2",
        "8fcf65bfe925f017fa614f7c3dcdb31ba4a16fb5b2e36b8e813a2ae1a3335ca4",
        "78f13eede78eb8b34ca87f49eceb7c157b2b465aaebd239df45c8cbb11b68dc0",
        "cf4f4a32c881ac6b5630ad5b8b6a7352f9e386508aba9de90fa9c48063396d45",
        "ff3d38c0190141c72b1cfb6f866bb7fadf6b56c73d867453ac2602153117ea17",
        "c9a0bde3c8dc93b65927a7b163f2991d6d44fad2b3959dcfb56097e2ea6f04e3",
        "ae5f07e89f4b90f692532d46a2e0d908c74ed90ef32eef516d14b6f4b4dfb8e4",
        "63693d678526d12113e028727217670a0b43109ac77388ae32b15dd5d23722d7",
        "5dcfe5b486b68497c00a88bc80b422b0ca2fc92c2950392dfa56845b97bd537e",
        "6084ec17ffdd00bc6db49b5a2bcee0b5ad57575ce6fb1fc5d80d16e2c890b790",
        "f787c885b5877ecb25522a387173ccf856893b77f6570a57755ed472aa04897e",
        "7366b2bee72f2e7abde9201e00d647d02cbfa3aa196ee90350a0ab9262db9b00",
        "0427e1b2529fa0e7e8d19b0e6899da4d5d4fb8d0301530e6c9099b2b91fc783a",
        "4eda5f853ebd841884e6de665e0f664f9e39dea416d79f01d8f02f2bdeb865b6",
        "33d34d14cc31e02da6c95a5f02fc067a1275cd8ec422ee69f4ab71a7157c028c",
        "49d2ade2de68cf68ab5ff062dc1181f7848747d93247a5d8e902fb329421077d",
        "cad8b815b9a52011ed140e6d0cd1124567d33773e4dbfe5eaea0435da05fcccb",
        "267a4aba6177765328066ebd0b34fb82655bbae18fd3d53fdca4bdb6b77bc565",
        "f58acf2a0e74045597cfd1d4915b51af25b940fe0b8c903628f60821a7d29b31",
        "2eaa1fe54c7e3cb7254f22e84d92b4e33245ac98164323e90ecc4cbbb82b01b5",
        "778130886f7435ab47a47c8359fa9dd0216e76f8c2c4f3d2e639f711d8e8abfd",
        "e6e77ef35eac9be09f2744daabaeaa255695da6708b73c67c78ad1c818a468ae",
        "38893a18e6eeaea1b32616a9d127fe225f3b71f1ac6ef961c233d00a69cdd3eb",
        "3013147443bd5f50ccf57217679cff11fce8659b0fc03f037047084c27a6c92b",
        "dd3953a96aa3cb3b4f606280fc33d11872061ae4552bafa24a7025886089ef37",
        "11ce58abed7fcb8b889246ce7ad4bd5806bd0448079a2cf36fc796fb19b38972",
        "e1afb4f3fc598659836bf65a4ac86efcf1b7d3810840af0dc4668bd6d43d5c3e",
        "e46e62a9c4fc8bdb34713f55c084bd7302e22c51716c4654ed832516441ebfb1",
        "41293ff45e13b0d0eafdd9ecf155a93db75b00e330cc3d4ce185f11eebd6deb8",
        "cbe8ec3b6917cd748a2651f1082469be0216397d478c38fe2cf2ac34cad57a34",
        "f89d8ce38b7d9177c62473c0bf4dc1631dec36d948adc77d9c44ca13c0c13ef5",
        "145a0616e924541d0d7ede4c9cb966a8ee7abee48476d442c2b01e796530b6e1",
        "ba640a20a576418ac36502d99ecb3ac7263320e3bcde8f9cab28951d975a9b95",
        "b71a640e9a79f5add1881027ade67d1e53a13585f8bed22139f02ab6dd7b5a86",
        "042d82df026cba94b300847be329d0e1fc79e620d50c7f9222892ef3951bc230",
        "79c1da5c7372f237e4ff89b23abbb22235322f5164f4e6005a593a59f13ae5c5",
        "5098ca1abb59425dc84bc0182f0f5ca2621ae3942a95cff6369c82d4351908a9",
        "127a27df6e945b8f0efc52e072d225141451221c4afb9f15a43cc30c9cd3a0dc",
        "b1f0b8bb539a4b9259629dd8e01f8aa42a8c43eec8f68bb40e29b05465f3bb02",
        "698ae966ea3c680d0a5c281ce003767196a283a726a5fdc9dc5491aaa3a5216a",
        "b732bb2233e4ea118a6ead7b709b64252555522ddc1b891cbdd4f11ab2788d28",
        "9a91d6b94c56bef1affdd767daed42e4d0aef2b9cfcf9c90db741a604b071d77",
        "0a7037c987d44a5ecc8b90bb48219815cc5413ade9538eb6c52a5568e87ff4d1",
        "d4c9837ef2fc40d90d8806d85d38436b46f560344342e341cec70279cad8c7d0",
        "47776274bcfaf00c2cd355e7b9ac6ef02200b67fca11b192d6324e9a4e2d33b9",
        "60317a57592145fbab3eb9d35043cf2b0f0ce12812319849640d0bb9b7eaf9f3",
        "8295930b5cd26d830923ece74115bc8ab07c1797ad5476a2b13ed76b41c9dfc5",
        "de88a01cef3fd8b4552b381e62afb63d861e3509968ec639afa90b1820eef9a6",
        "ecc9baad150c2ad93aad6571e6aad8e8a9b1ae51d77586adb32e844c6f59e80d",
        "7ab8c5d5ebbe9aa3cbb2d06bcd35ca49edf895af13f03de1cf0ca674101e406c",
        "f2dc1f11ff1f51eae47114099873e54de9ae1080be7fe8466350a96ba723501b",
        "6f31be2186131e190138734c8488ac18aa0ea19055ec5575b756c834e7d22f7c",
        "ee69838589047cee88f2f0145162de9a684a863f50fb262b9efdd1c0aca64d8c",
        "319567e0935c3f24ce1cb9142adc6a4776e9ed70433572a536f9bec30e5dd5c2",
        "9b482106f1583c00e29c2ec964bb52d693e405b5c83daf2a3b7d8dc1aac1a049",
        "2897640f5ea47b18a447b4680ac71cfab0c0a0f88c69cd6d23e53d372430bb09",
        "1354b2b1dee2c51c4431b9077d74609bc558dd2724cca45ca54c0cbcc3e74f1b",
        "1f11a855826f3b5970471b02bedffe73a6808cd841e84f34b669b1e723d6e7ce",
        "573726364121c080293b6c241eed0a18ec82b3b19abe4276e2bd4e199c6a4e0c",
        "f54317cbb1cb3cd79ce41165e9219ea1f246cf573ac44b17e1a696a06dde2fa9",
        "0635799b4c0dada4ab21db6620f9dd76f4b5a689f28b74fc4e39d8470487d2cd",
        "d93ff9380ffa06c8d75a7733a14ef252dd0701018ebaaa3d1e2fc9e39aef3b6b",
        "5bd9ac6d448ee63b9b37a4f72b06cf70223183660db73ee01f6ca0c19d3ba29f",
        "5ba02b75544898ee1b40202fa766f22d9e8d77f005db9ff6abe3d0ca2269555f",
        "c04b16216d059cc686b6b856c9c2511f13a2036e1f81085f04884c139c494131",
        "8eb5e2287f40a185a049b7ffe55489bba574f64f498d032268fbfaeec83eae93",
        "27036d824d3fb23d0c801f44d2a19b4edf2883622385a9fe93f9dfe968fddf3a",
        "b79647a389fc8aa56d467e715dbe72a5f9c827d214f52b0b1757fb44be5249cb",
        "1079e4919e5242b15fa1978ef952f57cefdab4a632cb269c4d42d70000c8282c",
        "7da5facd2dbafc385d33aee1f5cc200a6cd08cd60dbd563dedf8639fec22f234",
        "f6d243d567dad07842e7b1501428ac2cdcd833db1b92f7c4374b8dfbd4e39818",
        "49203a9abdae5a75e94cb20671c8f9c60d47fbf5a4e20be42f7fa3f2be72e4e3",
        "b4133625b6f8219b2eb4c313f2307ebc533b95484d8f61ab5cc5331c3852eab4",
        "1d2eeec6d07a11b9f6485aca8df2ec48c7a21db1d2644653d987e609ee6f9852",
        "49bf24ecae0e19bc8e0bf3ab8b09a95dd62832049312ed62fe914c3ea4583af4",
        "b985cf5f9471b90161430a0af2582500cd0c2029b606eb6ea7ebe76838964fb6",
        "6e6be840ef4299a41ca50e7e720c8aa1d516677cb09a96a6f6e6ffb3fa2b6d58",
        "1eb8d1304a60e4f7f5056d9a4c2d219760428fc68f6495742223590a86db7bc4",
        "efef946a1890b94f227a1e8cf53511c81ec9aba3718a748dfbd3e26b0d71a78e",
        "3300d80a716c77966544cd95852c5b0c96a08e59ca459ae9f8b071f6c846ef7c",
        "24ffec74088be29db0300f84f206041e7f580c49db303cd1d20edfdd76bf3258",
        "4862ba336f494c4d0c1c7730a3bcf9cd4c1a11146c6236760e3f17e0c9ee97ce",
        "436572105c2bbbaea97465b091a1048a25832bd98a64b116b448d20e470cccce",
        "65f59a96fc0c5038d296030fbe63eb8981cda7ec4f51da2d2474894e7f8590d5",
        "31078273b1f975f3921a92b2b5494e16bd0e9b1e77ae00f1d9b6efebc87130e1",
        "c5110a858e032cb1ef66cb1eda49ebbf79f5ded5cb9d37a34a11709402dddb4e",
        "7e073315768690726f3a0af8125d7697e0666131e47791eb858393fcc948d1d3",
        "e93771f92223e88cc96929fd5829931da4b53d2c5a37c0ae99152641f4e83159",
        "7aa3dbc2667d25eb8962b6c1b511535f43ab41477ab14a7266549197fb45ef78",
        "6e8fe73d35e9541a551664e908f95850c8b6f94c86782d1eb65212d7934382ca",
        "d98956eab27e0f60462f73b9d74a1b2d21e9f6375978e415d7060426e963b5a4",
        "1f319deba8fccbd6cbc72135ea65023f2f970b0b39d1efdb4e8d109207199781",
        "ddea2efffecd176d725dc91458ccabbb03d2e611e838cd19d76a080c4c639c78",
        "b0f231225b63cbf09f2ef76a78aa27eb4ab3104f1aad88a221a0195c042f8b77",
        "4790149dabaf20f6834158dbf3496484b60835eecb194bc04818fc918f71f34e",
        "7806e67376b99b9b9fd38e8d03f2c43836f20db724b4f0d0dece7a1b9c4cdf47",
        "e392505385f62e6eb07509a9ddadd512e27e201725570469a5f1c9f9601adbe0",
        "b222a1324f864c964b58c521cbf3c7e5c8ca63cf1bc6be1e7414d91bdf4b6d8d",
        "6184b28715f372db52da8b803da2f35e290b371f5ac8b120f9dc32641a91edb8",
        "9626f9c1874bcf4892dcbafd382b5f0ae2c4e9136b838165dc8530c0fb7274d6",
        "206e457319eaf5f519e170a097127f1150be259fea3c34d5b1d90368ff92202e",
        "27b5ef107878d3c389a75dbbdcb4426567332b3acbbced1fd567d4fc4bd5b125",
        "57464e4ae33925847b80306beb461a3e51bed610d2c9591df2d6d77bc20e8db4",
        "b5e6abadb89e70b39e388bc86b91eeb099c0ff57a05ec167b841333ceeaf7946",
        "fa3fc228d9138fcd2c06833053c6e4af955953d1d3a56d2243c711e54f47d8bc",
        "3d29f7c7f7780c75a1193a646ace40ef2d806a28e7b1cc38d2b4e229f79703f4",
        "86ec625a6bbf86eeba7420c177b06569501104dc8c67b3be4049cf1401a29b72",
        "e71c749d7db7184bc73b44abe1f97040afa37920a948c22a30a3d6cc9a038bfd",
        "5526f2867913788273bb1e698707322f777d4a44a2b164558e9a1f19302264b2",
        "6777e1717b51e0906945274594bd5297567951c788f81fe4d7cff5624095b0c8",
        "9e595aede6240f0b818a293abd6956e093ff7826e90fa29e230be11619f1ce03",
        "8a06b2400ff14fa5716ab554675b3abc63ace9499c7239086729514f8d67ea0d",
        "eef7549b3f9472da9daee729ff3a44c114af30b08fd50d598faa1d63e313cff2",
        "750541cd256c074b7ce25cad3c2cb1e3cef7941d0d59108124681bc2eeab5606",
        "d4b8f1d69002a96afdd33e4a1c4744b69444fecec11aeddbc088b5435406035a",
        "2af7e98c9c4cc53f1a001d0db5352cc095515f77ed6d85d6f648dd40aa229a86",
        "464fa8f0cbc3547886f463bfe684084d4a20a1bc48e3b2dc3e4800311f52bd3d",
        "c40aeaf5e5f2d0efd406581c523a935d9b5b099b8442857671ed9a1626ee1da8",
        "b1db56ddd1fa93c5757aa78fc8cada78c031f05dd4c9bcfba0520033960ac07a",
        "3304db0f51b79b4e65d5e9031eb87f20e35fe3e7273c5199b342734cc89b39d8",
        "4d850a770d2d09071d1b32ba5a542895d093cf687d4ca1b6438a3acd6442289f",
        "84f9bffd7092a8369ae5fce84a2aa6ff43412f1783d60d9441b9df5e473057f8",
        "e15b0d7d6865e2d6aa2ecc41b37ab019897099993352aa65901be1693a2edb2b",
        "869bf88a6a9e247627fec3907fa294f11364621c711081235a5f77e347946048",
        "f12233d73bfdcd0bfdf6aa66120cd0428b515f397fa21d045dabf7322af7dae2",
        "9850c71b984044bccc6826a6397135fae571e9de83f148fed58c5dc0da41e7f2",
        "666b00dfcfd4c25114e50be077b36d7a64f4def2ec668d1544e5edd843a23440",
        "15ad7f4df8c74d568eaf032ba44e96aa436ea020cc4e1f2908d692e8d46ac84f",
        "dfe84ca9015d1c6897b6953c59a6f4fa9f320163ab89fb40659468f6261d4364",
        "550c4cefbc1826f13dab71b6b574f9afb155977d0628286f9377bf314c90b104",
        "a8df48db1a48806d8cb867899d46beeef5b972f62d818674dfef88dfdd5bd7db",
        "d1b68b5fdea47abc5078a5eb334976e4e187f8b061cf93a0c23f4448d536c31e",
        "ef73762a1686b916f22ba0cfe085df5b9a241808153cd827d0c199563a65a869",
        "00d01d9af5187e6c28c01fce0939446fb32278f235581bbe25341190e1003483",
        "85087b930b8fd71e098c56733bfb69950771891282cbdaef7b5da5fa963fcdb1",
        "ff9ca88d708f10df2b30a36c79e87ee7a4667117ae59b9ca6b5300ad28b09a07",
        "83930013682d06454f323dddf10a2cb27bd28d5cc81ae24e46d53580843930ab",
        "07a5550492fa88beb1e194b53abc58326256d29c81d2a4bdeedf00f821dfc014",
        "3b63b8d2c9587c4bc3a89aa194d990e50b486dc3220eaa26b8888d8fb27db329",
        "946750c4ba2d92510a3b61c32827eba9a66d961d689deb34b3f8291271c26877",
        "71e7669bcccb8b46c18fb859b453959332e9c7dd67b81525eca25b94b886de07",
        "e054057c4bcec840b9c1a047f4f575bbe87af7daba1eb12b6224b083bd15ea24",
        "f8926d5dd985d9fd2c789c377e53ec2da7b07d2998f202f6e65c21b1d7e0f509",
        "f57f43ab071b42b1021e32ca39e23ccc9a2d12c9f26c76732306cc5a078e2f01",
        "94db76491e4b2d90934406e70a0e3bebc60daf65c112bba561795eadd52397fe",
        "280ba777f2414f6d9941f87e2b7b7d98fef88e8c3c658f08d959ae6b1d4f94d5",
        "1dfdbef3b6d10712cb8fdd7e909cbf691af963f3af5d1958c9d5115b04438438",
        "dd2e0e0c66fc8e71b446ba0488eeced2902e297d7157b4ce593129e0ce9d48de",
        "83eac19f2e152cc2ae86ae1fe8f98ccd8eef111466929320e45b8d0b68d12b46",
        "9045d06767b7bb03d9ca5b87e1827709fa592633b062f711938576f1bd08cd35",
        "31c5d20491d7d091c0e2c689a03e30d11ff33ee9ea6fabcbf99234ad3533c895",
        "79b18e675a6ad651c11c96e61fe22d58de1eb2d1dbbc3f6e2af18337d51bb7a5",
        "cc1a1b8b1913ed6d545daed019a9b0ea0cb66748da71f638488f232607b0d6ae",
        "e2a6c2458b4d1003c35a4f51f08f6f98843e4c4235ff2a4247d98ee5c93778ce",
        "5aafcab494f36abef7c4aff261129186e52ee3d3b0bf5dcc11eba15bce27aa6d",
        "30e1902176edc5c58bc78da97b645976372102d2b0e1cc438a75c73c1cfe410a",
        "39865096b54feb07f333067b8e5fe186e4dd3b7586e213fbe30aca6f8dad1bf1",
        "7f6453ffbb50fc113fdaae7d2d5930ba54bec039c68409a7e5a755cf7f97dd72",
        "a8324d4b3c3bb8482d75099f20bd12e1cf51abcbf4f16d0c99d307b758673e17",
        "4e0f0dbbbb555f00ade2515a7a1283fb429c0def291a68625ac147be703bee02",
        "902c030f044002f9d765ac3d6749de04be3de861b02016eefa03326949e6d49a",
        "c7464962ed196f8d4fb68a0d945c97b6abbe629d4cd0bc67e6fa9918ce78985d",
        "2140ddb3718fa2763e4b8dc01fda1434a098e3a7221b1490d404a1a551916744",
        "d359f95892fa2216af2950a316e7a46030b58c19ee97f0f7e751c06e48df8084",
        "d43250f0c8991cc47d773f086057b394892de2c5d3dd576f183d922100461539",
        "a7850365cc6fc2a15545f621a362405dea283ef7676a34be57c44b4ac0316de2",
        "f96e54272afa2cb9a3d96d06f8d9e4ce204e5339deb078522e0012e091db65fe",
        "6c1fa20ede63c576ddea4c6f7ee31ae274156ea3ab1ec9747705cfb194e19d0d",
        "7b320229f698fcd0230859634935775beb63d6299fcd2b8ccb74f27d32044b0d",
        "7dcd78bac0a4647bd96946a089a87b2395aae1dc9f86686adcccffe05f7420ef",
        "8e022d143bff419105eb0d20135574a80dc96bb9f0e1b39986bbc0a33c6d0c01",
        "c0ab49109fe9d85753709099485c61e05d352daea7bae85e7d7358df998bf356",
        "f03904733da13d6e4d872468955aa119c25e3c1b0e9939fff0e1e9c067590a94",
        "614d30a9183803878343558fae10a0949d401e8037fe9289fde8fee54d79dd78",
        "ee32d9967db0e3bba7dd1d9443cd1fde265051fea2462cf12162479b97ba0852",
        "fe36bca8fd215b8a7e6001e16b3e156149156ac578d8287c5be7bf6ce04f82b1",
        "acc25da87c3dd364196e419a46a2a8734f8c5ced6491d2140e9a88c1c294bba8",
        "c86ab2e1081d20f49bc8f79f45e6d2de1c756500a0a92d2122fb348933db4758",
        "b93cf4462b58b9683e911475817cad18576027dc0c39e85e99df0ac9fc65d3d0",
        "ac8fc06dca75281771635e2d70e090d6484e97e68689ef3d162c050e25d02920",
        "9ad22299ccd6fe3bd45425ae2a4a5ca80a14be4a1a109c4cf29057081f885b2f",
        "dfea57b66f23bfd07107a1da12f5325c009e83021659966a103a41024666d3b5",
        "25a4a46adc1eda55c83c23c1d67a4bb917b87825aeb3e37f99b857f6702c8f40",
        "4ff5adf8405a2c8365d423e706c2c7bb39ea4c952ac31fc0e994ff475c15da8e",
        "602d0a8e34180a2ee8ec4fc8c8ae6655bab12660041b6195b6f49a228a2a4508",
        "67e1134e6f2f588250c2a1123971ff6bfb429820ff6cc173f01fe5f71921bfd2",
        "3ce429fc0a24322eca57982af60e02ee60891af27b9723d5ea3e86367387aed0",
        "27a89aa02ae1a1217d201953f7ab7fe67a2ed37325a53222a65e41c3383a0a18",
        "6552ed89f73e9c90b4f57edd83850bf50fd5a3117f7fa8a539eef9445614596d",
        "134203a98dc9c5f28f863414db6c70b4403b9333301a2a21285f547338b022fb",
        "6d92563f0f60540bc4f66724863faeb85fcaf39957f660d3ab0697add1c06746",
        "e051329aa05af74afdb7a44baf5cc383ab4293cdb71c375440a83de783403bd6",
        "6224eaf4d1154a2aecf6bd9b838b45f3881468f79dd322abda9288ba2bbd95f4",
        "8ddc104fde797f4509fac92112004529aebdd6b7b373865632b598194d5570f4",
        "127bc852b1ff2fdaa8a551940fbd1200ee03098a05891f594b0640847cd70ea2",
        "abf8d85c0577752ff0f28ffbd5a2dd73995d43477b88c22110792b6c52144a43",
        "36ddcd67cbd4293a29516635f80e125a71604e645913543fa79ecb04252300ff",
        "672331fa918ef27b4bf78fc18cf85ba15375585c324c1eb85997e24f12bc2520",
        "b816907791fdbced2bcc4e65aec3a842a1dd840872ddb45ccc079574a16ae54c",
        "1791654a9301637f839430d9e2db790d3a4845c50733e7c344225bf8700d3ecb",
        "445ac9e96e82d22b18b8f2add329ee4d973c52adb87dc8ac99f370f92423ec73",
        "490ac4701468fb7ce5026208b5c74db229b6e47629b4f44903cc2db6186f032c",
        "8c756a91dd85e74b5bfadcae86c407df85f6ff5aa0a28c954db7d7598c1e7900",
        "14b0237d67706febdc0827614b36272e50ce3133e7e080ef5284875e31eaec56",
        "570ebd52340b6d3693969224cc8ef5c1f34b57d9f45f209fdc9715fa6129f581",
        "ff3e1f75446c4e9c2e06bbdc71b787a8b62088299159416fdb72d2c8d6cb0f36",
        "64fdf91c9bec607f6613e474afe58898498952e85d38a2d827aaa869939943c3",
        "9abfae55a9ab8544a1833b1eadfd18cb45d1e2cc681a8450a38c27b8624d8f44",
        "035c112214a0f2f5868d9ab5d6608fe8e612f81a6fd6d8692b227db2cd51fd43",
        "a467bb215a512fa2173e8e17fd1b5db1e0beddfc01f6a2fc159786ac02063c10",
        "61b79bef4fe29d5bce17709bbef59601b0a376eb1c56965dca9c9e9055821a5d",
        "399de9ae2021967015cb67ed6eb16e9cc88e073d4b406844306b777f5730fdf8",
        "973c68f2b9229946fcc4a99f1a234bf872c5db973026a296fb90cc89ddddc905",
        "961441f90cb0dfda79fe516d81b9971c44fd34c81bfe3b4ed25b8f92ef4ac8a6",
        "a97c786110fa83924f91c2ebefedab3f8afbe2999774524d0a445d93fef292c0",
        "6f3b0e65c4bd2a45afeb9b4b91c7440ffe42f5d50ca237a42b86031972ccd0d3",
        "2e5ab34fae87bfd015dc5be506197407bf103093473a88171bf28b069e73d8a2",
        "8b75ff9917d5965f5c2c372bac0d19ce42f3cd5419fae10a0a719fd91d18f08a",
        "e7e3fa39814ae1eaa7e9402e7e60514b35b095130d197034ac73d1713f18cd52",
        "80e875118999f2121df425cd25f452afb6dc8d4b4e908a1c484bbd3ea4cdb1f8",
        "a0521d2e112266064bf0518f2cf9f9a73899fd930f6de2dcbcc2816a03f2662b",
        "9ed3ae5bd533c104788c341bdec6d293d758df3b2b587f32665cb70dca0c64fb",
        "eb078455d83c4708d3d4b4f86bae49a961e8a9d37e5b12d56c6919879108ff90",
        "1fecbdaeacfab764d9b9f3700a3f6ca1acd4c57f38d77a87c94e91e5bebea2a3",
        "687f040ac7fb38bdaf1f427c800ab2be4f0cc29520fcf8cc52bd13c6f8187cd4",
        "078b89dd6486283ce5a46170b8ce1ba7a34bf060bba9c57b69715815c1e699b0",
        "4275464e7162836fd6ecc73a5e21722b325b4afbdfcb03bf9837ba10800c2560",
        "d52fae72a59f0ed3c27656243c5a64b33d7a59d3fdf099359382c35dbfda74e4",
        "260e7032cf9686bcff802e36c20f2ecbb38d13e874afd4a2adf6282bad8672a0",
        "9580bbaaaf384bcf55ec36c6a6c8cd0a9b8213124a275e24682606e280111cde",
        "3da633083a565d69cab45a6c3ae8492d9f80cb7671f1a8f61be522ebdb0dfeb2",
        "4fa86d7633e0040102bfa82fe002a520aea499d5ddb6283102c5eda1efea31dd",
        "6118d40ee599421f0ca08bc9a67d718fde98d65445d5dcfb4b1c3a7019ebaf60",
        "5adfdce24040b30347bc2065a28c74a0e24e44f827df522417a730d96108040c",
        "a1ac90db5e1da0c1fc468a9e6fca200b1ad4fbd6e57f93521097117d8c7fe0c1",
        "65036723e37958c03a5a47bcd340c27701f97b77fbaed4abb4b50417d603706d",
        "abdeaeb578ce05cb763090c188b4912127d95a975df929e5edc8ec9517afd2ba",
        "12784eb78b16ddb6e84ff66c802e419b24484b815cb82cf92929da7d0039d656",
        "baeb547059cf8dee4b82b4094bb1f0b3bd22fde722b6404e56857ee899f8df52",
        "6f06c43ffa7c32fa8d5234695fa05569aeed79f3996e9e83f8976a8f8df48dc8",
        "d25e347c31431180f0592c5f280d041891105f4de0fc6ec5aef11a750d5573f5",
        "5431a3a927a6d35b906f39c08fcafade3d6ef1c4a1564fec45b26921f1585ee6",
        "d8499f33038e110bae729e46ee208b644a0b32d4fe1e5d1fd476253b33cd1f93",
        "d139bdb64d76b8fb1f90651d8dd7cdbca5882c86d28bc0f910ebebbe053fc5a8",
        "0348c8893e5ed977be9054325cec4bb3b71fbdc9d5ff4db1e10f2e34c5c7cdac",
        "9c68c7f3847c10ea1001e49276186635cf5ae03dda2cac84f3ec176315c46f9d",
        "e0e8dd5989c1a99d11206360a2394492b7dffe65d9ed0051cc9a32ee1ce50a52",
        "62bc37993fd10e5ece16edf29a19741496e29cbaedfa7aa5a1226813d08e11d1",
        "eb6ad1d22a614208607885c5b726206c39684bfcf06357e0b28f74a209071a26",
        "b3463d8cec6d98860772ba96ad9451c214354fe827afe8636ae5da74891b5115",
        "17d8c4104f48112a658f439017c7555dd7f79eae41009e8f868d461f1d482314",
        "ea0879843b3aacc8ad6eac8751a08316197fb3f65d0811d006db8f3dd2245f3a",
        "2d672236e43b6273938a0fb182edfd760fa309ea1a142d3b5335f37d22c0e8d0",
        "dc6a909aa4e640ab6ea4372a2602f17e15f8019c98cbc4781c7ccdd5ed116fc8",
        "7cf35bfefb00e3cd9f8cb665d04724813a4481ffe4e365166fee2e2f63561ea1",
        "a55c07a082e2e4ec99cbf55ba2bca17c4c686a450405e5e5fcacc57fd512e5e1",
        "7e2563c2c509f6e73fa18b190c1aeefb45acf0214cb17300c1b199d5fdb5064b",
        "606248dc8329f8187d6b30ffc9c2eb3b9aafa389bd519b5c7b63b7c064f106a0",
        "628f310906cc348c7712e0cd53b01c1471fc77ba335112af66db2a5e609a0667",
        "b3d3322ca1b925f0620531a9042f2658877e7ab4d3bede77412d2f057e123617",
        "ed5b58318a55969c54a5e9083a714429472ac770411c5fdba26a0a076bddf8fc",
        "2d71b7d341dcf6748cdd6512d79c1506005350466436bc9e9684ea4e5561babd",
        "5e3866553f12f10f1f8d07305282e65330a7cd5c75d56a1e2bb8a6184892b23d",
        "a03bc2fe20925da3e3ac525b6a38140cc4abebba64193c24db2e49693df7408e",
        "837da6fbbdb3b4d8f6a5630a310d1c7a9f2e0d91c58b5fdcf3e5edc17497798a",
        "6693c14edee730ecbc892ca5b94d039761c625328051b171457d8ef3b3e013d5",
        "cac926c13370732c0decfab5e6065d78c106314e4c3c5c1913383e2e188dd12d",
        "9579741a54406e96ed5b0b09a85126dd85a94ea62f8563897da38f1635144b3f",
        "449755e6db3c44da98fab3e75a4b7c32f915f406e87393620b4f7942a2803726",
        "c65c36aca59e798248862c4697dc78d5d734bc38fcdbc49367d8846d7a9f106c",
        "81bded59744e84afc520b3fb1390aaadac7ae45941f19fea419ffd08dc79bbc6",
        "f7703a67023027776c5297c756c4621e9b1b56310350ca887d25cf55ef83dcf6",
        "4ed584f8ae3914ae022f2dcbc2d09abf6564a7afad0afdb2680694461b09cc97",
        "5ddaf2c24c3580e94e33ae87d26fede9d8885957bfd68f894747d1f1b7586ce6",
        "cdd6272a6c8255ba925f98fdc2d3497d7f7fffc0e83d29a065ca2bae82ad3168",
        "6016dad0fdc183451e940e58346a2bb02db66310428d322441263a6a80fa0ef2",
        "fbc4762e248478d1e8b48907d16e2733badaedca75876fd49eadb11d1f82df6a",
        "83e1d88695982648c6bc639e91c442952c176145602dda3b1c019244693d1238",
        "392737f3c08a17b4fdf010c148dcb4967e6c2e9b11c9d32bdca547701bc05d42",
        "327351d11d2d592bc8b439a4838836076c0cc9291015e3ab677ff42659142ab0",
        "db94c7adcf24ef73e5944d30fc3e36c508a4d6ba09251cb72306438e687d5ccd",
        "31395fe7fd4499098710520d5501b957368f2416ac8f73d89856a8d95179eeae",
        "a3ee64802e3aec24473346c51b0200e4fb9da848ba5cbf7cadce7b03fcd666a0",
        "4b119a31dcdbc869d4cfa1fe4a447783711c189aee83a57e10625e5128586bab",
        "8de420256ef922256f815624e5edf8652fbb16bacf6411bde273e62492920d12",
        "3c016f08157600b85f0ea68016e91735e89dd469edf170aa16c211f7fd96503f",
        "5502e3c32d9758dc4e6444bea5ee9e3c33f26bd607c103128dbb51b04d3b0f7d",
        "4ced1f233c6e90acfa2eceae3a35c44b0a9bba82391393ae3011cd41c9db6487",
        "14e593cc4cdb7885c1e57424e85bae3a5939d82b35fa236e596dd09cd5eecf86",
        "a3ebd49b58e310dca83702581649340eb1d21a6e1c29ac637e52e132d74ff56e",
        "2e9d2b3e42a7e97e8d17fb539ff4d257ed4e9ac8c6b86a9b54db6fb623073481",
        "e81be66935146975e8e646e4631a3a24bd48161c9eeab9cadb403d8597e5683b",
        "a0c2cb2920aea622e0ce8fed18d8e372182ef5cc777eda590790c07d3999d5dc",
        "c00d01e0ad8e4fd1108364ca999af682fb33bae2235199ee6c47e1c57ebb75f4",
        "25e0de1a8f62e234c9a0e2c8f8d3c11d998b317879555436339b7586dc5b93af",
        "6e5235d1d619421edfd5697ebc5632d5cbb1ac67cb088408881d8eba548d37bc",
        "92f415646ddffe7ddd5608494a08f370ef13d613543438d0d0e8f3761c3675e7",
        "4b8a2ee18e45efef321a88904e9a2412cd3fc3bc49687951140fad508325dd2f",
        "da6fdc5fe4ffd5e85cf71de338b4649ca59d9f555fc256a5a2467bfca5d749d8",
        "68b7e0f129a31515d9cd7f596253b168c33b4382f7f4d317af64665dd705dc81",
        "d0dfd56e5aa94b2332a2a62b87714c47952955dc4296d2383c8a30ab571f2fc8",
        "6c0895f13b57383b5b984c2cc58fd25dd2ec0ce56a9c05df01f245e7dfbed07b",
        "0cbe0e3cbd63cfe69057b10b40a3ebb262a77a140e07eef366fab461400b5cda",
        "6b38bab72ac5ec747dde60244e6ca567a41dd73d842f8083cbb6c92f010b9fff",
        "0a4c85a2af28ca5111ce7d23980a2f79f5f44d922ef21d6cba2009c3757aff3d",
        "92d6f36f4e167e79a1c55b0971f95e1adfb4e45491e1434ae0e3228c83490cbf",
        "01b6834269249cf2919783ea3be232f37e16eab819d34f31bcdbf7f6225267d3",
        "7d8a0d2c119752b7be5bc65e7e5807bd7355601250cf89d9bcdf34336a78c37f",
        "79657c338e0534fb0901889660b0d7be537a1a73c6356f155ebbcb254fa63f3a",
        "405e7e973178b195a2b85e744d67b1d12b6c6b7d6462f574cc1790e75ef8db8f",
        "8eb2ef156ee0e8c1608e8c3164652384ce83f7568093424b0673adede2f0265a",
        "4eaaacf6c24e4b91964f9c798b5cf259b80f1fadc1ed4ba50828ff5f4265ca6d",
        "4a412fb0b38feced61efaed432a66f458f48975f6272f2d87e664628abec18db",
        "4193a346d3513488492a89272247ef471453719c3b64cb819aa4cfb95b5d24e0",
        "81fab4ba7281e096ba751f02f29a7303dd557fca90b72078aff860a6fa88c54d",
        "580c0a67a1f62cef7a684577c744b25a61640b9dfba608bcb30ec8789e9069ba",
        "f9ae8728b9978fb116d23dcbcf1a12690ad7a56a962f3482ab16b3dd1b09f293",
        "501ad7a8a833d2fc7ed42d44cd3f760219d91ec8ceaaee8bb389e705991a07d3",
        "e4cbc703624ed2196182731ac66702cc2e2d8899be933a1dee3ae7ec48d60827",
        "e3ae240a44019fe497c5038f3ebeddb468a2ac26eab2f81ef401fbe4192dffc9",
        "afbfc6fcd3a4ce0ba81e00553882ae4401b8116c12810067d589e7d609159880",
        "426b1ba579e013608f5107639b01712d351a3ca6d907789fb1b4ad1521cfecba",
        "eee53b67f9b818a45dd6771f39f9b26c254306001b8da3a09b8d4e075b6853ca",
        "d077d3b28c49676d724f47312a9d91e9fbfa889681a9b1ee5b2abec28810e502",
        "4693807d1129da01eafb6f1d73dd2148db3c93254ffb26ff94a9227f7ce41cd5",
        "fe0c98a685952ca67959328edae5dc28e9177aa915d9d56f849ddc47e1126f3c",
        "40144085e13beea9e99fe73db3b2bd41de71a295c37301ebaa94c0b21ef927d1",
        "393af0e1c368bed3ea2ae6443f85d0c2a39b3fd0b074868b22bf2784a3d6aa6a",
        "c9f6992577d7169401eba6c557fdd2898d2870fd512b9d19d5a57825458f8ab9",
        "1656493d28fbedeba7f572268430acde5c7c0e60b005da8b281ab47ca47a82eb",
        "be5e8152f34f85e57834a65c0ca0f7f0224f9eecf1c2de9ea167725604a93f6c",
        "844461f5e85316946fb8ada32a92d00b5c33e4ec3aebee8c34ac920d221c3575",
        "bc0aeafb86458743b03cdf9764c0fa09bb46d1f959705c1221faff385bc1449a",
        "04c5749e7e04bef4e67c7a00fcaa6de4905ba4bf6c64d3ff044f8be67fd7b788",
        "af19dfe5203e22b0f0c81349fc6a3cb3bc06183e20e7809ff2339be6b1d7041f",
        "a84df9945236e610994272011a68358848c3af78bfd3aec1b0ad1d59c844c8ea",
        "3113d568ebb297e24544f801bbb425bcaa8b1d0eeb77f25fbba267e22dfdd8d3",
        "7f2e54c4bf37c4e09636221fb0de68411508c57d2f36bf4675766522bc73b363",
        "d649d720c7f11fbf1df5227052090ca051b6388edb210f74e1bbe5a0e6471d48",
        "4c0084f5ff722ec626ef99894f0db476a525927e87b55180f86e974670e21e6c",
        "6890fdf0479fb8f3f479e229bec60f2bb002f14da97556291be78d01f3a2b51a",
        "e65fd8ef216d16a9a5fceeccee8277effc9befa70718580512f0167350ccb8c5",
        "7f45add8a7ce3c474ce1af95c97ce88310d6e269ff1ab0c2c997c50e93858048",
        "b6f77e18e5efa0c5154c9dea4a80e5e532a076b60981f93eab896162c0612027",
        "50c025ca4fa85af57fe29676a725dc3edd9a98e6f2f0395d7277d0a31cdd5dfd",
        "991fb691c5c400f1ac35f4ef4008d07281d7b4dcf9f76cc5d83a79f6c69db0a9",
        "1465bb73398d17e9e25f9428e82c22d952a5ac1ade97be1ee4b2b9cfbbf87dca",
        "e822f6dd70dfe772def2f7eaf5a5910b192f19073672915af506dd14b52fea10",
        "4baeba4060e83139b8ee7461963862fd48ca77b9febe1b5004a3fcd76a6c6ded",
        "509343b83426e7e6ba241f1fd1af4f3ccc272efc85f45a452f0bb249b66e7520",
        "bb03b51b6ea9dea919d65401098add81f0552787511706d55e5426966771f543",
        "0172cbc541939b4fec13500f3421bbb24c34227b40b05305136098b277b2ec9c",
        "e41f5c1509075826f948ac50b2ca29d10d3f43c261db996221d2ba283a807ca9",
        "5ea21a99e138c716a746ee840f28e103c70cdce61afa286bdfd804a9d1026242",
        "893d1bbb65ebdbd1ac99b1726bdb31dfce23be4f81543981ea29efabbe0a3b8b",
        "160f995cf8a3d7df4db83d7d8e8d26564f28287166298047e77b8fdc2c375620",
        "3a071d1af33d304a6c42dd02f7260a615b3030bcb9f4564f0c3d8c5f0ba3fb46",
        "12412147b40d9d81d5b71381d6a4726e5f5d95c55adb47c6fdfe7c45de494159",
        "1cba7239d64173bfa949dcd62cc8090d0733a57de6ccfab4760e2ecec4eddf27",
        "83fbf70ed8c593a7b93e9d9674f613bf392797a20821486f5b5b9ce0b3ef57f6",
        "9afac36c30576b8ef4ba748c8e7801fbd5249080524527447616004c8a36e76d",
        "be56eba1d63e28e4ae36a52a90724fd47dd52f11f32d6380a6546a0ffae9e4c3",
        "d0f3db3bd286bb6fe96ac185c656c0365d759bd7a220f088658b90834297b075",
        "ef9889cea92b2fef4e1ef3ae68d9f74ad9ad9c41e0205ad0854220e10a6c83a3",
        "efcf4e2363c0cf5249966ed1bb948ccfbb67770fa317d598e05a0ef8b4c202f2",
        "14ac0008566fe16534ea345fb70a1fb5039bc8fa45eb78bcda9a2440540fc88a",
        "7e345b9c204a2ae477f1036536355bf4a96e061304fd67b61560e5ad9858046e",
        "71aaa0be95c3b6d9074f2b493fc18107cd49760e7b22fdc612096ced989a3135",
        "8d3bbb053e35c9750fe4072478b6868a7e7e98720240f834089703ecea2c1af4",
        "7164fcae623297bc18766fe4bcb5a0492925b8bb05204d5bb1f74b46b0866dcd",
        "decf77480510afb64a81df72d22b707d980b303443b9c85f27381cce1296ea93",
        "a5339e5a2f9932bc956f77060197ba182817e05a14c29767a420c39fb19a0446",
        "bf4a6acdd66be550db65666dcaa690f3cb8866127824ff2aa7ffb7964e54692b",
        "6ba6b4c2b410ae38339f1cc3928c65ec40670ec1d38837af42c5428e6d7cf0aa",
        "e64900a335fda5b10a6d038abee2293e64f539ebe2b15dc651d14fe62ba075fd",
        "55a73068e8a6919af8df3d4e0f457e57fc590a659709868d066fb567736b9112",
        "827bcb4228091d67e79f194e0c8332cb3d0612952e7db42aab11913523bebc7c",
        "41650051c7a79a3948fef3ab857ce3b9ccfd4065bb6e9add11a2e6c21751ba34",
        "d821f7da50f9348a283c267a78efa561db4b6eb8979df3f18f56b4e1d8aafc45",
        "c340d10d7fbfac7a75dac2e95e1dbbeaf2e9c7b7ac1dfbeafb691b817d300ade",
        "bae6d9eb5d860907df845523a7f6e7f6bec052fe587c345a233915b2a65a50cb",
        "96c13f20145f4857b7af12e2ad463b16d2c4de0b8f129e1d86eaa6b44805b2f8",
        "8738a5f62ea65b2d96725271dba959f4c42f137db0ed0bbf169e6555f3a17e66",
        "ac5c70f43f940b380cfc775c2325af9cb16de80c55142c4c0fb858dd843a4026",
        "1f528c1e528b023f39a5d673e0587cd250033aecdb77c2eaff950b554fa8e243",
        "08174efc91f8a12fe220faec32cdcf1e9615760bb047deff12080f9f5619d820",
        "3f64532095f3537556ce52edaaf34e1e115c47b364b39fb2ad690f94ec772dd2",
        "7b923a29e13842426285da86303814cd060fd56fb5bacd8f3468aab2109675d5",
        "88060b57555b0e1a5d2f6871b1e9ee5613bedce575bd294ebd96bef8fce4590f",
        "7681a7c1d1e7e959a3b7866781b304125fe9aa418d20e9a587cf6f062ba34257",
        "d350783d3737daff3de8c69dc5809a731ebbf31ae52ea802ee467b968f11422e",
        "edf84f988c57bb9db6f6da555ea0cc0107d34ef6c936f6bc71e535802a8e7751",
        "46c323441e9cc82b14e3ebf880fcba85234a94c8e8a5f5c009062f3c0702d4e8",
        "863cb3693c4dee0d21e57ccc3edaab0eb5b755fa056f9e2e4fc1ecf5aae18f51",
        "3c74ac7e697bf00aca438a3a56b2b649c2a7b8e682a367b4dab4acadb4bb0015",
        "da714dfc8b4d4448e9b9f9a870fd88157b41ea1f6da343d12709c345e51372e3",
        "b04ddc424d3a377a9591941822b26d273a6667df60ca95b9cf63e1202a518580",
        "5ee150a9032e520770efdd6003f1a05a708eed677970b0eab3dfba03fc4c8975",
        "0ebb1c7adfbef1c29f52719521384bf7521028816493cc600baa49fb97b5d330",
        "e80c626e4d5f023971772abf0c02acaf0cb3f7e5afd61c7b4574babd330052e1",
        "5c06ddc55f906fe08ce23b01cb86ac30d8480ee4fbaa932e7f2cea82be8b0ffb",
        "ca9b5b3138f4ed932616c5305fa680e5e4c0ddcef0d37842182b118d23339b41",
        "794bfe844801bfd0304a94b50a55a2b26060895cce79e693ee36ce3524b95828",
        "e7173a124459ead322f840ff1d400cb6fce234da66853dfd3a774f283e08d7bd",
        "9b86a454e373f6ed34323482e19b5fc0eee6c5f3891b328cc6080ef13a701669",
        "36fcef3d2cf3d69867b6d102fc8b226065c0e1c12a594319e95baa2fff095f9d",
        "edb026aec17deb573c971d51e1ece8a798340b5ffcc84b5767fb0bd27fa6e844",
        "c1b5e175c42d1c4394b559f1ec0cabc94eab0e73e71117e7ac1674c40ea822d8",
        "b48d392c8511fa588a69371d01a18b3b68b2377275f44406fc2e3f90f7f0921a",
        "c14f6d086ae73fd531419e1d99cceede145e327697a369f3173ba12c221dee88",
        "ddb7c8028f5e3bba99e14449e9b7bc80c4c4a2b9055b0c9a68a63a3078d78b4d",
        "137e69639746a4fea140d0a986286df8b230c1e868c54176d97cc210be3b5808",
        "e3a00535cce9a9bd73f40678a192873d6c509083d2a59681da36ac62c7370959",
        "fe2fdd596f8315991c3f070eabd0ff9d9da6fe8a1d413067ee9132437a7f977b",
        "980bd11bd7861176517ca190ba3c521b882741f47fec7849fff6a7207925bc95",
        "6131dda53adf33e1f43f6ae638ef202fd4b2eac67eff76647ae590f5067b7eca",
        "44efe521dcff27dacbdb97cb46a92ae0e4ce2376c9b3915e4b559cbef01e57c7",
        "650d6fc78fea6496fd5d8b7a62061e2e617b1941c34e057754b7fe7efaf2019b",
        "151fa1008eb53dde030ed4f9a0236e1dbcb2c08eede2d961c9a1c71a9a95f895",
        "9cd3fb1d51141f1f015ebd4253a5518b4107523cc9894b9aa117c21f8f0b34c7",
        "097e328da1b1356d91a45e4b1e52ae77fbdc9ea722a1446beced3a63eaa1afc2",
        "9a793160d6560de961993c8a3384742ea7e3758660e609b45229d978d0d896e8",
        "3747c549946d69ade81ca5797883ccbf08a5e53ccef0ec7fb535c8b5cf50f338",
        "b9ced5f5f522a0975b410c58d4d9d6a1059291c25ecd0ff7f931e7e97a3e48e0",
        "3cf45df892b552d7e2fac9ce6048701dca2f72b182c2a652375d8f735a74d3cb",
        "fe595d3da85e7aa2343e153d27f8d159c2827b01450e9ecb87f1bb889fb97e8c",
        "b303ecc6ddebe7ba6f376bf0993b16764d90e1ab4358d8b8f93fc33e006b230a",
        "3d8d900d96deca793841c92116e53f9b5dc0dd0eab4a846bff4371f55137282e",
        "9a7db80d16415374d47ef83f9444e31cfee743b87d101c3255add2f80777bd77",
        "935c54725653e57d84c85d2e9054c91fdd1762ec41b85a81bcc6c396b86edecd",
        "84fc350786f065c884925860f61a4e95bcbe692547414515c03b34b81a8a9fec",
        "4ab0eadbf41f321fea5ffb316316a69cc3ce8fb9824785ec9800815cb133f098",
        "67dccb720b0fafe64e55f132a013773cdd3d0ef4e4236fd53289b690bd65adc9",
        "930eadbf037ff159cd89b932560a938ab814bcacc90961581b95d6c3fa04f804",
        "422464bf65f4fd6927b4afa414849ad0502c50c8eb10d437dc6b96347aa2b412",
        "799db75d3beec04ffdae12baa6d7a14fced94d6d5c79cd61bd80f2ff7a163e97",
        "5ab791c6cf6bdade91f8ca2b9e855d3f0a6e3e0c54f68427e72b21ae3fc7ac09",
        "4a501ba337ec29591406da3ae7ca9ef827b6cf071a066cf16d4b6d193468b29c",
        "8b29fd42e1f463dd17be1a173e2f5db33f7d359b415bcdd2603b23f8005973f8",
        "3d354223989731186e9665e712e52eb98f749f86f66835065a6474d0f99d3fe0",
        "0a5314c2ce9de52e05079cab5fa88fee99ac7aae26eac9635cda3a192fc0cab2",
        "b0983a7a7be2714fa48c1a4479c99c4484dfbdc2e30f5195865120b46487c711",
        "cc1aaef2d46b52d355cefce6836dbcde7d432dd39f561a936d9fea917843895e",
        "6c0ea226cc37d7fa1020c8cf799868524e9bf28e5bc19fe1048df0284a2178bd",
        "e8219713e862d40cf21d3f590896b2ad275cd8e2b51cc78b7c098b02d2a46381",
        "b6432e6ebaff466e5043a57be0503632e18d3759a31acf5dd141e13a2433c3ca",
        "be11a9f0a282e9d39ce5324338f8327a96fd40f85c9a63722cbcbb62ef5a8301",
        "45342cd9ac4547eef71bc825102a5c56dd4229288b22284d3d9e7fdd3e17250f",
        "38fe959ea48757e66c7ae98a3c5a4b2e7bca05e3f5ea4f7034ca100aebf35978",
        "bddeb9eaa3db92ba66ba6c5fb743fae8f1d78991d5ccf0a485539b1e91988448",
        "93c1a66baeff768faac03692986c3ecd7cd46db4d619459416275d0c7a4b20f5",
        "ded9b970a1d823f9dc0e0404f0ecc53e77e94aed9fae07372a8ed4a05413c539",
        "efe47cf4247e89c6a4b0a015630a7286e980b04616b0a083010b939e9577cf7e",
        "1a22c5e6b8e4c9a4e066786626b5fe6046bfdcfe6941903bc8800583c7ffe5f8",
        "63ac5742555a19d0ae36438bae9e6b6b9452c108a9206f26db91d12a277ffbe6",
        "9f7483c87cb441edbc449d3c83f8d6427e614ae9ff0ccc5dff463f56b1fbb04d",
        "91313f84b1fedb0147be7b5b4cf14b60ba7fc81cd544a72e2ed4104752e38cdb",
        "bd405a232031fd137548a83bfda19202d5d9e828d69cdfd120293ef51d26eb32",
        "25731162b4eb46d1986bd04c0f1031fcd95dd437a17a29f86c2488aa0ef42dee",
        "250740239fbbba51f5fd0c7b0c6d11b7fc511724089b06051350e9cf69e2a2e3",
        "7b8c0ab9dd8f8027441fda01d1f54ab54dac9c8a521c8402fee62743e64cd753",
        "f3ef4b66c2385ce7c1cca2cb8790b57c47409e9380f2b452852f0a973510ffee",
        "662aae71ac7e55f025659d820bde9b43dee391668261af1eacd44f276b85a04f",
        "1f7a637e815dd4bfb35c4c126ced8fe8a3bbfdac1df118f8dfa071ef31487e0f",
        "91f4a562119a643b4af720a13625e737ec3c486234e88e0192ad0e88724a3060",
        "3052322513f91d663a0df89be90a7059628ae550426474f53014c45a8c78b946",
        "cd0ca8b286d89c0290c6e7a8fe2e02d6c0baa4861b9b883f09835a24fe71c621",
        "146d473699a10ce9efcabd03dc075ca216f67e8e44969a1918c65565c8826076",
        "1d1c23f52701e758129cbc52c74a1bfe132adf06ccb7ff4483c7c1b5572fad4f",
        "ca36026e844fff62f89e47b739064c64b925af0e48e442611f55b7bd29386490",
        "0848613756d78b3a100ee8cc07bea82c37f01c7ada74d48c59448100959245da",
        "6c3a10a6961f6ce78563557cbcdb0524dccb2c4d8a7dacf4efa426a82df44166",
        "83df9041c5b0b4aa5d7149c39964bbcee3bce8041b0a37d9b146a20f1ca652e1",
        "8037b0b09223a70d60ebe5aed63f6ece106d23261ea647bf0fe1bf24a3487726",
        "aabe97289a2c444a3c7d394efd9befa531a76412155d3b3cb3a9355fcfb9c842",
        "de19f8dd9b92df9ae494c0eeb1920f551ec0b97f29349d087ee6e42b559b1a00",
        "e0ee1fd624673f9d3afd005edacca22edddfeb171922f3ff37cdd9a9a805ea5e",
        "7495017cb5e1aefb0b1e96aa1ae695cb54f67b453ae8b7c0050f665be92074c0",
        "191248fe94967abc4d1bd0cc0d88bdcc3eef67ec7158d688d930604d952a3a64",
        "e9269417ec568c8a91a23dbcdebcb891fd75915b1fdfc8da06233da45ff2e201",
        "8b885143615bf5e10d0e95b1d7d2dadd005d589d40917f8ae8cef6acb08529a6",
        "a4ba612c4de8bc270604e4f0a163431004ec957f49388e768b388d87118c04fc",
        "d7040819b487012b14f5da24f42a57ae2f4429ee0665d0a1511086e21f599f71",
        "9a7805175e91b22e42003e37ef5b665ada734090445d448eccf39cff4c44aedd",
        "e2a3996820abcddfb6fe0dc41f1d5388a1e99af8bfb753d66a1fdf11f6fd7f03",
        "45cd5e611e8096fb544159ff946d3b1aa8c0a33330eefdcc8144e2cd71c577c6",
        "158604d0b033fe1b96783772886a09d8493f31fe7a9ff68638eae103ecc39467",
        "3ee934561960b224afe026f5f0f03b6f2514d81efd5f1f11eb8da3ef9975378e",
        "5bbe716678212dab01c6561bb9179c29795250ddc135b2cdb3002dceb40eeaf4",
        "ca876207ffebfb16191b840eca893d4545b980e5611a08c80ae0e257140d3071",
        "e17a3f34c9640ed3f2d0299aaf809b0f01c3592022fbe67c12459210cf15ca04",
        "3e61742118c32cfc7c1b827c447f3b7bb45f18b51d0347f4f3818b0f1833992f",
        "a413b9707d7305787eac0b0a6e44cfb3a2e8e0229580396c2511e3d6007dc1e8",
        "ef205baf95c385234aa58e57e092ac9ad6f26d9e8dedc878d1ca588205aceb44",
        "132b6092ae158bc074755322e7e088f6a748c54a86d1df7055e7c74090264631",
        "194d6bd7a8487fc498ef97d97360ca1c90b619b8a0dc11b0c8c1c0de0493889b",
        "cda67e7f2f366bf411f77f741bb28d2e4c6f7d167734142826430bff863af640",
        "b943d22a5dcaa79479318edbb4d9affb5c7ba10e4dbe7dc6391d023f3ba8324b",
        "4e1fe6c26c62a7d98c24eec44651a9e6a82db4358a7123f1c04248856af558d2",
        "2be258796fca0b7311af500b26efdd5ac0e50e1cea1d35d957bcc670040a28af",
        "4da49da6f9970c3e690fba21a68810d89ee7e0a7135622e06dd31936b7675d82",
        "6925fde34da04c6a2b5a97993336306075e2d6de318cc63d7b23952beaf799ee",
        "b8741facbb7333c5aaca69bed8d64216b32cbbd5fd113ce5d8b439548aaff2f6",
        "35182bcd421dd9716e532f82c1a006c37cf7af8c556209ba585dde1b53b43c1a",
        "f898443d793f4f18beabc6442531bee5f2891a6a1e6def037ba96e8f01a6ce08",
        "00b5b7d45466c233103e334e34965f8cfc8a0946db545fda03741a1c121aa737",
        "f55368b274772a5cf9c7bd0c952f8aae748d6a2ec88b33b266852118e7ba6e40",
        "3566f0c0da4b784e0f42308167a76c53070cebcb788693c49bfeaa37d66dcd07",
        "243c4ef1a52e892283f903c46ec36c38b16b56406b229f213fa0a50c6cc68886",
        "b750df581b71124c02604299ff54891c056d5b9a953045a61662a4fa95c2d796",
        "6c74a6fa0984af041cf6efbd82e773b79d59efdfeaa35b13e62d4ce77275a78c",
        "089e79a27b2df007a171befbe5a163452b2bc9b5cd6c1e53c0c85bc80466717f",
        "5b144e5627b8e11363ed19c5e58eade87698242988c3fb235fdf7efc31f388e2",
        "6ea5eed10b23e660ffa163c0e054e584a3b22516185edec6e32510918c15e5aa",
        "3933dc298b27274c15fea14f09a5578a67bb74e505fa3169b692d7431a85ef60",
        "13f62b5f4bab521be733fee6ef0919e51b521a072ec9b267eb4facd03afc57e9",
        "7c1457936a831b3d4f43908a5a85f4e6eca7265e90da5ec575bcb214728ea241",
        "8196c03743c92f11824eebb304cc1a72e4246465a2ea5176bdc5aafb230a4f91",
        "b77a46227f1ea943caa3d49dd8659d192cd29f1fd433ea3fca6e7d3d61106ae1",
        "f5f795612036cede9e5a36a901a522ba69a3b8f75365b3dcf49291525a313552",
        "9b148b14225db77736ef56ae688d3eace0143f9fc0e5e3f33e5521a829408789",
        "01f709bf1c1e34a4b0423c2a659a5f5df3c2963b8cba1a3c71611f3bb1d687a8",
        "f954b48c933d9b88b9be58fed7f3f67c6a97482ebcda384b4fcadfeb7dadfcbf",
        "f9320beba51084f17e423ee2052856e8ed4618cc133a8724d732b785bda0197a",
        "ba716c11233ee60cc1a91176ed54067d4301651eab6bf5c51d26b87e45554ee4",
        "f03efad380418ee1597645ca1623a7623d51acc167c01183a89cc2a15cce3a29",
        "a4ecfde046c4adf4d031ed6c4baadf7ece2168ec96c54d5f4e109467413e8b85",
        "9b51647896ad9df8fa47644be5b14320dd55311d39df1f5f87854474cfbebcee",
        "fcc979069792c2fc0c9dca17aedf55e83b0012d31f44645b18e4d6ea2f445cd5",
        "2e98d8e485ac7ca8c46304829ecc289e8f7ed1c4c19b882ed6e1cb907b313086",
        "94e3061075d9986336795a64ab2de56a992b611f4aad0ee6926ce46cb95d4b13",
        "e446027b1a90b2a42dc7bb096e032ef1d8e0262d045eed8237ae92d35ddab4f4",
        "73c5733c2b2d24436fd4f29cbca2fdee5da365eb9bf3f77dbe58dec2588ce6ed",
        "4f4fcc67701821984bbb270a22578f4a67fe82ff954090c9c18b3c6e5cd50458",
        "53811340e3f64da19ac95dafda224856c21672f793b0080e54ddd5a0e607cd31",
        "2769ed5d84e16f4b273ad9c05824fbfc97c04741465fa1eb4c1148e19e528e80",
        "65d0aad1444e73f768c43f0ebb6ea8894f729256bb8c7860995a2a473a400028",
        "3fe415c267b8a29d3f6c4ad2fbe70c4948e84695a52e5ab654b1a204b90ab845",
        "655ee3336f3f24ff5bf03f1a8a8bee378802e4243a3505938dcebc7146ce9aa1",
        "2b2105646102f60ba8e7633a2efb8e78e78f0c351d240ca4091f2e99cf549c51",
        "7e7b7f3df12115a3fcc66d557d1958ad70cbbdc2212388ec3e1e5d06bae2b696",
        "5d018f5696f95dfc0999d7959869232bf622e745d6d0a7705767bb967737aa83",
        "e21282bde86b2bfe9fc557d730794a33543384c485a3cb45f791b2105d682553",
        "9594fad7a1b3de345dfcc0b58b369133a386d233b0ac32801f0b62513ffb93ba",
        "3522b184f72508de0e3e90a3d8433a21d176c63b162eaadcb595a632c6acd022",
        "0de9730c537f1b1b79b7eb6d316a4332ff364348deef9b7fd24c1db4c41abebe",
        "3accae7d9c10e7590a74ee068526eaccfcfa8d262bbbb11934442cc58d9c141b",
        "ad3293b69e827109b658cb02520fa1becb0671c4d33071637fe103946bc22a6b",
        "b7f69567a508da59ca3c5a1fd767138599b18a5bfca6f5206ccf1231b82a99fd",
        "bdd5f6d234ef242957a0855d2054c2659dd2ad20b237c5afb48a7754494b7111",
        "21009c1e551bef00a83f19de5911f410decec00e5803f5e1a1eca5d1da3f3899",
        "1bae46129d5385ffd3cf1ca3543f9c031bebf02664fbdefd2be56e312bc9e0dd",
        "25d809baced0783e3edf2eeaf7a2b082cc2c35b38d7bc4917972df37555ef00c",
        "9e7db069e996755bc0d46eac3b3f58bc6fdb98890d6df4d60946280240c44e41",
        "04f7a83e8956522225a3c404c566ca6ce998d3ca194e57ce7bbb0d30263bf316",
        "b2126254293b6fc6d48ae26671f2bc16fd481dc8a5d4ae77f2568a170e834508",
        "24c92a5f98b35fd4cd0316f204de8afb400f72c439219e1199512dc00e8b66d9",
        "522ec9b1303fec35950778cfb5aeff8fb66b7be2c636906c518a21ea12ed291e",
        "d4de54064e3df3a727436547a29283c470454922f65c0505647c25600ac2a3bc",
        "06970188011335e039c4a3a321d626400dbe3a4d3e88cc2dac9a3423069d484c",
        "3494e85d483cf4d4a1343c75cd6c683bf05d15007193f9ec17e4e3095eab8dfa"};

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
