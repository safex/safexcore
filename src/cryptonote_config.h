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
#define FINAL_SUBSIDY_PER_MINUTE                        ((uint64_t)3) //after 1 billion, emit constant small block reward

#define CRYPTONOTE_REWARD_BLOCKS_WINDOW                 100
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1    20000 //size of block (bytes) after which reward for block is calculated using block size
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2    60000
#define CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE          600
#define CRYPTONOTE_DISPLAY_DECIMAL_POINT                10


#define AIRDROP_SAFEX_CASH_AMOUNT                       (10000000 * SAFEX_CASH_COIN) //10 million coins
#define AIRDROP_TOKEN_TO_CASH_REWARD_RATE               (0.00232830643) //migration token to cash rate

#define TOKEN_TOTAL_SUPPLY                              ((uint64_t)2147483647) //Token total supply, without decimals

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
#define HF_VERSION_MIN_SUPPORTED_TX_VERSION     1
#define HF_VERSION_MAX_SUPPORTED_TX_VERSION     2
#define HF_VERSION_VALID_DECOMPOSED_MINER_TX    3
#define HF_VERSION_ALLOW_LESS_BLOCK_REWARD      2
#define HF_VERSION_MINER_TX_MAX_OUTS            11
#define HF_VERSION_CHANGE_MINER_DUST_HANDLING   4



//Safex related constants
#define SAFEX_COMMAND_PROTOCOL_VERSION          1
#define SAFEX_MINIMUM_TOKEN_STAKE_AMOUNT         10000 * SAFEX_TOKEN
#define SAFEX_DEFAULT_TOKEN_STAKE_EXPIRY_PERIOD  500000
#define SAFEX_DEFAULT_INTERVAL_PERIOD           1000 //blocks
#define SAFEX_DEFAULT_MINUMUM_TOKEN_STAKE_PERIOD SAFEX_DEFAULT_INTERVAL_PERIOD*10 //blocks
#define SAFEX_DEFAULT_NETWORK_FEE_PERCENTAGE    ((uint64_t)5)
#define SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_FEE     ((uint64_t)100*SAFEX_TOKEN)
#define SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_PERIOD  ((uint64_t)15) //15 blocks for tests, TBD
#define SAFEX_ACCOUNT_DATA_MAX_SIZE             2048
#define SAFEX_OFFER_DATA_MAX_SIZE               2048


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
    //TODO: Set to other values when activating new hard fork
    uint64_t const HARDFORK_V4_INIT_DIFF = 330000000;
    uint64_t const HARDFORK_V4_START_HEIGHT = 330000;

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
    uint64_t const HARDFORK_V4_INIT_DIFF = 6000;
    uint64_t const HARDFORK_V4_START_HEIGHT = 308450;
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
    //TODO: Set to other values when activating new hard fork
    uint64_t const HARDFORK_V4_INIT_DIFF = 100;
    uint64_t const HARDFORK_V4_START_HEIGHT = 241847;
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
