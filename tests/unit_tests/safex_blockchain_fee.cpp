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
// Parts of this file are originally copyright (c) 2014-2018 The Monero Project

#include <boost/filesystem.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <cstdio>
#include <iostream>
#include <chrono>
#include <thread>

#include "gtest/gtest.h"

#include "string_tools.h"
#include "blockchain_db/blockchain_db.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "safex_test_common.h"

using namespace cryptonote;
using epee::string_tools::pod_to_hex;

#define ASSERT_HASH_EQ(a, b) ASSERT_EQ(pod_to_hex(a), pod_to_hex(b))

namespace
{  // anonymous namespace

  const int NUMBER_OF_BLOCKS = 543;
  const uint64_t default_miner_fee = ((uint64_t) 500000000);
  const std::string bitcoin_tx_hashes_str[6] = {"3b7ac2a66eded32dcdc61f0fec7e9ddb30ccb3c6f5f06c0743c786e979130c5f", "3c904e67190d2d8c5cc93147c1a3ead133c61fc3fa578915e9bf95544705e63c",
                                                "2d825e690c4cb904556285b74a6ce565f16ba9d2f09784a7e5be5f7cdb05ae1d", "89352ec1749c872146eabddd56cd0d1492a3be6d2f9df98f6fbbc0d560120182",
                                                "80220aec436a2298bae6b35c920017d36646cda874a0516e121e658a888d2b55", "361074a34cf1723c7f797f2764b4c34a8e1584475c28503867778ca90bebbc0a"};


  template<typename T>
  class SafexBlockchainFeeTest : public testing::Test
  {
    protected:
      SafexBlockchainFeeTest() : m_db(new T(false, cryptonote::network_type::FAKECHAIN)), m_hardfork(*m_db, 1, 0)
      {
        m_test_sizes = std::vector<size_t>(NUMBER_OF_BLOCKS, 0);
        m_test_coins = std::vector<uint64_t>(NUMBER_OF_BLOCKS, 60);
        m_test_coins[0] = 2000 * SAFEX_CASH_COIN; //genesis tx airdrop
        m_test_tokens = std::vector<uint64_t>(NUMBER_OF_BLOCKS, 0);
        m_test_tokens[0] = 1000 * SAFEX_TOKEN;
        m_test_tokens[1] = 100 * SAFEX_TOKEN;
        m_test_diffs = std::vector<difficulty_type>(NUMBER_OF_BLOCKS, 200);
        m_test_diffs[0] = 1;
        m_test_diffs[1] = 100;
        m_test_diffs[2] = 180;

        //m_txs = std::vector<std::vector<transaction>>(1, std::vector<transaction>());

        m_miner_acc.generate();
        m_users_acc[0].generate();
        m_users_acc[1].generate();

        for (int i = 0; i < NUMBER_OF_BLOCKS; i++)
        {
          block blk;
          std::list<cryptonote::transaction> tx_list; // fill tx list with transactions for that block
          crypto::hash prev_hash = boost::value_initialized<crypto::hash>();/* null hash*/

          if (i > 0) prev_hash = cryptonote::get_block_hash(m_blocks[i - 1]);

          if (i == 0)
          {
            //skip, genesis block
          }
          else if (i == 1)
          {
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();                                                           \
            construct_migration_tx_to_key(m_txmap, m_blocks, tx, m_miner_acc, m_users_acc[0], m_test_tokens[0], default_miner_fee, get_hash_from_string(bitcoin_tx_hashes_str[0]));
            m_txmap[get_transaction_hash(tx)] = tx;
          }
          else if (i == 2)
          {
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();                                                           \
            construct_token_tx_to_key(m_txmap, m_blocks, tx, m_users_acc[0], m_users_acc[1], 200 * SAFEX_TOKEN, default_miner_fee, 0);
            m_txmap[get_transaction_hash(tx)] = tx;

            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx2 = tx_list.back();                                                           \
            construct_tx_to_key(m_txmap, m_blocks, tx2, m_miner_acc, m_users_acc[1], 10 * SAFEX_CASH_COIN, default_miner_fee, 0);
            m_txmap[get_transaction_hash(tx2)] = tx2;
          }
          else if (i == 3)
          {
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();                                                           \
            construct_token_tx_to_key(m_txmap, m_blocks, tx, m_users_acc[0], m_users_acc[1], 100 * SAFEX_TOKEN, default_miner_fee, 0);
            m_txmap[get_transaction_hash(tx)] = tx;
          }
          else if (i == 10)
          {
            //create token stake transaction, user 0 locks 100 safex token
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();                                                           \
            construct_token_stake_transaction(m_txmap, m_blocks, tx, m_users_acc[0], m_users_acc[0], 100 * SAFEX_TOKEN, default_miner_fee, 0);
//            std::cout << "tx 10 hash: " << epee::string_tools::pod_to_hex(get_transaction_hash(tx)) << std::endl;
            m_txmap[get_transaction_hash(tx)] = tx;
          }
          else if (i == 11)
          {
            //create other token stake transaction
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();                                                           \
            construct_token_stake_transaction(m_txmap, m_blocks, tx, m_users_acc[0], m_users_acc[0], 400 * SAFEX_TOKEN, default_miner_fee, 0);
            m_txmap[get_transaction_hash(tx)] = tx;

            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx2 = tx_list.back();                                                           \
            construct_token_stake_transaction(m_txmap, m_blocks, tx2, m_users_acc[1], m_users_acc[1], 100 * SAFEX_TOKEN, default_miner_fee, 0);
            m_txmap[get_transaction_hash(tx2)] = tx2;

          }
          else if (i == 13)
          {
            //add network fee
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();                                                           \
            construct_fee_donation_transaction(m_txmap, m_blocks, tx, m_miner_acc, 2 * SAFEX_CASH_COIN, default_miner_fee, 0);
            std::cout << "tx 13 hash: " << epee::string_tools::pod_to_hex(get_transaction_hash(tx)) << std::endl;
            m_txmap[get_transaction_hash(tx)] = tx;
          }
          else if (i == 15)
          {
            //add more network fee
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();                                                           \
            construct_fee_donation_transaction(m_txmap, m_blocks, tx, m_miner_acc, 12.5 * SAFEX_CASH_COIN, default_miner_fee, 0);
            std::cout << "tx 15 hash: " << epee::string_tools::pod_to_hex(get_transaction_hash(tx)) << std::endl;
            m_txmap[get_transaction_hash(tx)] = tx;
          }
          else if (i == 19)
          {
            //token stake transaction
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();
            construct_token_stake_transaction(m_txmap, m_blocks, tx, m_users_acc[1], m_users_acc[1], 200 * SAFEX_TOKEN, default_miner_fee, 0);
            m_txmap[get_transaction_hash(tx)] = tx;
          }
          else if (i == 157)
          {
            //add network fee
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();                                                           \
            construct_fee_donation_transaction(m_txmap, m_blocks, tx, m_miner_acc, 1 * SAFEX_CASH_COIN, default_miner_fee, 0);
            m_txmap[get_transaction_hash(tx)] = tx;
          }
          else if (i == 243)
          {
            //add network fee
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();                                                           \
            construct_fee_donation_transaction(m_txmap, m_blocks, tx, m_miner_acc, 1 * SAFEX_CASH_COIN, default_miner_fee, 0);
            m_txmap[get_transaction_hash(tx)] = tx;

            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx2 = tx_list.back();                                                           \
            construct_fee_donation_transaction(m_txmap, m_blocks, tx2, m_miner_acc, 60404980, default_miner_fee, 0);
            m_txmap[get_transaction_hash(tx2)] = tx2;
          }
          else if (i == 517)
          {
            //token unlock transaction
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();
            construct_token_unstake_transaction(m_txmap, m_blocks, tx, m_users_acc[1], m_users_acc[1], 100 * SAFEX_TOKEN, default_miner_fee, 0); //unlock 100
            m_txmap[get_transaction_hash(tx)] = tx;
          }
          else if (i == 520)
          {
            //token unlock transaction
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();
            construct_token_unstake_transaction(m_txmap, m_blocks, tx, m_users_acc[0], m_users_acc[0], 400 * SAFEX_TOKEN, default_miner_fee, 0); //unlock 400
            m_txmap[get_transaction_hash(tx)] = tx;
          }


          construct_block(blk, i, prev_hash, m_miner_acc, 0, m_test_sizes[i], tx_list);

          m_txs.push_back(std::vector<cryptonote::transaction>{tx_list.begin(), tx_list.end()});
          m_blocks.push_back(blk);
        }

      }


      ~SafexBlockchainFeeTest()
      {
        delete m_db;
        remove_files(m_filenames, m_prefix);
      }

      BlockchainDB *m_db;
      HardFork m_hardfork;
      std::string m_prefix;
      std::vector<block> m_blocks;
      //std::unordered_map<crypto::hash, cryptonote::transaction>
      map_hash2tx_t m_txmap; //vector of all transactions
      std::vector<std::vector<transaction> > m_txs;
      std::vector<std::string> m_filenames;

      cryptonote::account_base m_miner_acc;
      cryptonote::account_base m_users_acc[2];

      std::vector<size_t> m_test_sizes;
      std::vector<uint64_t> m_test_coins;
      std::vector<uint64_t> m_test_tokens;
      std::vector<difficulty_type> m_test_diffs;


      void init_hard_fork()
      {
        m_hardfork.init();
        m_db->set_hard_fork(&m_hardfork);
      }

      void get_filenames()
      {
        m_filenames = m_db->get_filenames();
        for (auto &f : m_filenames)
        {
          std::cerr << "File created by test: " << f << std::endl;
        }
      }

      void set_prefix(const std::string &prefix)
      {
        m_prefix = prefix;
      }
  };

  using testing::Types;

  typedef Types<BlockchainLMDB> implementations;

  TYPED_TEST_CASE(SafexBlockchainFeeTest, implementations);

#if 1

  TYPED_TEST(SafexBlockchainFeeTest, RetrieveCollectedFee)
  {
    boost::filesystem::path tempPath = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
    std::string dirPath = tempPath.string();

    this->set_prefix(dirPath);

    // make sure open does not throw
    ASSERT_NO_THROW(this->m_db->open(dirPath));
    this->get_filenames();
    this->init_hard_fork();

    for (int i = 0; i < NUMBER_OF_BLOCKS - 1; i++)
    {
      try
      {
        this->m_db->add_block(this->m_blocks[i], this->m_test_sizes[i], this->m_test_diffs[i], this->m_test_coins[i], this->m_test_tokens[i], this->m_txs[i]);
      }
      catch (std::exception &e)
      {
        std::cout << "Error: " << e.what() << std::endl;
      }

      if (i == 517) {
        //here, we have unlocked 100, check current db status
        uint64_t number_of_staked_tokens51 = this->m_db->get_staked_token_sum_for_interval(51);
        uint64_t number_of_staked_tokens52 = this->m_db->get_staked_token_sum_for_interval(52);
        uint64_t number_of_staked_tokens52_cur = this->m_db->get_current_staked_token_sum();

        ASSERT_EQ(number_of_staked_tokens51, 800 * SAFEX_TOKEN);
        ASSERT_EQ(number_of_staked_tokens52, 700 * SAFEX_TOKEN);
        ASSERT_EQ(number_of_staked_tokens52_cur, 700 * SAFEX_TOKEN);
      } else if (i == 520) {
        //here, we have unlocked 400, check current db status
        uint64_t number_of_staked_tokens51 = this->m_db->get_staked_token_sum_for_interval(51);
        uint64_t number_of_staked_tokens52 = this->m_db->get_staked_token_sum_for_interval(52);
        uint64_t number_of_staked_tokens52_cur = this->m_db->get_current_staked_token_sum();

        ASSERT_EQ(number_of_staked_tokens51, 800 * SAFEX_TOKEN);
        ASSERT_EQ(number_of_staked_tokens52, 300 * SAFEX_TOKEN);
        ASSERT_EQ(number_of_staked_tokens52_cur, 300 * SAFEX_TOKEN);
      } else if (i == 521) {
      //new period 53 started, check current db status
      uint64_t number_of_staked_tokens51 = this->m_db->get_staked_token_sum_for_interval(51);
      uint64_t number_of_staked_tokens52 = this->m_db->get_staked_token_sum_for_interval(52);
      uint64_t number_of_staked_tokens53 = this->m_db->get_staked_token_sum_for_interval(53);
      uint64_t number_of_staked_tokens54 = this->m_db->get_staked_token_sum_for_interval(54);
      uint64_t number_of_staked_tokens53_cur = this->m_db->get_current_staked_token_sum();

      ASSERT_EQ(number_of_staked_tokens51, 800 * SAFEX_TOKEN);
      ASSERT_EQ(number_of_staked_tokens52, 300 * SAFEX_TOKEN);
      ASSERT_EQ(number_of_staked_tokens53, 300 * SAFEX_TOKEN);
      ASSERT_EQ(number_of_staked_tokens53_cur, 300 * SAFEX_TOKEN);
    }

    }

    uint64_t number_of_staked_tokens2 = this->m_db->get_staked_token_sum_for_interval(2); // in first interval we have staked 100, they receive interest in interval 2
    ASSERT_EQ(number_of_staked_tokens2, 100 * SAFEX_TOKEN);

    uint64_t number_of_staked_tokens3 = this->m_db->get_staked_token_sum_for_interval(3); // in first interval we have staked another 700, in totall 800, they receive interest in interval 3
    ASSERT_EQ(number_of_staked_tokens3, 800 * SAFEX_TOKEN);

    uint64_t number_of_staked_tokens10 = this->m_db->get_staked_token_sum_for_interval(10);
    ASSERT_EQ(number_of_staked_tokens10, 800 * SAFEX_TOKEN);

    uint64_t number_of_staked_tokens51 = this->m_db->get_staked_token_sum_for_interval(51);
    ASSERT_EQ(number_of_staked_tokens51, 800 * SAFEX_TOKEN);

    uint64_t number_of_staked_tokens52 = this->m_db->get_staked_token_sum_for_interval(52);
    ASSERT_EQ(number_of_staked_tokens52, 300 * SAFEX_TOKEN);

    uint64_t number_of_staked_tokens55 = this->m_db->get_staked_token_sum_for_interval(55);
    ASSERT_EQ(number_of_staked_tokens55, 300 * SAFEX_TOKEN);

    uint64_t number_of_staked_tokens_endsum = this->m_db->get_current_staked_token_sum();
    ASSERT_EQ(number_of_staked_tokens_endsum, 300 * SAFEX_TOKEN); //100+400+100+200-400-100




    uint64_t fee_sum = this->m_db->get_network_fee_sum_for_interval(0);
//    ASSERT_EQ(fee_sum, 14.5 * SAFEX_CASH_COIN); // 2 + 12.5
    std::cout << "Cash collected fee:" << print_money(fee_sum) << std::endl;



    ASSERT_NO_THROW(this->m_db->close());

  }

#endif


}  // anonymous namespace
