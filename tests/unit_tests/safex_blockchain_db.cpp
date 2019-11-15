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

  const int NUMBER_OF_BLOCKS = 23;
  const uint64_t default_miner_fee = ((uint64_t) 500000000);
  const std::string bitcoin_tx_hashes_str[6] = {"3b7ac2a66eded32dcdc61f0fec7e9ddb30ccb3c6f5f06c0743c786e979130c5f", "3c904e67190d2d8c5cc93147c1a3ead133c61fc3fa578915e9bf95544705e63c",
                                                "2d825e690c4cb904556285b74a6ce565f16ba9d2f09784a7e5be5f7cdb05ae1d", "89352ec1749c872146eabddd56cd0d1492a3be6d2f9df98f6fbbc0d560120182",
                                                "80220aec436a2298bae6b35c920017d36646cda874a0516e121e658a888d2b55", "361074a34cf1723c7f797f2764b4c34a8e1584475c28503867778ca90bebbc0a"};


  template<typename T>
  class SafexBlockchainDBTest : public testing::Test
  {
    protected:
      SafexBlockchainDBTest() : m_db(new T(false, cryptonote::network_type::FAKECHAIN)), m_hardfork(*m_db, 1, 0)
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
          else if (i == 17)
          {
            //token unlock transaction
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();
            construct_token_unstake_transaction(m_txmap, m_blocks, tx, m_users_acc[1], m_users_acc[1], 100 * SAFEX_TOKEN, default_miner_fee, 0); //unlock 100
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
          else if (i == 21)
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


      ~SafexBlockchainDBTest()
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

  TYPED_TEST_CASE(SafexBlockchainDBTest, implementations);

#if 1
  TYPED_TEST(SafexBlockchainDBTest, OpenAndClose)
  {
    boost::filesystem::path tempPath = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
    std::string dirPath = tempPath.string();

    this->set_prefix(dirPath);

    // make sure open does not throw
    ASSERT_NO_THROW(this->m_db->open(dirPath));
    this->get_filenames();

    // make sure open when already open DOES throw
    ASSERT_THROW(this->m_db->open(dirPath), DB_OPEN_FAILURE);

    ASSERT_NO_THROW(this->m_db->close());
  }

  TYPED_TEST(SafexBlockchainDBTest, AddBlock)
  {

    boost::filesystem::path tempPath = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
    std::string dirPath = tempPath.string();

    this->set_prefix(dirPath);

    // make sure open does not throw
    ASSERT_NO_THROW(this->m_db->open(dirPath));
    this->get_filenames();
    this->init_hard_fork();

    // adding a block with no parent in the blockchain should throw.
    // note: this shouldn't be possible, but is a good (and cheap) failsafe.
    //
    // TODO: need at least one more block to make this reasonable, as the
    // BlockchainDB implementation should not check for parent if
    // no blocks have been added yet (because genesis has no parent).
    //ASSERT_THROW(this->m_db->add_block(this->m_blocks[1], m_test_sizes[1], t_diffs[1], t_coins[1], this->m_txs[1]), BLOCK_PARENT_DNE);

//    for (int i = 0; i < NUMBER_OF_BLOCKS; i++)
//      ASSERT_NO_THROW(this->m_db->add_block(this->m_blocks[i], this->m_test_sizes[i], this->m_test_diffs[i], this->m_test_coins[i], this->m_test_tokens[i], this->m_txs[i]));

    for (int i = 0; i < NUMBER_OF_BLOCKS; i++)
    {
      try
      {
        this->m_db->add_block(this->m_blocks[i], this->m_test_sizes[i], this->m_test_diffs[i], this->m_test_coins[i], this->m_test_tokens[i], this->m_txs[i]);
      }
      catch (std::exception &e)
      {
        std::cout << "Error: " << e.what() << std::endl;
      }
    }


    block b;
    ASSERT_TRUE(this->m_db->block_exists(get_block_hash(this->m_blocks[0])));
    ASSERT_NO_THROW(b = this->m_db->get_block(get_block_hash(this->m_blocks[0])));

    ASSERT_TRUE(compare_blocks(this->m_blocks[0], b));

    ASSERT_NO_THROW(b = this->m_db->get_block_from_height(0));

    ASSERT_TRUE(compare_blocks(this->m_blocks[0], b));

    // assert that we can't add the same block twice
    ASSERT_THROW(this->m_db->add_block(this->m_blocks[0], this->m_test_sizes[0], this->m_test_diffs[0], this->m_test_coins[0], this->m_test_tokens[0], this->m_txs[0]), TX_EXISTS);

    for (auto &h : this->m_blocks[NUMBER_OF_BLOCKS - 1].tx_hashes)
    {
      transaction tx;
      ASSERT_TRUE(this->m_db->tx_exists(h));
      ASSERT_NO_THROW(tx = this->m_db->get_tx(h));
      ASSERT_HASH_EQ(h, get_transaction_hash(tx));
    }
  }

  TYPED_TEST(SafexBlockchainDBTest, RetrieveBlockData)
  {
    boost::filesystem::path tempPath = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
    std::string dirPath = tempPath.string();

    this->set_prefix(dirPath);

    // make sure open does not throw
    ASSERT_NO_THROW(this->m_db->open(dirPath));
    this->get_filenames();
    this->init_hard_fork();

    for (int i = 0; i < NUMBER_OF_BLOCKS - 1; i++)
      ASSERT_NO_THROW(this->m_db->add_block(this->m_blocks[i], this->m_test_sizes[i], this->m_test_diffs[i], this->m_test_coins[i], this->m_test_tokens[i], this->m_txs[i]));

    ASSERT_EQ(this->m_test_sizes[0], this->m_db->get_block_size(0));
    ASSERT_EQ(this->m_test_diffs[0], this->m_db->get_block_cumulative_difficulty(0));
    ASSERT_EQ(this->m_test_diffs[0], this->m_db->get_block_difficulty(0));
    ASSERT_EQ(this->m_test_coins[0], this->m_db->get_block_already_generated_coins(0));

    ASSERT_NO_THROW(this->m_db->add_block(this->m_blocks[NUMBER_OF_BLOCKS - 1], this->m_test_sizes[NUMBER_OF_BLOCKS - 1], this->m_test_diffs[NUMBER_OF_BLOCKS - 1], this->m_test_coins[NUMBER_OF_BLOCKS - 1], this->m_test_tokens[NUMBER_OF_BLOCKS - 1],
                                          this->m_txs[NUMBER_OF_BLOCKS - 1]));
    ASSERT_EQ(this->m_test_diffs[1] - this->m_test_diffs[0], this->m_db->get_block_difficulty(1));

    ASSERT_HASH_EQ(get_block_hash(this->m_blocks[0]), this->m_db->get_block_hash_from_height(0));

    std::vector<block> blks;
    ASSERT_NO_THROW(blks = this->m_db->get_blocks_range(0, NUMBER_OF_BLOCKS - 1));
    ASSERT_EQ(NUMBER_OF_BLOCKS, blks.size());

    ASSERT_HASH_EQ(get_block_hash(this->m_blocks[0]), get_block_hash(blks[0]));
    ASSERT_HASH_EQ(get_block_hash(this->m_blocks[1]), get_block_hash(blks[1]));
    ASSERT_HASH_EQ(get_block_hash(this->m_blocks[10]), get_block_hash(blks[10]));
    ASSERT_HASH_EQ(get_block_hash(this->m_blocks[NUMBER_OF_BLOCKS - 1]), get_block_hash(blks[NUMBER_OF_BLOCKS - 1]));

    std::vector<crypto::hash> hashes;
    ASSERT_NO_THROW(hashes = this->m_db->get_hashes_range(0, NUMBER_OF_BLOCKS - 1));
    ASSERT_EQ(NUMBER_OF_BLOCKS, hashes.size());

    ASSERT_HASH_EQ(get_block_hash(this->m_blocks[0]), hashes[0]);
    ASSERT_HASH_EQ(get_block_hash(this->m_blocks[1]), hashes[1]);
    ASSERT_HASH_EQ(get_block_hash(this->m_blocks[10]), hashes[10]);
    ASSERT_HASH_EQ(get_block_hash(this->m_blocks[NUMBER_OF_BLOCKS - 1]), hashes[NUMBER_OF_BLOCKS - 1]);
  }

#endif

  TYPED_TEST(SafexBlockchainDBTest, RetrieveTokenLockData)
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
      ASSERT_NO_THROW(this->m_db->add_block(this->m_blocks[i], this->m_test_sizes[i], this->m_test_diffs[i], this->m_test_coins[i], this->m_test_tokens[i], this->m_txs[i]));
    }

    uint64_t number_of_locked_tokens = this->m_db->get_current_staked_token_sum();
    ASSERT_EQ(number_of_locked_tokens, 300 * SAFEX_TOKEN); //100+400+100-100+200-400

    std::vector<uint64_t> data = this->m_db->get_token_stake_expiry_outputs(SAFEX_DEFAULT_TOKEN_STAKE_EXPIRY_PERIOD + 11);
    ASSERT_EQ(data.size(), 2);

    data = this->m_db->get_token_stake_expiry_outputs(SAFEX_DEFAULT_TOKEN_STAKE_EXPIRY_PERIOD + 15);
    ASSERT_EQ(data.size(), 0);

    data = this->m_db->get_token_stake_expiry_outputs(SAFEX_DEFAULT_TOKEN_STAKE_EXPIRY_PERIOD + 19);
    ASSERT_EQ(data.size(), 1);

    uint64_t test_output_id = data[0]; //first tx in 11 block


    uint64_t token_lock_output_num =  this->m_db->get_num_outputs(tx_out_type::out_staked_token);
    ASSERT_EQ(token_lock_output_num, 4);



    output_advanced_data_t outd = this->m_db->get_output_key(tx_out_type::out_staked_token, test_output_id);
    bool match = false;
    crypto::hash matching_tx_hash;

    //find pkey key in transaction output of block 19
    for (transaction& tx: this->m_txs[19])
    {
      for (tx_out out: tx.vout)
      {
        crypto::public_key check = *boost::apply_visitor(cryptonote::destination_public_key_visitor(), out.target); //get public key of first output of first tx in 11 block
        if (memcmp(outd.pubkey.data, check.data, sizeof(outd.pubkey.data)) == 0) {
          match = true;
          matching_tx_hash = tx.hash;
        }
      }
    }
    ASSERT_EQ(match, true);

    tx_out_index index1 = this->m_db->get_output_tx_and_index_from_global(test_output_id);
    ASSERT_EQ(matching_tx_hash, index1.first);


    ASSERT_THROW(this->m_db->get_output_key(tx_out_type::out_staked_token, 5913), DB_ERROR);
    ASSERT_THROW(this->m_db->get_output_key(tx_out_type::out_cash, test_output_id), DB_ERROR);


    uint64_t tx_index;
    if (!this->m_db->tx_exists(matching_tx_hash, tx_index))
    {
      ASSERT_TRUE(false);
    }

    std::vector<uint64_t> output_indexs;

    // get amount or output id for outputs, currently referred to in parts as "output global indices", but they are actually specific to amounts for cash and token outputs
    output_indexs = this->m_db->get_tx_amount_output_indices(tx_index);
    if (output_indexs.empty())
    {
      ASSERT_TRUE(false);
    }


    this->m_db->for_all_advanced_outputs([](const crypto::hash &tx_hash, uint64_t height, uint64_t output_id, const txout_to_script& txout){
      std::cout << "Height: " << height << " txid: " << output_id << " txout type: "<< static_cast<uint64_t>(txout.output_type) << std::endl;
      return true;
    }, cryptonote::tx_out_type::out_staked_token);

    ASSERT_NO_THROW(this->m_db->close());

  }

#if 1

  TYPED_TEST(SafexBlockchainDBTest, RetrieveCollectedFee)
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
      ASSERT_NO_THROW(this->m_db->add_block(this->m_blocks[i], this->m_test_sizes[i], this->m_test_diffs[i], this->m_test_coins[i], this->m_test_tokens[i], this->m_txs[i]));
    }

    uint64_t number_of_locked_tokens = this->m_db->get_current_staked_token_sum();
    ASSERT_EQ(number_of_locked_tokens, 300 * SAFEX_TOKEN); //100+400+100-100+200-400

    uint64_t fee_sum = this->m_db->get_network_fee_sum_for_interval(2);
    std::cout << "Fee sum:" << fee_sum << std::endl;
    ASSERT_EQ(fee_sum, 14.5 * SAFEX_CASH_COIN); // 2 + 12.5



    ASSERT_NO_THROW(this->m_db->close());

  }

#endif


}  // anonymous namespace
