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
#include <cstdio>
#include <iostream>
#include <chrono>

#include "gtest/gtest.h"

#include "string_tools.h"
#include "blockchain_db/blockchain_db.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "safex/safex_account.h"
#include "safex/safex_offer.h"
#include "safex/safex_purchase.h"
#include "safex_test_common.h"


using namespace cryptonote;
using epee::string_tools::pod_to_hex;

#define ASSERT_HASH_EQ(a, b) ASSERT_EQ(pod_to_hex(a), pod_to_hex(b))

namespace
{  // anonymous namespace

  const int NUMBER_OF_BLOCKS = 30;
  const int NUMBER_OF_BLOCKS1 = 15;
  const int NUMBER_OF_BLOCKS2 = 20;
  const int NUMBER_OF_BLOCKS3 = 30;
  const uint64_t default_miner_fee = ((uint64_t) 500000000);
  const std::string bitcoin_tx_hashes_str[6] = {"3b7ac2a66eded32dcdc61f0fec7e9ddb30ccb3c6f5f06c0743c786e979130c5f", "3c904e67190d2d8c5cc93147c1a3ead133c61fc3fa578915e9bf95544705e63c",
                                                "2d825e690c4cb904556285b74a6ce565f16ba9d2f09784a7e5be5f7cdb05ae1d", "89352ec1749c872146eabddd56cd0d1492a3be6d2f9df98f6fbbc0d560120182"};


  template<typename T>
  class SimplePurchaseTest : public testing::Test
  {
    protected:
      safex::safex_offer create_demo_safex_offer(std::string title, uint64_t price, uint8_t quantity, std::string desc,safex::safex_account_key_handler keys, safex::safex_account curr_account) {

          safex::safex_price m_safex_price1{price,price,5};

          return safex::safex_offer(title, quantity, m_safex_price1,
                               desc, true, keys.get_keys(), curr_account.username);
      }

      SimplePurchaseTest() : m_db(new T(false, cryptonote::network_type::FAKECHAIN)), m_hardfork(*m_db, 1, 0)
      {
        m_test_sizes = std::vector<size_t>(NUMBER_OF_BLOCKS, 0);
        m_test_coins = std::vector<uint64_t>(NUMBER_OF_BLOCKS, 60);
        m_test_coins[0] = 2000 * SAFEX_CASH_COIN; //genesis tx airdrop
        m_test_tokens = std::vector<uint64_t>(NUMBER_OF_BLOCKS, 0);
        m_test_tokens[0] = 4000 * SAFEX_TOKEN;
        m_test_diffs = std::vector<difficulty_type>(NUMBER_OF_BLOCKS, 200);
        m_test_diffs[0] = 1;
        m_test_diffs[1] = 100;
        m_test_diffs[2] = 180;

        m_miner_acc.generate();
        m_users_acc[0].generate();
        m_users_acc[1].generate();

        m_safex_account1_keys.generate();
        m_safex_account2_keys.generate();



        m_safex_account1.username = "user1";
        m_safex_account1.pkey = m_safex_account1_keys.get_keys().m_public_key;
        m_safex_account1.account_data = {'s','m','o','r'};
        m_safex_account2.username = "user2";
        m_safex_account2.pkey = m_safex_account2_keys.get_keys().m_public_key;

        std::cout << "Alice public key: " << epee::string_tools::pod_to_hex(m_safex_account1_keys.get_keys().m_public_key) << std::endl;
        std::cout << "Alice private key: " << epee::string_tools::pod_to_hex(m_safex_account1_keys.get_keys().m_secret_key) << std::endl;

        const std::string data1_new_str = "Another data tesst for edit";
        data1_new = std::vector<uint8_t>(data1_new_str.begin(), data1_new_str.end());


        m_safex_offer[0] = create_demo_safex_offer("Apple",10*SAFEX_CASH_COIN,10,"This is an apple", m_safex_account1_keys, m_safex_account1);
        m_safex_offer[1] = create_demo_safex_offer("Barbie",50*SAFEX_CASH_COIN,30,"This is a Barbie",m_safex_account2_keys, m_safex_account2);




        m_safex_purchase = safex::safex_purchase{1, m_safex_offer[0].price, m_safex_offer[0].offer_id, true, 1, safex::safex_purchase::safex_purchase_started};

        offers_total_fee = m_safex_purchase.price.price*5/100;


                  std::string new_str_desc{"Now without worms!!"};
        std::vector<uint8_t> new_desc{new_str_desc.begin(),new_str_desc.end()};
        m_edited_safex_offer = m_safex_offer[0];
        m_edited_safex_offer.description = new_desc;


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
            //distribute tokens and coins to accounts as starter
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();                                                           \
            construct_token_tx_to_key(m_txmap, m_blocks, tx, m_users_acc[0], m_users_acc[1],  1000 * SAFEX_TOKEN, default_miner_fee, 0);
            m_txmap[get_transaction_hash(tx)] = tx;

            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx2 = tx_list.back();                                                           \
            construct_tx_to_key(m_txmap, m_blocks, tx2, m_miner_acc, m_users_acc[0], 100 * SAFEX_CASH_COIN, default_miner_fee, 0);
            m_txmap[get_transaction_hash(tx2)] = tx2;

            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx3 = tx_list.back();                                                           \
            construct_tx_to_key(m_txmap, m_blocks, tx3, m_miner_acc, m_users_acc[1], 200 * SAFEX_CASH_COIN, default_miner_fee, 0);
            m_txmap[get_transaction_hash(tx3)] = tx3;
          }
          else if (i == 5)
          {
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();                                                           \
            construct_create_account_transaction(m_txmap, m_blocks, tx, m_users_acc[0], default_miner_fee, 0, m_safex_account1.username, m_safex_account1.pkey, m_safex_account1.account_data, m_safex_account1_keys.get_keys());
            m_txmap[get_transaction_hash(tx)] = tx;

            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx2 = tx_list.back();                                                           \
            construct_create_account_transaction(m_txmap, m_blocks, tx2, m_users_acc[1], default_miner_fee, 0, m_safex_account2.username, m_safex_account2.pkey, m_safex_account2.account_data, m_safex_account2_keys.get_keys());
            m_txmap[get_transaction_hash(tx2)] = tx2;
          }
          else if (i == 7)
          {
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();                                                           \
            construct_create_offer_transaction(m_txmap, m_blocks, tx, m_users_acc[0], default_miner_fee, 0, m_safex_account1.pkey, m_safex_offer[0], m_safex_account1_keys.get_keys());
            m_txmap[get_transaction_hash(tx)] = tx;

            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx2 = tx_list.back();                                                           \
            construct_create_offer_transaction(m_txmap, m_blocks, tx2, m_users_acc[1], default_miner_fee, 0, m_safex_account2.pkey, m_safex_offer[1], m_safex_account2_keys.get_keys());
            m_txmap[get_transaction_hash(tx2)] = tx2;
          }
          else if (i == 12)
          {
              tx_list.resize(tx_list.size() + 1);
              cryptonote::transaction &tx = tx_list.back();                                                           \
              construct_create_purchase_transaction(m_txmap, m_blocks, tx, m_users_acc[0], default_miner_fee, 0, m_safex_purchase,m_users_acc[1].get_keys().m_account_address);
              m_txmap[get_transaction_hash(tx)] = tx;
          }
          else if (i == 14)
          {

          }
          else if (i == 16)
          {

          }
          else if (i == 25)
          {
              tx_list.resize(tx_list.size() + 1);
              cryptonote::transaction &tx = tx_list.back();                                                           \
              construct_close_offer_transaction(m_txmap, m_blocks, tx, m_users_acc[0], default_miner_fee, 0, m_safex_account1.pkey, m_safex_offer[0].offer_id, m_safex_account1_keys.get_keys());
              m_txmap[get_transaction_hash(tx)] = tx;
          }


          construct_block(blk, i, prev_hash, m_miner_acc, 0, m_test_sizes[i], tx_list);

          m_txs.push_back(std::vector<cryptonote::transaction>{tx_list.begin(), tx_list.end()});
          m_blocks.push_back(blk);
        }
      }


      ~SimplePurchaseTest()
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

      safex::safex_account_key_handler m_safex_account1_keys{};
      safex::safex_account_key_handler m_safex_account2_keys{};
      safex::safex_account m_safex_account1;
      safex::safex_account m_safex_account2;

      safex::safex_offer m_safex_offer[2];

      safex::safex_offer m_edited_safex_offer;

      safex::safex_purchase m_safex_purchase;

      std::vector<uint8_t> data1_new;

      uint64_t offers_total_fee;


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

  TYPED_TEST_CASE(SimplePurchaseTest, implementations);

#if 1

  TYPED_TEST(SimplePurchaseTest, CreateOfferCommand) {
        boost::filesystem::path tempPath = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
        std::string dirPath = tempPath.string();

        bool result;

        this->set_prefix(dirPath);

        // make sure open does not throw
        ASSERT_NO_THROW(this->m_db->open(dirPath));
        this->get_filenames();
        this->init_hard_fork();

        for (int i = 0; i < NUMBER_OF_BLOCKS1; i++) {
            ASSERT_NO_THROW(this->m_db->add_block(this->m_blocks[i], this->m_test_sizes[i], this->m_test_diffs[i],
                                                  this->m_test_coins[i], this->m_test_tokens[i], this->m_txs[i]));
        }
        //Checking created offers
        for (auto safex_offer: this->m_safex_offer) {

            safex::safex_offer saved_offer;
            result = this->m_db->get_offer(safex_offer.offer_id,saved_offer);
            ASSERT_TRUE(result);
            ASSERT_TRUE(std::equal(safex_offer.description.begin(), safex_offer.description.end(),
                                   saved_offer.description.begin()));
            ASSERT_EQ(safex_offer.title,saved_offer.title);

            std::string username;
            result = this->m_db->get_offer_seller(safex_offer.offer_id, username);
            ASSERT_TRUE(result);
            ASSERT_EQ(username.compare(safex_offer.seller), 0);

            safex::safex_price price;
            result = this->m_db->get_offer_price(safex_offer.offer_id, price);
            ASSERT_TRUE(result);
            ASSERT_EQ(memcmp((void *)&price, (void *)&safex_offer.price, sizeof(price)), 0);

            uint64_t quantity;
            result = this->m_db->get_offer_quantity(safex_offer.offer_id, quantity);
            ASSERT_TRUE(result);
            ASSERT_EQ(safex_offer.quantity, quantity);

            bool active;
            result = this->m_db->get_offer_active_status(safex_offer.offer_id, active);
            ASSERT_TRUE(result);
            ASSERT_EQ(safex_offer.active, active);

        }

        for (int i = NUMBER_OF_BLOCKS1; i < NUMBER_OF_BLOCKS2; i++) {
            ASSERT_NO_THROW(this->m_db->add_block(this->m_blocks[i], this->m_test_sizes[i], this->m_test_diffs[i],
                                                  this->m_test_coins[i], this->m_test_tokens[i], this->m_txs[i]));
        }
        //Checking edited offer
        safex::safex_offer saved_offer;

        for (int i = NUMBER_OF_BLOCKS2; i < NUMBER_OF_BLOCKS3; i++) {
            ASSERT_NO_THROW(this->m_db->add_block(this->m_blocks[i], this->m_test_sizes[i], this->m_test_diffs[i],
                                                  this->m_test_coins[i], this->m_test_tokens[i], this->m_txs[i]));
        }
        //Checking closed offer
        safex::safex_offer closed_offer;
        result = this->m_db->get_offer(this->m_edited_safex_offer.offer_id,saved_offer);
        ASSERT_FALSE(result);

        uint64_t fee_sum = 0;

        for(int i=0;i<NUMBER_OF_BLOCKS3; i++) {
            fee_sum += this->m_db->get_network_fee_sum_for_interval(i);
        }
        ASSERT_EQ(fee_sum,this->offers_total_fee);

    ASSERT_NO_THROW(this->m_db->close());

  }
#endif

}  // anonymous namespace
