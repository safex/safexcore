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
#include "../safex_test_common.h"

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

    class SafexStakeCommand : public ::testing::Test
    {
     public:
        SafexStakeCommand() {
          crypto::public_key pubKey;
          epee::string_tools::hex_to_pod("229d8c9229ba7aaadcd575cc825ac2bd0301fff46cc05bd01110535ce43a15d1", pubKey);
          keys.push_back(pubKey);
       }
     protected:
       std::vector<crypto::public_key> keys;
       TestDB m_db;
   };

    class SafexUnstakeCommand : public ::testing::Test
    {
     public:
        SafexUnstakeCommand() {
          crypto::public_key pubKey;
          epee::string_tools::hex_to_pod("229d8c9229ba7aaadcd575cc825ac2bd0301fff46cc05bd01110535ce43a15d1", pubKey);
          keys.push_back(pubKey);
       }
     protected:
       std::vector<crypto::public_key> keys;
       TestDB m_db;
   };

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
            //token unstake transaction
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();
            construct_token_unstake_transaction(m_txmap, m_blocks, tx, m_users_acc[1], m_users_acc[1], 100 * SAFEX_TOKEN, default_miner_fee, 0); //unstake 100
            m_txmap[get_transaction_hash(tx)] = tx;
          }
          else if (i == 520)
          {
            //token unstake transaction
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();
            construct_token_unstake_transaction(m_txmap, m_blocks, tx, m_users_acc[0], m_users_acc[0], 400 * SAFEX_TOKEN, default_miner_fee, 0); //unstake 400
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

  TEST_F(SafexStakeCommand, HandlesCorruptedArrayOfBytes)
  {

    std::vector<uint8_t> serialized_command = {0x32, 0x32, 0x13, 0x43, 0x12, 0x3, 0x4, 0x5, 0x5, 0x6, 0x32, 0x12, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};

    //deserialize
    EXPECT_THROW(safex::safex_command_serializer::parse_safex_object(serialized_command, safex::command_t::token_stake), safex::command_exception);

  }

  TEST_F(SafexUnstakeCommand, HandlesCorruptedArrayOfBytes)
  {

    std::vector<uint8_t> serialized_command = {0x32, 0x32, 0x13, 0x43, 0x12, 0x3, 0x4, 0x5, 0x5, 0x6, 0x32, 0x12, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};

    //deserialize
    EXPECT_THROW(safex::safex_command_serializer::parse_safex_object(serialized_command, safex::command_t::token_unstake), safex::command_exception);

  }

  TEST_F(SafexStakeCommand, HandlesUnknownProtocolVersion)
  {

    try
    {
      safex::token_stake command1{SAFEX_COMMAND_PROTOCOL_VERSION + 1, 2000};
      FAIL() << "Should throw exception with message invalid command";
    }
    catch (safex::command_exception &exception)
    {
      ASSERT_STREQ(std::string(("Unsupported command protocol version " + std::to_string(SAFEX_COMMAND_PROTOCOL_VERSION + 1))).c_str(), std::string(exception.what()).c_str());
    }
    catch (...)
    {
      FAIL() << "Unexpected exception";
    }
  }

  TEST_F(SafexUnstakeCommand, HandlesUnknownProtocolVersion)
  {

    try
    {
      safex::token_unstake command1{SAFEX_COMMAND_PROTOCOL_VERSION + 1, 1};
      FAIL() << "Should throw exception with message invalid command";
    }
    catch (safex::command_exception &exception)
    {
      ASSERT_STREQ(std::string(("Unsupported command protocol version " + std::to_string(SAFEX_COMMAND_PROTOCOL_VERSION + 1))).c_str(), std::string(exception.what()).c_str());
    }
    catch (...)
    {
      FAIL() << "Unexpected exception";
    }
  }

  TEST_F(SafexStakeCommand, HandlesCommandParsing)
  {

    safex::token_stake command1{SAFEX_COMMAND_PROTOCOL_VERSION, 2000};

    //serialize
    std::vector<uint8_t> serialized_command;
    safex::safex_command_serializer::serialize_safex_object(command1, serialized_command);

    safex::command_t command_type = safex::safex_command_serializer::get_command_type(serialized_command);
    ASSERT_EQ(command_type, safex::command_t::token_stake) << "Token stake command type not properly parsed from binary blob";

    //deserialize
    std::unique_ptr<safex::command> command2 = safex::safex_command_serializer::parse_safex_object(serialized_command, safex::command_t::token_stake);

    ASSERT_EQ(command1.get_version(), command2->get_version()) << "Original and deserialized command must have same version";
    ASSERT_EQ(command1.get_command_type(), command2->get_command_type()) << "Original and deserialized command must have same command type";
    ASSERT_EQ(command1.get_staked_token_amount(), dynamic_cast<safex::token_stake*>(command2.get())->get_staked_token_amount()) << "Original and deserialized command must have same staked amount";

  }

  TEST_F(SafexUnstakeCommand, HandlesCommandParsing)
  {

    safex::token_unstake command1{SAFEX_COMMAND_PROTOCOL_VERSION, 1};

    //serialize
    std::vector<uint8_t> serialized_command;
    safex::safex_command_serializer::serialize_safex_object(command1, serialized_command);

    safex::command_t command_type = safex::safex_command_serializer::get_command_type(serialized_command);
    ASSERT_EQ(command_type, safex::command_t::token_unstake) << "Token stake command type not properly parsed from binary blob";

    //deserialize
    std::unique_ptr<safex::command> command2 = safex::safex_command_serializer::parse_safex_object(serialized_command, safex::command_t::token_unstake);

    ASSERT_EQ(command1.get_version(), command2->get_version()) << "Original and deserialized command must have same version";
    ASSERT_EQ(command1.get_command_type(), command2->get_command_type()) << "Original and deserialized command must have same command type";
    ASSERT_EQ(command1.get_staked_token_output_index(), dynamic_cast<safex::token_unstake*>(command2.get())->get_staked_token_output_index()) << "Original and deserialized command must have same staked index";

  }



  TEST_F(SafexStakeCommand, TokenStakeExecute)
  {

    try
    {
      cryptonote::txin_to_script txinput = AUTO_VAL_INIT(txinput);
      txinput.command_type = safex::command_t::token_stake;
      txinput.token_amount = 10000*SAFEX_TOKEN;
      safex::token_stake command1{SAFEX_COMMAND_PROTOCOL_VERSION, 10000*SAFEX_TOKEN};
      safex::safex_command_serializer::serialize_safex_object(command1, txinput.script);

      std::unique_ptr<safex::command> command2 = safex::safex_command_serializer::parse_safex_object(txinput.script, safex::command_t::token_stake);
      std::unique_ptr<safex::execution_result> result{command2->execute(this->m_db, txinput)};

      std::cout << "Token amount: " << static_cast<safex::token_stake_result *>(result.get())->token_amount << " status:" << static_cast<int>(result->status)
      << " block number:" << static_cast<safex::token_stake_result*>(result.get())->block_number << std::endl;
    }
    catch (safex::command_exception &exception)
    {
      FAIL() << exception.what();
    }
    catch (std::exception &exception)
    {
      FAIL() << "Exception happened " << exception.what();
    }
    catch (...)
    {
      FAIL() << "Unexpected exception";
    }

  }

  TEST_F(SafexStakeCommand, TokenStakeExceptions)
  {

    // Token amount not whole
    try
    {

      cryptonote::txin_to_script txinput = AUTO_VAL_INIT(txinput);
      txinput.token_amount = 8000;
      txinput.command_type = safex::command_t::token_stake;
      safex::token_stake command1{SAFEX_COMMAND_PROTOCOL_VERSION, 8000};
      safex::safex_command_serializer::serialize_safex_object(command1, txinput.script);

      std::unique_ptr<safex::command> command2 = safex::safex_command_serializer::parse_safex_object(txinput.script, safex::command_t::token_stake);

      safex::execution_status status = command2->validate(this->m_db, txinput);
      ASSERT_EQ(status, safex::execution_status::error_stake_token_not_whole_amount);

      std::unique_ptr<safex::execution_result> result{command2->execute(this->m_db, txinput)};
      FAIL() << "Should throw exception with token amount not whole";

    }
    catch (safex::command_exception &exception)
    {

    }
    catch (std::exception &exception)
    {
      FAIL() << "Exception happened " << exception.what();
    }
    catch (...)
    {
      FAIL() << "Unexpected exception";
    }


    // Token amount not matching
    try
    {

      cryptonote::txin_to_script txinput = AUTO_VAL_INIT(txinput);
      txinput.token_amount = 19000*SAFEX_TOKEN;
      txinput.command_type = safex::command_t::token_stake;
      safex::token_stake command1{SAFEX_COMMAND_PROTOCOL_VERSION, 11000*SAFEX_TOKEN};
      safex::safex_command_serializer::serialize_safex_object(command1, txinput.script);

      std::unique_ptr<safex::command> command2 = safex::safex_command_serializer::parse_safex_object(txinput.script, safex::command_t::token_stake);

      safex::execution_status status = command2->validate(this->m_db, txinput);
      ASSERT_EQ(status, safex::execution_status::error_stake_token_amount_not_matching);

      std::unique_ptr<safex::execution_result> result{command2->execute(this->m_db, txinput)};
      FAIL() << "Should throw exception with input amount differs from token stake command amount";
    }
    catch (safex::command_exception &exception)
    {

    }
    catch (std::exception &exception)
    {
      FAIL() << "Exception happened " << exception.what();
    }
    catch (...)
    {
      FAIL() << "Unexpected exception";
    }


  }


  TEST_F(SafexStakeCommand, TokenStakeExecuteWrongType)
  {

    try
    {

      cryptonote::txin_to_script txinput = AUTO_VAL_INIT(txinput);
      txinput.token_amount = 10000*SAFEX_TOKEN; //stake 10k tokens
      txinput.command_type = safex::command_t::token_stake;
      txinput.key_offsets.push_back(23);
      uint64_t staked_token_output_index = 23;
      safex::token_stake command1{SAFEX_COMMAND_PROTOCOL_VERSION, staked_token_output_index};
      safex::safex_command_serializer::serialize_safex_object(command1, txinput.script);

      std::unique_ptr<safex::command> command2 = safex::safex_command_serializer::parse_safex_object(txinput.script, safex::command_t::token_unstake);
      std::unique_ptr<safex::execution_result> result{command2->execute(this->m_db, txinput)};

    }
    catch (safex::command_exception &exception)
    {
      ASSERT_STREQ("Could not create command, wrong command type", std::string(exception.what()).c_str());

    }
    catch (std::exception &exception)
    {
      FAIL() << "Exception happened " << exception.what();
    }
    catch (...)
    {
      FAIL() << "Unexpected exception";
    }
  }

  TEST_F(SafexUnstakeCommand, TokenUnstakeExecuteWrongType)
  {

    try
    {

      cryptonote::txin_to_script txinput = AUTO_VAL_INIT(txinput);
      txinput.token_amount = 10000; //unstake 10k tokens
      txinput.command_type = safex::command_t::token_unstake;
      txinput.key_offsets.push_back(23);
      uint64_t staked_token_output_index = 23;
      safex::token_unstake command1{SAFEX_COMMAND_PROTOCOL_VERSION, staked_token_output_index};
      safex::safex_command_serializer::serialize_safex_object(command1, txinput.script);

      std::unique_ptr<safex::command> command2 = safex::safex_command_serializer::parse_safex_object(txinput.script, safex::command_t::token_stake);
      std::unique_ptr<safex::execution_result> result{command2->execute(this->m_db, txinput)};

    }
    catch (safex::command_exception &exception)
    {
      ASSERT_STREQ("Could not create command, wrong command type", std::string(exception.what()).c_str());

    }
    catch (std::exception &exception)
    {
      FAIL() << "Exception happened " << exception.what();
    }
    catch (...)
    {
      FAIL() << "Unexpected exception";
    }
  }

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
        //here, we have unstaked 100, check current db status
        uint64_t number_of_staked_tokens51 = this->m_db->get_staked_token_sum_for_interval(51);
        uint64_t number_of_staked_tokens52 = this->m_db->get_staked_token_sum_for_interval(52);
        uint64_t number_of_staked_tokens52_cur = this->m_db->get_current_staked_token_sum();

        ASSERT_EQ(number_of_staked_tokens51, 800 * SAFEX_TOKEN);
        ASSERT_EQ(number_of_staked_tokens52, 700 * SAFEX_TOKEN);
        ASSERT_EQ(number_of_staked_tokens52_cur, 700 * SAFEX_TOKEN);
      } else if (i == 520) {
        //here, we have unstaked 400, check current db status
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

  TYPED_TEST(SafexBlockchainFeeTest, TokenUnstakeExecute)
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
    }

    try
    {

      cryptonote::txin_to_script txinput = AUTO_VAL_INIT(txinput);
      txinput.token_amount = 400 * SAFEX_TOKEN; //unstake 120k tokens
      txinput.command_type = safex::command_t::token_unstake;
      txinput.key_offsets.push_back(1);
      uint64_t staked_token_output_index = 1;
      safex::token_unstake command1{SAFEX_COMMAND_PROTOCOL_VERSION, staked_token_output_index};
      safex::safex_command_serializer::serialize_safex_object(command1, txinput.script);

      std::unique_ptr<safex::command> command2 = safex::safex_command_serializer::parse_safex_object(txinput.script, safex::command_t::token_unstake);
      std::unique_ptr<safex::execution_result> rslt{command2->execute(*(this->m_db), txinput)};
      safex::token_unstake_result* result = static_cast<safex::token_unstake_result *>(rslt.get());

      std::cout << "Token amount: " << result->token_amount << " valid:" << result->valid << " block number:" << result->block_number << " interest: " << result->interest << std::endl;
    }
    catch (std::exception &exception)
    {
      FAIL() << "Exception happened " << exception.what();
    }
    catch (...)
    {
      FAIL() << "Unexpected exception";
    }

    ASSERT_NO_THROW(this->m_db->close());

  }

  TYPED_TEST(SafexBlockchainFeeTest, TokenUnstakeExceptions)
  {
    boost::filesystem::path tempPath = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
    std::string dirPath = tempPath.string();

    this->set_prefix(dirPath);

    // make sure open does not throw
    ASSERT_NO_THROW(this->m_db->open(dirPath));
    this->get_filenames();
    this->init_hard_fork();

    uint64_t minimum_stake_block_height = 10 + safex::get_safex_minumum_token_lock_period(this->m_db->get_net_type());

    for (int i = 0; i < minimum_stake_block_height; i++)
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

    // Not enough time passed
    try
    {

      cryptonote::txin_to_script txinput = AUTO_VAL_INIT(txinput);
      txinput.token_amount = 400 * SAFEX_TOKEN; //unstake 400 tokens
      txinput.command_type = safex::command_t::token_unstake;
      txinput.key_offsets.push_back(1);
      uint64_t staked_token_output_index = 0;
      safex::token_unstake command1{SAFEX_COMMAND_PROTOCOL_VERSION, staked_token_output_index};
      safex::safex_command_serializer::serialize_safex_object(command1, txinput.script);

      std::unique_ptr<safex::command> command2 = safex::safex_command_serializer::parse_safex_object(txinput.script, safex::command_t::token_unstake);

      safex::execution_status status = command2->validate(*(this->m_db), txinput);
      ASSERT_EQ(status, safex::execution_status::error_unstake_token_minimum_period);

      std::unique_ptr<safex::execution_result> rslt{command2->execute(*(this->m_db), txinput)};
      FAIL() << "Should throw exception with matching output not found";

    }
    catch (safex::command_exception &exception)
    {

    }
    catch (std::exception &exception)
    {
      FAIL() << "Exception happened " << exception.what();
    }
    catch (...)
    {
      FAIL() << "Unexpected exception";
    }


    try
    {
      this->m_db->add_block(this->m_blocks[minimum_stake_block_height], this->m_test_sizes[minimum_stake_block_height],
                            this->m_test_diffs[minimum_stake_block_height], this->m_test_coins[minimum_stake_block_height],
                            this->m_test_tokens[minimum_stake_block_height], this->m_txs[minimum_stake_block_height]);
    }
    catch (std::exception &e)
    {
      std::cout << "Error: " << e.what() << std::endl;
    }


    // Token amount offset more than one
    try
    {

      cryptonote::txin_to_script txinput = AUTO_VAL_INIT(txinput);
      txinput.token_amount = 400 * SAFEX_TOKEN; //unstake 400 tokens
      txinput.command_type = safex::command_t::token_unstake;
      txinput.key_offsets.push_back(1);
      txinput.key_offsets.push_back(12);
      uint64_t staked_token_output_index = 1;
      safex::token_unstake command1{SAFEX_COMMAND_PROTOCOL_VERSION, staked_token_output_index};
      safex::safex_command_serializer::serialize_safex_object(command1, txinput.script);

      std::unique_ptr<safex::command> command2 = safex::safex_command_serializer::parse_safex_object(txinput.script, safex::command_t::token_unstake);

      safex::execution_status status = command2->validate(*(this->m_db), txinput);
      ASSERT_EQ(status, safex::execution_status::error_unstake_token_offset_not_one);

      std::unique_ptr<safex::execution_result> rslt{command2->execute(*(this->m_db), txinput)};
      FAIL() << "Should throw exception with offsets size more than 1";

    }
    catch (safex::command_exception &exception)
    {

    }
    catch (std::exception &exception)
    {
      FAIL() << "Exception happened " << exception.what();
    }
    catch (...)
    {
      FAIL() << "Unexpected exception";
    }

    // Interest too big
    try
    {

      cryptonote::txin_to_script txinput = AUTO_VAL_INIT(txinput);
      txinput.token_amount = 400 * SAFEX_TOKEN; //unstake 400 tokens
      txinput.amount = 5000 * SAFEX_CASH_COIN;
      txinput.command_type = safex::command_t::token_unstake;
      txinput.key_offsets.push_back(1);
      uint64_t staked_token_output_index = 0;
      safex::token_unstake command1{SAFEX_COMMAND_PROTOCOL_VERSION, staked_token_output_index};
      safex::safex_command_serializer::serialize_safex_object(command1, txinput.script);

      std::unique_ptr<safex::command> command2 = safex::safex_command_serializer::parse_safex_object(txinput.script, safex::command_t::token_unstake);

      safex::execution_status status = command2->validate(*(this->m_db), txinput);
      ASSERT_EQ(status, safex::execution_status::error_unstake_token_network_fee_not_matching);

      std::unique_ptr<safex::execution_result> rslt{command2->execute(*(this->m_db), txinput)};
      FAIL() << "Should throw exception with interest too big";

    }
    catch (safex::command_exception &exception)
    {

    }
    catch (std::exception &exception)
    {
      FAIL() << "Exception happened " << exception.what();
    }
    catch (...)
    {
      FAIL() << "Unexpected exception";
    }

    // Output not found
    try
    {

      cryptonote::txin_to_script txinput = AUTO_VAL_INIT(txinput);
      txinput.token_amount = 100 * SAFEX_TOKEN; //unstake 400 tokens
      txinput.command_type = safex::command_t::token_unstake;
      txinput.key_offsets.push_back(1);
      uint64_t staked_token_output_index = 0;
      safex::token_unstake command1{SAFEX_COMMAND_PROTOCOL_VERSION, staked_token_output_index};
      safex::safex_command_serializer::serialize_safex_object(command1, txinput.script);

      std::unique_ptr<safex::command> command2 = safex::safex_command_serializer::parse_safex_object(txinput.script, safex::command_t::token_unstake);

      safex::execution_status status = command2->validate(*(this->m_db), txinput);
      ASSERT_EQ(status, safex::execution_status::error_unstake_token_output_not_found);

      std::unique_ptr<safex::execution_result> rslt{command2->execute(*(this->m_db), txinput)};
      FAIL() << "Should throw exception with matching output not found";

    }
    catch (safex::command_exception &exception)
    {

    }
    catch (std::exception &exception)
    {
      FAIL() << "Exception happened " << exception.what();
    }
    catch (...)
    {
      FAIL() << "Unexpected exception";
    }

    ASSERT_NO_THROW(this->m_db->close());

  }

#endif


}  // anonymous namespace
