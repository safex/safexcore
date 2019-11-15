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
// Parts of this file are originally copyright (c) 2017-2018 The Monero Project

#include "gtest/gtest.h"
#include "safex/command.h"
#include <vector>
#include <iostream>

#include "blockchain_db/blockchain_db.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/hardfork.h"


using namespace safex;


class TestBlockchainDB : public cryptonote::BlockchainDB
{
  public:
    TestBlockchainDB()
    {};

    virtual void open(const std::string &filename, const int db_flags = 0)
    {}

    virtual void close()
    {}

    virtual void sync()
    {}

    virtual void safesyncmode(const bool onoff)
    {}

    virtual void reset()
    {}

    virtual std::vector<std::string> get_filenames() const
    { return std::vector<std::string>(); }

    virtual std::string get_db_name() const
    { return std::string(); }

    virtual bool lock()
    { return true; }

    virtual void unlock()
    {}

    virtual bool batch_start(uint64_t batch_num_blocks = 0, uint64_t batch_bytes = 0)
    { return true; }

    virtual void batch_stop()
    {}

    virtual void set_batch_transactions(bool)
    {}

    virtual void block_txn_start(bool readonly = false)
    {}

    virtual void block_txn_stop()
    {}

    virtual void block_txn_abort()
    {}

    virtual void drop_hard_fork_info()
    {}

    virtual bool block_exists(const crypto::hash &h, uint64_t *height) const
    { return false; }

    virtual cryptonote::blobdata get_block_blob_from_height(const uint64_t &height) const
    { return cryptonote::t_serializable_object_to_blob(get_block_from_height(height)); }

    virtual cryptonote::blobdata get_block_blob(const crypto::hash &h) const
    { return cryptonote::blobdata(); }

    virtual bool get_tx_blob(const crypto::hash &h, cryptonote::blobdata &tx) const
    { return false; }

    virtual uint64_t get_block_height(const crypto::hash &h) const
    { return 0; }

    virtual cryptonote::block_header get_block_header(const crypto::hash &h) const
    { return cryptonote::block_header(); }

    virtual uint64_t get_block_timestamp(const uint64_t &height) const
    { return 0; }

    virtual uint64_t get_top_block_timestamp() const
    { return 0; }

    virtual size_t get_block_size(const uint64_t &height) const
    { return 128; }

    virtual cryptonote::difficulty_type get_block_cumulative_difficulty(const uint64_t &height) const
    { return 10; }

    virtual cryptonote::difficulty_type get_block_difficulty(const uint64_t &height) const
    { return 0; }

    virtual uint64_t get_block_already_generated_coins(const uint64_t &height) const
    { return 10000000000; }

    virtual uint64_t get_block_already_migrated_tokens(const uint64_t &height) const
    { return 10000000000; }

    virtual crypto::hash get_block_hash_from_height(const uint64_t &height) const
    { return crypto::hash(); }

    virtual std::vector<cryptonote::block> get_blocks_range(const uint64_t &h1, const uint64_t &h2) const
    { return std::vector<cryptonote::block>(); }

    virtual std::vector<crypto::hash> get_hashes_range(const uint64_t &h1, const uint64_t &h2) const
    { return std::vector<crypto::hash>(); }

    virtual crypto::hash top_block_hash() const
    { return crypto::hash(); }

    virtual cryptonote::block get_top_block() const
    { return cryptonote::block(); }

    virtual uint64_t height() const
    { return blocks.size(); }

    virtual bool tx_exists(const crypto::hash &h) const
    { return false; }

    virtual bool tx_exists(const crypto::hash &h, uint64_t &tx_index) const
    { return false; }

    virtual uint64_t get_tx_unlock_time(const crypto::hash &h) const
    { return 0; }

    virtual cryptonote::transaction get_tx(const crypto::hash &h) const
    { return cryptonote::transaction(); }

    virtual bool get_tx(const crypto::hash &h, cryptonote::transaction &tx) const
    { return false; }

    virtual uint64_t get_tx_count() const
    { return 0; }

    virtual std::vector<cryptonote::transaction> get_tx_list(const std::vector<crypto::hash> &hlist) const
    { return std::vector<cryptonote::transaction>(); }

    virtual uint64_t get_tx_block_height(const crypto::hash &h) const
    { return 0; }

    virtual uint64_t get_num_outputs(const uint64_t &amount, const cryptonote::tx_out_type output_type) const
    { return 1; }

    virtual uint64_t get_num_outputs(const cryptonote::tx_out_type output_type) const {return 1;}

    virtual uint64_t get_indexing_base() const
    { return 0; }

    virtual cryptonote::output_data_t get_output_key(const uint64_t &amount, const uint64_t &index, const cryptonote::tx_out_type output_type)
    { return cryptonote::output_data_t(); }

    virtual cryptonote::output_advanced_data_t get_output_key(const cryptonote::tx_out_type output_type, const uint64_t output_id) {return cryptonote::output_advanced_data_t{};}

    virtual cryptonote::tx_out_index get_output_tx_and_index_from_global(const uint64_t &index) const
    { return cryptonote::tx_out_index(); }

    virtual cryptonote::tx_out_index get_output_tx_and_index(const uint64_t &amount, const uint64_t &index, const cryptonote::tx_out_type output_type) const
    { return cryptonote::tx_out_index(); }

    virtual void get_output_tx_and_index(const uint64_t &amount, const std::vector<uint64_t> &offsets, std::vector<cryptonote::tx_out_index> &indices, const cryptonote::tx_out_type output_type) const
    {}

    virtual void get_amount_output_key(const uint64_t &amount, const std::vector<uint64_t> &offsets,
                                       std::vector<cryptonote::output_data_t> &outputs,
                                       const cryptonote::tx_out_type output_type, bool allow_partial = false)
    {}

    virtual void get_advanced_output_key(const std::vector<uint64_t> &output_ids, std::vector<cryptonote::output_advanced_data_t> &outputs,
            const cryptonote::tx_out_type output_type, bool allow_partial = false)
    {}

    virtual bool can_thread_bulk_indices() const
    { return false; }

    virtual std::vector<uint64_t> get_tx_output_indices(const crypto::hash &h) const
    { return std::vector<uint64_t>(); }

    virtual std::vector<uint64_t> get_tx_amount_output_indices(const uint64_t tx_index) const
    { return std::vector<uint64_t>(); }

    virtual bool has_key_image(const crypto::key_image &img) const
    { return false; }

    virtual void remove_block()
    { blocks.pop_back(); }

    virtual uint64_t add_transaction_data(const crypto::hash &blk_hash, const cryptonote::transaction &tx, const crypto::hash &tx_hash)
    { return 0; }

    virtual void remove_transaction_data(const crypto::hash &tx_hash, const cryptonote::transaction &tx)
    {}

    virtual uint64_t add_output(const crypto::hash &tx_hash, const cryptonote::tx_out &tx_output, const uint64_t &local_index, const uint64_t unlock_time, const rct::key *commitment)
    { return 0; }

    virtual void add_tx_amount_output_indices(const uint64_t tx_index, const std::vector<uint64_t> &amount_output_indices)
    {}

    virtual void add_spent_key(const crypto::key_image &k_image)
    {}

    virtual void remove_spent_key(const crypto::key_image &k_image)
    {}

    virtual void process_command_input(const cryptonote::txin_to_script &txin) {}

    virtual uint64_t update_network_fee_sum_for_interval(const uint64_t interval_starting_block, const uint64_t collected_fee){return 0;}
    virtual uint64_t update_staked_token_for_interval(const uint64_t interval, const uint64_t new_locked_tokens_in_interval) { return 0;}

    virtual bool for_all_key_images(std::function<bool(const crypto::key_image &)>) const
    { return true; }

    virtual bool for_blocks_range(const uint64_t &, const uint64_t &, std::function<bool(uint64_t, const crypto::hash &, const cryptonote::block &)>) const
    { return true; }

    virtual bool for_all_transactions(std::function<bool(const crypto::hash &, const cryptonote::transaction &)>) const
    { return true; }

    virtual bool for_all_outputs(std::function<bool(uint64_t amount, const crypto::hash &tx_hash, uint64_t height, size_t tx_idx)> f, const cryptonote::tx_out_type output_type) const
    { return true; }

    virtual bool for_all_outputs(uint64_t amount, const std::function<bool(uint64_t height)> &f, const cryptonote::tx_out_type output_type) const
    { return true; }

    virtual bool for_all_advanced_outputs(std::function<bool(const crypto::hash &tx_hash, uint64_t height, uint64_t output_id, const cryptonote::txout_to_script& txout)> f, const cryptonote::tx_out_type output_type) const { return true;}

    virtual bool is_read_only() const
    { return false; }

    virtual std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>> get_output_histogram(const std::vector<uint64_t> &amounts, bool unlocked, uint64_t recent_cutoff, const cryptonote::tx_out_type output_type) const
    { return std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>>(); }

    virtual void add_txpool_tx(const cryptonote::transaction &tx, const cryptonote::txpool_tx_meta_t &details)
    {}

    virtual void update_txpool_tx(const crypto::hash &txid, const cryptonote::txpool_tx_meta_t &details)
    {}

    virtual uint64_t get_txpool_tx_count(bool include_unrelayed_txes = true) const
    { return 0; }

    virtual bool txpool_has_tx(const crypto::hash &txid) const
    { return false; }

    virtual void remove_txpool_tx(const crypto::hash &txid)
    {}

    virtual bool get_txpool_tx_meta(const crypto::hash &txid, cryptonote::txpool_tx_meta_t &meta) const
    { return false; }

    virtual bool get_txpool_tx_blob(const crypto::hash &txid, cryptonote::blobdata &bd) const
    { return false; }

    virtual cryptonote::blobdata get_txpool_tx_blob(const crypto::hash &txid) const
    { return ""; }

    virtual bool for_all_txpool_txes(std::function<bool(const crypto::hash &, const cryptonote::txpool_tx_meta_t &, const cryptonote::blobdata *)>, bool include_blob = false, bool include_unrelayed_txes = false) const
    { return false; }

    virtual uint64_t get_current_staked_token_sum()  const override { return 0;}
    virtual uint64_t get_staked_token_sum_for_interval(const uint64_t interval) const override { return 0;};
    virtual uint64_t get_network_fee_sum_for_interval(const uint64_t interval) const override {return 0;}
    virtual std::vector<uint64_t> get_token_stake_expiry_outputs(const uint64_t block_height) const override {return std::vector<uint64_t>{};}
    virtual bool get_interval_interest_map(const uint64_t start_height, const uint64_t  end_height, safex::map_interval_interest &map) const override {return true;}
    virtual bool get_account_key(const safex::account_username &username, crypto::public_key &pkey) const { return true;}
    virtual bool get_account_data(const safex::account_username &username, std::vector<uint8_t> &data) const { return true;}

    virtual void add_block(const cryptonote::block &blk, const size_t &block_size, const cryptonote::difficulty_type &cumulative_difficulty,
            const uint64_t &coins_generated, const uint64_t &tokens_migrated, const crypto::hash &blk_hash)
    {
      blocks.push_back(blk);
    }

    virtual cryptonote::block get_block_from_height(const uint64_t &height) const
    {
      return blocks.at(height);
    }

    virtual void set_hard_fork_version(uint64_t height, uint8_t version)
    {
      if (versions.size() <= height)
        versions.resize(height + 1);
      versions[height] = version;
    }

    virtual uint8_t get_hard_fork_version(uint64_t height) const
    {
      return versions.at(height);
    }

    virtual void check_hard_fork_info()
    {}

  private:
    std::vector<cryptonote::block> blocks;
    std::deque<uint8_t> versions;
};


TEST(SafexCommandParsing, HandlesTokenLock)
{

  token_stake command1{SAFEX_COMMAND_PROTOCOL_VERSION, 2000};

  //serialize
  std::vector<uint8_t> serialized_command;
  safex_command_serializer::serialize_safex_object(command1, serialized_command);



  command_t command_type = safex_command_serializer::get_command_type(serialized_command);
  ASSERT_EQ(command_type, command_t::token_stake) << "Token stake command type not properly parsed from binary blob";

  //deserialize
  std::unique_ptr<safex::command> command2 = safex_command_serializer::parse_safex_object(serialized_command, command_t::token_stake);

  ASSERT_EQ(command1.get_version(), command2->get_version()) << "Original and deserialized command must have same version";
  ASSERT_EQ(command1.get_command_type(), command2->get_command_type()) << "Original and deserialized command must have same command type";
  ASSERT_EQ(command1.get_staked_token_amount(), dynamic_cast<safex::token_stake*>(command2.get())->get_staked_token_amount()) << "Original and deserialized command must have same locked amount";

}

TEST(SafexCommandParsing, HandlesTokenCollect)
{

  token_collect command1{SAFEX_COMMAND_PROTOCOL_VERSION, 2000};

  //serialize
  std::vector<uint8_t> serialized_command;
  safex_command_serializer::serialize_safex_object(command1, serialized_command);

  command_t command_type = safex_command_serializer::get_command_type(serialized_command);
  ASSERT_EQ(command_type, command_t::token_collect) << "Token unlock command type not properly parsed from binary blob";

  //deserialize
  std::unique_ptr<safex::command> command2 = safex_command_serializer::parse_safex_object(serialized_command, command_t::token_collect);

  ASSERT_EQ(command1.get_version(), command2->get_version()) << "Original and deserialized command must have same version";
  ASSERT_EQ(command1.get_command_type(), command2->get_command_type()) << "Original and deserialized command must have same command type";
  ASSERT_EQ(command1.get_staked_token_output_index(), dynamic_cast<safex::token_collect*>(command2.get())->get_staked_token_output_index()) << "Original and deserialized command must have same output index";

}

TEST(SafexCommandParsing, HandlesCorruptedArrayOfBytes)
{

  std::vector<uint8_t> serialized_command = {0x32, 0x32, 0x13, 0x43, 0x12, 0x3, 0x4, 0x5, 0x5, 0x6, 0x32, 0x12, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};

  //deserialize
  EXPECT_THROW(safex_command_serializer::parse_safex_object(serialized_command, command_t::token_stake), safex::command_exception);

}


TEST(SafexCommandCreation, HandlesUnknownProtocolVersion)
{

  try
  {
    token_stake command1{SAFEX_COMMAND_PROTOCOL_VERSION + 1, 2000};
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



namespace
{


  class SafexCommandExecution : public ::testing::Test
  {
    public:
      SafexCommandExecution() {
        crypto::public_key pubKey;
        epee::string_tools::hex_to_pod("229d8c9229ba7aaadcd575cc825ac2bd0301fff46cc05bd01110535ce43a15d1", pubKey);
        keys.push_back(pubKey);

      }
    protected:
      std::vector<crypto::public_key> keys;
      TestBlockchainDB db;
  };
}

TEST_F(SafexCommandExecution, TokenLockExecute)
{

  try
  {


    cryptonote::txin_to_script txinput = AUTO_VAL_INIT(txinput);
    txinput.command_type = command_t::token_stake;
    txinput.token_amount = 10000*SAFEX_TOKEN;
    token_stake command1{SAFEX_COMMAND_PROTOCOL_VERSION, 10000*SAFEX_TOKEN};
    safex_command_serializer::serialize_safex_object(command1, txinput.script);

    std::unique_ptr<safex::command> command2 = safex_command_serializer::parse_safex_object(txinput.script, command_t::token_stake);
    std::unique_ptr<execution_result> result{command2->execute(this->db, txinput)};




    std::cout << "Token amount: " << static_cast<token_stake_result *>(result.get())->token_amount << " status:" << static_cast<int>(result->status)
    << " block number:" << static_cast<token_stake_result*>(result.get())->block_number << std::endl;
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


TEST_F(SafexCommandExecution, TokenLockExceptions)
{

  try
  {

    cryptonote::txin_to_script txinput = AUTO_VAL_INIT(txinput);
    txinput.token_amount = 8000;
    txinput.command_type = command_t::token_stake;
    token_stake command1{SAFEX_COMMAND_PROTOCOL_VERSION, 8000};
    safex_command_serializer::serialize_safex_object(command1, txinput.script);

    std::unique_ptr<safex::command> command2 = safex_command_serializer::parse_safex_object(txinput.script, command_t::token_stake);

    std::unique_ptr<execution_result> result{command2->execute(this->db, txinput)};
    FAIL() << "Should throw exception with minimum amount of tokens to lock";

  }
  catch (safex::command_exception &exception)
  {
    ASSERT_STREQ(std::string("Staked input is not whole token amount").c_str(), std::string(exception.what()).c_str());
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

    cryptonote::txin_to_script txinput = AUTO_VAL_INIT(txinput);
    txinput.token_amount = 19000;
    txinput.command_type = command_t::token_stake;
    token_stake command1{SAFEX_COMMAND_PROTOCOL_VERSION, 11000};
    safex_command_serializer::serialize_safex_object(command1, txinput.script);

    std::unique_ptr<safex::command> command2 = safex_command_serializer::parse_safex_object(txinput.script, command_t::token_stake);

    std::unique_ptr<execution_result> result{command2->execute(this->db, txinput)};
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


TEST_F(SafexCommandExecution, TokenUnlockExecuteWrongType)
{

  try
  {

    cryptonote::txin_to_script txinput = AUTO_VAL_INIT(txinput);
    txinput.token_amount = 10000; //unlock 10k tokens
    txinput.command_type = command_t::token_unstake;
    txinput.key_offsets.push_back(23);
    uint64_t locked_token_output_index = 23;
    token_unstake command1{SAFEX_COMMAND_PROTOCOL_VERSION, locked_token_output_index};
    safex_command_serializer::serialize_safex_object(command1, txinput.script);

    std::unique_ptr<safex::command> command2 = safex_command_serializer::parse_safex_object(txinput.script, command_t::token_stake);
    std::unique_ptr<execution_result> result{command2->execute(db, txinput)};

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


TEST_F(SafexCommandExecution, TokenUnlockExecute)
{

  try
  {

    cryptonote::txin_to_script txinput = AUTO_VAL_INIT(txinput);
    txinput.token_amount = 120000; //unlock 120k tokens
    txinput.command_type = command_t::token_unstake;
    txinput.key_offsets.push_back(23);
    uint64_t locked_token_output_index = 23;
    token_unstake command1{SAFEX_COMMAND_PROTOCOL_VERSION, locked_token_output_index};
    safex_command_serializer::serialize_safex_object(command1, txinput.script);

    std::unique_ptr<safex::command> command2 = safex_command_serializer::parse_safex_object(txinput.script, command_t::token_unstake);
    std::unique_ptr<execution_result> rslt{command2->execute(this->db, txinput)};
    token_unstake_result* result = static_cast<token_unstake_result *>(rslt.get());

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
}