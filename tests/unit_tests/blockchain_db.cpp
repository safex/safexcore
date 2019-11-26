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
#ifdef BERKELEY_DB
#include "blockchain_db/berkeleydb/db_bdb.h"
#endif
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"

using namespace cryptonote;
using epee::string_tools::pod_to_hex;

#define ASSERT_HASH_EQ(a,b) ASSERT_EQ(pod_to_hex(a), pod_to_hex(b))

namespace {  // anonymous namespace

const int NUMBER_OF_BLOCKS = 5;


// if the return type (blobdata for now) of block_to_blob ever changes
// from std::string, this might break.
bool compare_blocks(const block& a, const block& b)
{
  auto hash_a = pod_to_hex(get_block_hash(a));
  auto hash_b = pod_to_hex(get_block_hash(b));

  return hash_a == hash_b;
}

/*
void print_block(const block& blk, const std::string& prefix = "")
{
  std::cerr << prefix << ": " << std::endl
            << "\thash - " << pod_to_hex(get_block_hash(blk)) << std::endl
            << "\tparent - " << pod_to_hex(blk.prev_id) << std::endl
            << "\ttimestamp - " << blk.timestamp << std::endl
  ;
}

// if the return type (blobdata for now) of tx_to_blob ever changes
// from std::string, this might break.
bool compare_txs(const transaction& a, const transaction& b)
{
  auto ab = tx_to_blob(a);
  auto bb = tx_to_blob(b);

  return ab == bb;
}
*/

  //-----------------------------------------------------------------------------------------------------
static bool find_nonce_for_given_block(block &bl, const difficulty_type &diffic, uint64_t height)
{
  for (; bl.nonce != std::numeric_limits<uint32_t>::max(); bl.nonce++)
  {
    crypto::hash h;
    get_block_longhash(NULL, bl, h, height, 0);

    if (check_hash(h, diffic))
    {
      bl.invalidate_hashes();
      return true;
    }
  }
  bl.invalidate_hashes();
  return false;
}


template <typename T>
class BlockchainDBTest : public testing::Test
{
protected:
  BlockchainDBTest() : m_db(new T()), m_hardfork(*m_db, 1, 0)
  {
    m_test_sizes = std::vector<size_t>(NUMBER_OF_BLOCKS, 0);
    m_test_coins = std::vector<uint64_t>(NUMBER_OF_BLOCKS, 60);
    m_test_coins[0] = 10000000; //genesis tx airdrop
    m_test_tokens = std::vector<uint64_t>(NUMBER_OF_BLOCKS, 0);
    m_test_diffs = std::vector<difficulty_type>(NUMBER_OF_BLOCKS, 200);
    m_test_diffs[0] = 1;
    m_test_diffs[1] = 100;
    m_test_diffs[2] = 180;

    m_txs = std::vector<std::vector<transaction>>(1, std::vector<transaction>());

    m_miner_acc.generate();
    m_users_acc[0].generate();
    m_users_acc[1].generate();

    for (int i=0; i<NUMBER_OF_BLOCKS; i++)
    {
      block blk;
      std::list<cryptonote::transaction> tx_list;
      crypto::hash prev_hash = boost::value_initialized<crypto::hash>();/* null hash*/
      if (i > 0) prev_hash = cryptonote::get_block_hash(m_blocks[i - 1]);

      if (i > 0)
      {
        //fill inputs entry
        typedef tx_source_entry::output_entry tx_output_entry;
        std::vector <tx_source_entry> sources;
        sources.resize(sources.size() + 1);
        tx_source_entry &src = sources.back();
        src.amount = 1231 + i * 1000000;
        {
          tx_output_entry oe;
          src.push_output(0, boost::get<txout_to_key>(m_blocks[i - 1].miner_tx.vout[0].target).key, src.amount);
          src.real_out_tx_key = cryptonote::get_tx_pub_key_from_extra(m_blocks[i - 1].miner_tx);
          src.real_output = 0;
          src.real_output_in_tx_index = 0;
        }
        //fill outputs entry
        tx_destination_entry td;
        td.addr = m_users_acc[i % 2].get_keys().m_account_address;
        td.amount = 1231 + i * 1000000 - 321415 - 100 * i;
        std::vector <tx_destination_entry> destinations;
        destinations.push_back(td);

        std::vector <transaction> txs;
        transaction tx_current;
        bool r = construct_tx(m_miner_acc.get_keys(), sources, destinations, boost::none, std::vector<uint8_t>(), tx_current, 0);
        if (!r)
          std::cerr << "Failed to generate transaction!" << std::endl;

        txs.push_back(tx_current);
        tx_list.push_back(tx_current);
        m_txs.push_back(txs);
      }

      construct_block(blk, i, prev_hash, m_miner_acc, 0, m_test_sizes[i], tx_list);
      m_blocks.push_back(blk);
    }

  }

  bool construct_block(cryptonote::block& blk, uint64_t height, const crypto::hash& prev_id,
                                       const cryptonote::account_base& miner_acc, uint64_t timestamp, uint64_t already_generated_coins,
                                       std::vector<size_t>& block_sizes, const std::list<cryptonote::transaction>& tx_list, size_t &actual_block_size)
  {
    blk.major_version = CURRENT_BLOCK_MAJOR_VERSION;
    blk.minor_version = CURRENT_BLOCK_MINOR_VERSION;
    blk.timestamp = timestamp;
    blk.prev_id = prev_id;

    blk.tx_hashes.reserve(tx_list.size());
    BOOST_FOREACH(const transaction &tx, tx_list)
    {
      crypto::hash tx_hash;
      get_transaction_hash(tx, tx_hash);
      blk.tx_hashes.push_back(tx_hash);
    }

    uint64_t total_fee = 0;
    size_t txs_size = 0;
    BOOST_FOREACH(auto& tx, tx_list)
    {
      uint64_t fee = 0;
      bool r = get_tx_fee(tx, fee);
      CHECK_AND_ASSERT_MES(r, false, "wrong transaction passed to construct_block");
      total_fee += fee;
      txs_size += get_object_blobsize(tx);
    }

    blk.miner_tx = AUTO_VAL_INIT(blk.miner_tx);
    size_t target_block_size = txs_size + get_object_blobsize(blk.miner_tx);
    while (true)
    {
      if (!construct_miner_tx(height, epee::misc_utils::median(block_sizes), already_generated_coins, target_block_size, total_fee, miner_acc.get_keys().m_account_address, blk.miner_tx, blobdata(), 10))
        return false;

      actual_block_size = txs_size + get_object_blobsize(blk.miner_tx);
      if (target_block_size < actual_block_size)
      {
        target_block_size = actual_block_size;
      }
      else if (actual_block_size < target_block_size)
      {
        size_t delta = target_block_size - actual_block_size;
        blk.miner_tx.extra.resize(blk.miner_tx.extra.size() + delta, 0);
        actual_block_size = txs_size + get_object_blobsize(blk.miner_tx);
        if (actual_block_size == target_block_size)
        {
          break;
        }
        else
        {
          CHECK_AND_ASSERT_MES(target_block_size < actual_block_size, false, "Unexpected block size");
          delta = actual_block_size - target_block_size;
          blk.miner_tx.extra.resize(blk.miner_tx.extra.size() - delta);
          actual_block_size = txs_size + get_object_blobsize(blk.miner_tx);
          if (actual_block_size == target_block_size)
          {
            break;
          }
          else
          {
            CHECK_AND_ASSERT_MES(actual_block_size < target_block_size, false, "Unexpected block size");
            blk.miner_tx.extra.resize(blk.miner_tx.extra.size() + delta, 0);
            target_block_size = txs_size + get_object_blobsize(blk.miner_tx);
          }
        }
      }
      else
      {
        break;
      }
    }

    // Nonce search...
    blk.nonce = 0;
    while (!find_nonce_for_given_block(blk, 1 /*test difficulty*/, height))
      blk.timestamp++;

    return true;
  }

  bool construct_block(cryptonote::block& blk, uint64_t height, const crypto::hash& prev_id, const cryptonote::account_base& miner_acc, uint64_t timestamp, size_t &block_size,  std::list<cryptonote::transaction> tx_list)
  {
    std::vector<size_t> block_sizes;
    return construct_block(blk, height, prev_id, miner_acc, timestamp, 0, block_sizes, tx_list, block_size);
  }

  ~BlockchainDBTest() {
    delete m_db;
    remove_files();
  }

  BlockchainDB* m_db;
  HardFork m_hardfork;
  std::string m_prefix;
  std::vector<block> m_blocks;
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
    for (auto& f : m_filenames)
    {
      std::cerr << "File created by test: " << f << std::endl;
    }
  }

  void remove_files()
  {
    // remove each file the db created, making sure it starts with fname.
    for (auto& f : m_filenames)
    {
      if (boost::starts_with(f, m_prefix))
      {
        boost::filesystem::remove(f);
      }
      else
      {
        std::cerr << "File created by test not to be removed (for safety): " << f << std::endl;
      }
    }

    // remove directory if it still exists
    boost::filesystem::remove_all(m_prefix);
  }

  void set_prefix(const std::string& prefix)
  {
    m_prefix = prefix;
  }
};

using testing::Types;

typedef Types<BlockchainLMDB
#ifdef BERKELEY_DB
  , BlockchainBDB
#endif
> implementations;

TYPED_TEST_CASE(BlockchainDBTest, implementations);

TYPED_TEST(BlockchainDBTest, OpenAndClose)
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

TYPED_TEST(BlockchainDBTest, AddBlock)
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

  for (int i=0;i<NUMBER_OF_BLOCKS; i++)
    ASSERT_NO_THROW(this->m_db->add_block(this->m_blocks[i], this->m_test_sizes[i], this->m_test_diffs[i], this->m_test_coins[i], this->m_test_tokens[i], this->m_txs[i]));


  block b;
  ASSERT_TRUE(this->m_db->block_exists(get_block_hash(this->m_blocks[0])));
  ASSERT_NO_THROW(b = this->m_db->get_block(get_block_hash(this->m_blocks[0])));

  ASSERT_TRUE(compare_blocks(this->m_blocks[0], b));

  ASSERT_NO_THROW(b = this->m_db->get_block_from_height(0));

  ASSERT_TRUE(compare_blocks(this->m_blocks[0], b));

  // assert that we can't add the same block twice
  ASSERT_THROW(this->m_db->add_block(this->m_blocks[0], this->m_test_sizes[0], this->m_test_diffs[0], this->m_test_coins[0], this->m_test_tokens[0], this->m_txs[0]), TX_EXISTS);

  for (auto& h : this->m_blocks[NUMBER_OF_BLOCKS-1].tx_hashes)
  {
    transaction tx;
    ASSERT_TRUE(this->m_db->tx_exists(h));
    ASSERT_NO_THROW(tx = this->m_db->get_tx(h));
    ASSERT_HASH_EQ(h, get_transaction_hash(tx));
  }
}

TYPED_TEST(BlockchainDBTest, RetrieveBlockData)
{
  boost::filesystem::path tempPath = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
  std::string dirPath = tempPath.string();

  this->set_prefix(dirPath);

  // make sure open does not throw
  ASSERT_NO_THROW(this->m_db->open(dirPath));
  this->get_filenames();
  this->init_hard_fork();

  for (int i=0;i<NUMBER_OF_BLOCKS-1; i++)
    ASSERT_NO_THROW(this->m_db->add_block(this->m_blocks[i], this->m_test_sizes[i], this->m_test_diffs[i], this->m_test_coins[i], this->m_test_tokens[i], this->m_txs[i]));

  ASSERT_EQ(this->m_test_sizes[0], this->m_db->get_block_size(0));
  ASSERT_EQ(this->m_test_diffs[0], this->m_db->get_block_cumulative_difficulty(0));
  ASSERT_EQ(this->m_test_diffs[0], this->m_db->get_block_difficulty(0));
  ASSERT_EQ(this->m_test_coins[0], this->m_db->get_block_already_generated_coins(0));

  ASSERT_NO_THROW(this->m_db->add_block(this->m_blocks[NUMBER_OF_BLOCKS-1], this->m_test_sizes[NUMBER_OF_BLOCKS-1], this->m_test_diffs[NUMBER_OF_BLOCKS-1], this->m_test_coins[NUMBER_OF_BLOCKS-1], this->m_test_tokens[NUMBER_OF_BLOCKS-1], this->m_txs[NUMBER_OF_BLOCKS-1]));
  ASSERT_EQ(this->m_test_diffs[1] - this->m_test_diffs[0], this->m_db->get_block_difficulty(1));

  ASSERT_HASH_EQ(get_block_hash(this->m_blocks[0]), this->m_db->get_block_hash_from_height(0));

  std::vector<block> blks;
  ASSERT_NO_THROW(blks = this->m_db->get_blocks_range(0, NUMBER_OF_BLOCKS-1));
  ASSERT_EQ(NUMBER_OF_BLOCKS, blks.size());
  
  ASSERT_HASH_EQ(get_block_hash(this->m_blocks[0]), get_block_hash(blks[0]));
  ASSERT_HASH_EQ(get_block_hash(this->m_blocks[1]), get_block_hash(blks[1]));
  ASSERT_HASH_EQ(get_block_hash(this->m_blocks[NUMBER_OF_BLOCKS-1]), get_block_hash(blks[NUMBER_OF_BLOCKS-1]));

  std::vector<crypto::hash> hashes;
  ASSERT_NO_THROW(hashes = this->m_db->get_hashes_range(0, NUMBER_OF_BLOCKS-1));
  ASSERT_EQ(NUMBER_OF_BLOCKS, hashes.size());

  ASSERT_HASH_EQ(get_block_hash(this->m_blocks[0]), hashes[0]);
  ASSERT_HASH_EQ(get_block_hash(this->m_blocks[1]), hashes[1]);
  ASSERT_HASH_EQ(get_block_hash(this->m_blocks[NUMBER_OF_BLOCKS-1]), hashes[NUMBER_OF_BLOCKS-1]);
}

}  // anonymous namespace
