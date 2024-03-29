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

#include <algorithm>
#include <cstdio>
#include <boost/filesystem.hpp>
#include <boost/range/adaptor/reversed.hpp>

#include "include_base_utils.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "tx_pool.h"
#include "blockchain.h"
#include "blockchain_db/blockchain_db.h"
#include "cryptonote_basic/cryptonote_boost_serialization.h"
#include "cryptonote_config.h"
#include "cryptonote_basic/miner.h"
#include "misc_language.h"
#include "profile_tools.h"
#include "file_io_utils.h"
#include "common/int-util.h"
#include "common/threadpool.h"
#include "common/boost_serialization_helper.h"
#include "warnings.h"
#include "crypto/hash.h"
#include "crypto/hash-ops.h"
#include "cryptonote_core.h"
#include "ringct/rctSigs.h"
#include "common/perf_timer.h"

#ifdef SAFEX_PROTOBUF_RPC
 #include "cryptonote_core/protobuf/cryptonote_to_protobuf.h"
#endif

#if defined(PER_BLOCK_CHECKPOINT)
#include "blocks/blocks.h"
#endif
#include "safex/command.h"
#include "safex/safex_account.h"

#undef SAFEX_DEFAULT_LOG_CATEGORY
#define SAFEX_DEFAULT_LOG_CATEGORY "blockchain"

#define FIND_BLOCKCHAIN_SUPPLEMENT_MAX_SIZE (100*1024*1024) // 100 MB

using namespace crypto;

//#include "serialization/json_archive.h"

/* TODO:
 *  Clean up code:
 *    Possibly change how outputs are referred to/indexed in blockchain and wallets
 *
 */

using namespace cryptonote;
using epee::string_tools::pod_to_hex;
extern "C" void slow_hash_allocate_state();
extern "C" void slow_hash_free_state();

DISABLE_VS_WARNINGS(4267)

#define MERROR_VER(x) MCERROR("verify", x)

// used to overestimate the block reward when estimating a per kB to use
#define BLOCK_REWARD_OVERESTIMATE (10 * 1000000000000)

static const struct {
  uint8_t version;
  uint64_t height;
  uint8_t threshold;
  time_t time;
} mainnet_hard_forks[] = {
  // version 1 from the start of the blockchain
  { 1, 1, 0, 1514764801 },
  //version 2 starts from block 61660, around 2018-11-26. Fork time finalized on 2018-11-06
  { 2, 61660, 0, 1541503503 },
  //version 3 starts from block 92200, fork time finalized on 2019-01-04
  { 3, 92200, 0, 1546602383 },
  { 4, config::HARDFORK_V4_START_HEIGHT, 0, 1565962165},
  //version 5 starts from block 335252, fork time finalized on 2019-12-11
  { 5, 335252, 0, 1576069200},
  //version 6 starts from block TBD, fork time finalized on TBD
  { 6, 354100, 0, 1578327338},
  //version 7 starts from block 605700, fork time finalized on 2020-12-21
  { 7, 605700, 0, 1608570000}
};
static const uint64_t mainnet_hard_fork_version_1_till = 61659;

static const struct {
  uint8_t version;
  uint64_t height;
  uint8_t threshold;
  time_t time;
} testnet_hard_forks[] = {
  // version 1 from the start of the blockchain
  { 1, 1, 0, 1514764801 },
  { 2, 1250, 0, 1541066055},
  { 3, 1260, 0, 1605355986}, //184650
  { 4, config::testnet::HARDFORK_V4_START_HEIGHT, 0, 1605455986},
  //TODO: Update when preapring HF5 for testnet
  { 5, config::testnet::HARDFORK_V4_START_HEIGHT, 0, 1605555986},
  { 6, config::testnet::HARDFORK_V4_START_HEIGHT, 0, 1605655986},
  { 7, config::testnet::HARDFORK_V4_START_HEIGHT, 0, 1605755986}
};
static const uint64_t testnet_hard_fork_version_1_till = 33406;

static const struct {
  uint8_t version;
  uint64_t height;
  uint8_t threshold;
  time_t time;
} stagenet_hard_forks[] = {
  // version 1 from the start of the blockchain
  { 1, 1, 0, 1560283500 },
  { 2, 100, 0, 1561283500},
  { 3, 200, 0, 1562283500},
  { 4, config::stagenet::HARDFORK_V4_START_HEIGHT, 0, 1565962165},
  { 5, config::stagenet::HARDFORK_V4_START_HEIGHT + 1, 0, 1565962166},
  { 6, config::stagenet::HARDFORK_V4_START_HEIGHT + 2, 0, 1592478292},
  { 7, 91020, 0, 1605691874}
};

//------------------------------------------------------------------
Blockchain::Blockchain(tx_memory_pool& tx_pool) :
  m_db(), m_tx_pool(tx_pool), m_hardfork(NULL), m_timestamps_and_difficulties_height(0), m_current_block_cumul_sz_limit(0), m_current_block_cumul_sz_median(0),
  m_enforce_dns_checkpoints(false), m_max_prepare_blocks_threads(4), m_db_blocks_per_sync(1), m_db_sync_mode(db_async), m_db_default_sync(false),
  m_fast_sync(true), m_show_time_stats(false), m_sync_counter(0), m_cancel(false), m_prepare_height(0), m_batch_success(true)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
}
//------------------------------------------------------------------
bool Blockchain::have_tx(const crypto::hash &id) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return m_db->tx_exists(id);
}
//------------------------------------------------------------------
bool Blockchain::have_tx_keyimg_as_spent(const crypto::key_image &key_im) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return  m_db->has_key_image(key_im);
}
//------------------------------------------------------------------
// This function makes sure that each "input" in an input (mixins) exists
// and collects the public key for each from the transaction it was included in
// via the visitor passed to it.
template <class visitor_t, class TxInput>
bool Blockchain::scan_outputkeys_for_indexes(size_t tx_version, const TxInput& txin, visitor_t &vis,
                                             const crypto::hash &tx_prefix_hash, uint64_t* pmax_related_block_height) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  // ND: Disable locking and make method private.
  //CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // verify that the input has key offsets (that it exists properly, really)
  if(!txin.key_offsets.size())
    return false;

  // cryptonote_format_utils uses relative offsets for indexing to the global
  // outputs list.  that is to say that absolute offset #2 is absolute offset
  // #1 plus relative offset #2.
  // TODO: Investigate if this is necessary / why this is done.
  std::vector<uint64_t> absolute_offsets = relative_output_offsets_to_absolute(txin.key_offsets);
  std::vector<output_data_t> outputs;

  uint64_t value_amount = get_tx_input_value_amount(txin); //token or cash amount depending of input type

  bool found = false;
  auto it = m_scan_table.find(tx_prefix_hash);
  if (it != m_scan_table.end())
  {
    auto its = it->second.find(txin.k_image);
    if (its != it->second.end())
    {
      outputs = its->second;
      found = true;
    }
  }

  if (!found)
  {
    try
    {
      tx_out_type txout_type = cryptonote::derive_tx_out_type_from_input(txin);
      m_db->get_amount_output_key(value_amount, absolute_offsets, outputs, txout_type, true);
      if (absolute_offsets.size() != outputs.size())
      {
        MERROR_VER("Output does not exist! amount = " << value_amount);
        return false;
      }
    }
    catch (...)
    {
      MERROR_VER("Output does not exist! amount = " << value_amount);
      return false;
    }
  }
  else
  {
    // check for partial results and add the rest if needed;
    if (outputs.size() < absolute_offsets.size() && outputs.size() > 0)
    {
      MDEBUG("Additional outputs needed: " << absolute_offsets.size() - outputs.size());
      std::vector < uint64_t > add_offsets;
      std::vector<output_data_t> add_outputs;
      for (size_t i = outputs.size(); i < absolute_offsets.size(); i++)
        add_offsets.push_back(absolute_offsets[i]);
      try
      {
        tx_out_type txout_type = cryptonote::derive_tx_out_type_from_input(txin);
        m_db->get_amount_output_key(value_amount, add_offsets, add_outputs, txout_type, true);
        if (add_offsets.size() != add_outputs.size())
        {
          MERROR_VER("Output does not exist! amount = " << value_amount);
          return false;
        }
      }
      catch (...)
      {
        MERROR_VER("Output does not exist! amount = " << value_amount);
        return false;
      }
      outputs.insert(outputs.end(), add_outputs.begin(), add_outputs.end());
    }
  }

  size_t count = 0;
  for (const uint64_t& i : absolute_offsets)
  {
    try
    {
      output_data_t output_index;
      try
      {
        tx_out_type txout_type = cryptonote::derive_tx_out_type_from_input(txin);

        // get tx hash and output index for output
        if (count < outputs.size())
          output_index = outputs.at(count);
        else
          output_index = m_db->get_output_key(value_amount, i, txout_type);

        // call to the passed boost visitor to grab the public key for the output
        if (!vis.handle_output(output_index.unlock_time, output_index.pubkey, output_index.commitment))
        {
          MERROR_VER("Failed to handle_output for output no = " << count << ", with absolute offset " << i);
          return false;
        }
      }
      catch (...)
      {
        MERROR_VER("Output does not exist! amount = " << value_amount << ", absolute_offset = " << i);
        return false;
      }

      // if on last output and pmax_related_block_height not null pointer
      if(++count == absolute_offsets.size() && pmax_related_block_height)
      {
        // set *pmax_related_block_height to tx block height for this output
        auto h = output_index.height;
        if(*pmax_related_block_height < h)
        {
          *pmax_related_block_height = h;
        }
      }

    }
    catch (const OUTPUT_DNE& e)
    {
      MERROR_VER("Output does not exist: " << e.what());
      return false;
    }
    catch (const TX_DNE& e)
    {
      MERROR_VER("Transaction does not exist: " << e.what());
      return false;
    }

  }

  return true;
}
//------------------------------------------------------------------
//Template specialization for script inputs, where it depends which outputs we shold take
template<>
bool Blockchain::scan_outputkeys_for_indexes<Blockchain::outputs_generic_visitor, cryptonote::txin_to_script>
        (size_t tx_version, const txin_to_script &txin, Blockchain::outputs_generic_visitor &vis,
         const crypto::hash &tx_prefix_hash, uint64_t *pmax_related_block_height) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  // ND: Disable locking and make method private.
  //CRITICAL_REGION_LOCAL(m_blockchain_lock);

  tx_out_type output_type{tx_out_type::out_invalid}; //type which the input is referencing

  //check command type
  switch (txin.command_type)
  {
    case safex::command_t::token_stake:
      output_type = tx_out_type::out_token;
      break;
    case safex::command_t::token_unstake:
      output_type = tx_out_type::out_staked_token;
      break;
    case safex::command_t::donate_network_fee:
      output_type = tx_out_type::out_cash;
      break;
    case safex::command_t::create_account:
      output_type = tx_out_type::out_token;
      break;
    case safex::command_t::edit_account:
      output_type = tx_out_type::out_safex_account;
      break;
    case safex::command_t::create_offer:
      output_type = tx_out_type::out_safex_account;
      break;
    case safex::command_t::edit_offer:
      output_type = tx_out_type::out_safex_offer;
      break;
    case safex::command_t::simple_purchase:
      output_type = tx_out_type::out_cash;
      break;
    case safex::command_t::create_feedback:
      output_type = tx_out_type::out_safex_feedback_token;
      break;
    case safex::command_t::create_price_peg:
      output_type = tx_out_type::out_safex_account;
      break;
    case safex::command_t::update_price_peg:
      output_type = tx_out_type::out_safex_price_peg;
      break;
    default:
      MERROR_VER("Unknown command type");
      return false;
      break;
  }

  if (!txin.key_offsets.size())
    return false;

  if(!safex::is_safex_key_image_verification_needed(txin.command_type) && txin.key_offsets.size() != 1){
      MERROR_VER("Commands that don't have key image verification must have only 1 key offset");
      return false;
  }


  std::vector<uint64_t> absolute_offsets;
  uint64_t value_amount = 0;
  switch (output_type)
  {
    case tx_out_type::out_staked_token:
    case tx_out_type::out_safex_account:
    case tx_out_type::out_safex_feedback_token:
    case tx_out_type::out_safex_offer:
    case tx_out_type::out_safex_price_peg:
    {
      absolute_offsets = txin.key_offsets;
      break;
    }
    case tx_out_type::out_token:
    {
      absolute_offsets = relative_output_offsets_to_absolute(txin.key_offsets);
      value_amount = get_tx_input_token_amount(txin);
      break;
    }

    case tx_out_type::out_cash:
    case tx_out_type::out_network_fee:
    {
      absolute_offsets = relative_output_offsets_to_absolute(txin.key_offsets);
      value_amount = get_tx_input_cash_amount(txin);
      break;
    }
    default:
      MERROR_VER("Unknown output type");
      return false;
  }

  if (output_type == tx_out_type::out_token || output_type == tx_out_type::out_cash)
  {
    std::vector<output_data_t> outputs;
    bool found = false;
    auto it = m_scan_table.find(tx_prefix_hash);
    if (it != m_scan_table.end())
    {
      auto its = it->second.find(txin.k_image);
      if (its != it->second.end())
      {
        outputs = its->second;
        found = true;
      }
    }

    if (!found)
    {
      try
      {
        m_db->get_amount_output_key(value_amount, absolute_offsets, outputs, output_type, true);
        if (absolute_offsets.size() != outputs.size())
        {
          MERROR_VER("Output does not exist! amount = " << value_amount);
          return false;
        }
      }
      catch (...)
      {
        MERROR_VER("Output does not exist! amount = " << value_amount);
        return false;
      }
    }
    else
    {
      // check for partial results and add the rest if needed;
      if (outputs.size() < absolute_offsets.size() && outputs.size() > 0)
      {
        MDEBUG("Additional outputs needed: " << absolute_offsets.size() - outputs.size());
        std::vector<uint64_t> add_offsets;
        std::vector<output_data_t> add_outputs;
        for (size_t i = outputs.size(); i < absolute_offsets.size(); i++)
          add_offsets.push_back(absolute_offsets[i]);
        try
        {
          m_db->get_amount_output_key(value_amount, add_offsets, add_outputs, output_type, true);
          if (add_offsets.size() != add_outputs.size())
          {
            MERROR_VER("Output does not exist! amount = " << value_amount);
            return false;
          }
        }
        catch (...)
        {
          MERROR_VER("Output does not exist! amount = " << value_amount);
          return false;
        }
        outputs.insert(outputs.end(), add_outputs.begin(), add_outputs.end());
      }
    }

    size_t count = 0;
    for (const uint64_t &i : absolute_offsets)
    {
      try
      {
        output_data_t output_index;
        try
        {
          // get tx hash and output index for output
          if (count < outputs.size())
            output_index = outputs.at(count);
          else
            output_index = m_db->get_output_key(value_amount, i, output_type);

          // call to the passed boost visitor to grab the public key for the output
          if (!vis.handle_output(output_index.unlock_time, output_index.pubkey, output_index.commitment))
          {
            MERROR_VER("Failed to handle_output for output no = " << count << ", with absolute offset " << i);
            return false;
          }
        }
        catch (...)
        {
          MERROR_VER("Output does not exist! amount = " << value_amount << ", absolute_offset = " << i);
          return false;
        }

        // if on last output and pmax_related_block_height not null pointer
        if (++count == absolute_offsets.size() && pmax_related_block_height)
        {
          // set *pmax_related_block_height to tx block height for this output
          auto h = output_index.height;
          if (*pmax_related_block_height < h)
          {
            *pmax_related_block_height = h;
          }
        }
      }
      catch (const OUTPUT_DNE &e)
      {
        MERROR_VER("Output does not exist: " << e.what());
        return false;
      }
      catch (const TX_DNE &e)
      {
        MERROR_VER("Transaction does not exist: " << e.what());
        return false;
      }

    }
  }
/* Handle advanced outputs that should be spend in the transaction */
  else if ((output_type == tx_out_type::out_staked_token)
           || (output_type == tx_out_type::out_network_fee)
           || (output_type == tx_out_type::out_safex_account)
           || (output_type == tx_out_type::out_safex_feedback_token)
           || (output_type ==  tx_out_type::out_safex_offer)
           || (output_type == tx_out_type::out_safex_price_peg)) {

    std::vector<output_advanced_data_t> outputs;
    bool found = false;
    auto it = m_scan_table_adv.find(tx_prefix_hash);
    if (it != m_scan_table_adv.end())
    {
      auto its = it->second.find(txin.k_image);
      if (its != it->second.end())
      {
        outputs = its->second;
        found = true;
      }
    }

    if (!found)
    {
      try
      {
        m_db->get_advanced_output_key(absolute_offsets, outputs, output_type, true);
        if (absolute_offsets.size() != outputs.size())
        {
          MERROR_VER("Advanced outputs do not exist!");
          return false;
        }
      }
      catch (...)
      {
        MERROR_VER("Advanced outputs do not exist");
        return false;
      }
    }
    else
    {
      // check for partial results and add the rest if needed;
      if (outputs.size() < absolute_offsets.size() && outputs.size() > 0)
      {
        MDEBUG("Additional advanced outputs needed: " << absolute_offsets.size() - outputs.size());
        std::vector<uint64_t> add_offsets;
        std::vector<output_advanced_data_t> add_outputs;
        for (size_t i = outputs.size(); i < absolute_offsets.size(); i++)
          add_offsets.push_back(absolute_offsets[i]);
        try
        {
          m_db->get_advanced_output_key(add_offsets, add_outputs, output_type, true);
          if (add_offsets.size() != add_outputs.size())
          {
            MERROR_VER("Advanced outputs do not exist");
            return false;
          }
        }
        catch (...)
        {
          MERROR_VER("Advanced output does not exist!");
          return false;
        }
        outputs.insert(outputs.end(), add_outputs.begin(), add_outputs.end());
      }
    }

    size_t count = 0;
    for (const uint64_t &i : absolute_offsets)
    {
      try
      {
        output_advanced_data_t output_data;
        try
        {
          // get tx hash and output index for output
          if (count < outputs.size())
            output_data = outputs.at(count);
          else
            output_data = m_db->get_output_advanced_data(output_type, i);

          // call to the passed boost visitor to grab the public key for the output
          if (!vis.handle_output(output_data.unlock_time, output_data.pubkey, rct::key{0}))
          {
            MERROR_VER("Failed to handle_output for output no = " << count << ", with absolute offset " << i);
            return false;
          }
        }
        catch (...)
        {
          MERROR_VER("Output does not exist! amount = " << value_amount << ", absolute_offset = " << i);
          return false;
        }

        // if on last output and pmax_related_block_height not null pointer
        if (++count == absolute_offsets.size() && pmax_related_block_height)
        {
          // set *pmax_related_block_height to tx block height for this output
          auto h = output_data.height;
          if (*pmax_related_block_height < h)
          {
            *pmax_related_block_height = h;
          }
        }

      }
      catch (const OUTPUT_DNE &e)
      {
        MERROR_VER("Output does not exist: " << e.what());
        return false;
      }
      catch (const TX_DNE &e)
      {
        MERROR_VER("Transaction does not exist: " << e.what());
        return false;
      }

    }

  }
  else {
    MERROR_VER("Unknown output type.");
    return false;
  }

  return true;
}
//------------------------------------------------------------------
uint64_t Blockchain::get_current_blockchain_height() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return m_db->height();
}
//------------------------------------------------------------------
//FIXME: possibly move this into the constructor, to avoid accidentally
//       dereferencing a null BlockchainDB pointer
bool Blockchain::init(BlockchainDB* db, const network_type nettype, bool offline, const cryptonote::test_options *test_options)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_tx_pool);
  CRITICAL_REGION_LOCAL1(m_blockchain_lock);

  if (db == nullptr)
  {
    LOG_ERROR("Attempted to init Blockchain with null DB");
    return false;
  }
  if (!db->is_open())
  {
    LOG_ERROR("Attempted to init Blockchain with unopened DB");
    delete db;
    return false;
  }

  m_db = db;

  m_nettype = test_options != NULL ? FAKECHAIN : nettype;
  m_offline = offline;
  if (m_hardfork == nullptr)
  {
    if (m_nettype ==  FAKECHAIN || m_nettype == STAGENET)
      m_hardfork = new HardFork(*db, 1, 0);
    else if (m_nettype == TESTNET)
      m_hardfork = new HardFork(*db, 1, testnet_hard_fork_version_1_till);
    else
      m_hardfork = new HardFork(*db, 1, mainnet_hard_fork_version_1_till);
  }
  if (m_nettype == FAKECHAIN)
  {
    for (size_t n = 0; test_options->hard_forks[n].first; ++n)
      m_hardfork->add_fork(test_options->hard_forks[n].first, test_options->hard_forks[n].second, 0, n + 1);
  }
  else if (m_nettype == TESTNET)
  {
    for (size_t n = 0; n < sizeof(testnet_hard_forks) / sizeof(testnet_hard_forks[0]); ++n)
      m_hardfork->add_fork(testnet_hard_forks[n].version, testnet_hard_forks[n].height, testnet_hard_forks[n].threshold, testnet_hard_forks[n].time);
  }
  else if (m_nettype == STAGENET)
  {
    for (size_t n = 0; n < sizeof(stagenet_hard_forks) / sizeof(stagenet_hard_forks[0]); ++n)
      m_hardfork->add_fork(stagenet_hard_forks[n].version, stagenet_hard_forks[n].height, stagenet_hard_forks[n].threshold, stagenet_hard_forks[n].time);
  }
  else
  {
    for (size_t n = 0; n < sizeof(mainnet_hard_forks) / sizeof(mainnet_hard_forks[0]); ++n)
      m_hardfork->add_fork(mainnet_hard_forks[n].version, mainnet_hard_forks[n].height, mainnet_hard_forks[n].threshold, mainnet_hard_forks[n].time);
  }
  m_hardfork->init();

  m_db->set_hard_fork(m_hardfork);

  // if the blockchain is new, add the genesis block
  // this feels kinda kludgy to do it this way, but can be looked at later.
  // TODO: add function to create and store genesis block,
  //       taking testnet into account
  if(!m_db->height())
  {
    MINFO("Blockchain not loaded, generating genesis block.");
    block bl = boost::value_initialized<block>();
    block_verification_context bvc = boost::value_initialized<block_verification_context>();
    if (m_nettype == TESTNET)
    {
      generate_genesis_block(bl, config::testnet::GENESIS_TX, config::testnet::GENESIS_NONCE);
    }
    else if (m_nettype == STAGENET)
    {
      generate_genesis_block(bl, config::stagenet::GENESIS_TX, config::stagenet::GENESIS_NONCE);
    }
    else
    {
      generate_genesis_block(bl, config::GENESIS_TX, config::GENESIS_NONCE);
    }
    add_new_block(bl, bvc);
    CHECK_AND_ASSERT_MES(!bvc.m_verifivation_failed, false, "Failed to add genesis block to blockchain");
  }
  // TODO: if blockchain load successful, verify blockchain against both
  //       hard-coded and runtime-loaded (and enforced) checkpoints.
  else
  {
  }

  if (m_nettype != FAKECHAIN)
  {
    // ensure we fixup anything we found and fix in the future
    m_db->fixup();
  }

  m_db->block_txn_start(true);
  // check how far behind we are
  uint64_t top_block_timestamp = m_db->get_top_block_timestamp();
  uint64_t timestamp_diff = time(NULL) - top_block_timestamp;

  // genesis block has no timestamp, could probably change it to have timestamp of 1341378000...
  if(!top_block_timestamp)
    timestamp_diff = time(NULL) - 1341378000;

  // create general purpose async service queue

  m_async_work_idle = std::unique_ptr < boost::asio::io_service::work > (new boost::asio::io_service::work(m_async_service));
  // we only need 1
  m_async_pool.create_thread(boost::bind(&boost::asio::io_service::run, &m_async_service));

#if defined(PER_BLOCK_CHECKPOINT)
  if (m_nettype != FAKECHAIN)
    load_compiled_in_block_hashes();
#endif

  MINFO("Blockchain initialized. last block: " << m_db->height() - 1 << ", " << epee::misc_utils::get_time_interval_string(timestamp_diff) << " time ago, current difficulty: " << get_difficulty_for_next_block());
  m_db->block_txn_stop();

  uint64_t num_popped_blocks = 0;
  while (!m_db->is_read_only())
  {
    const uint64_t top_height = m_db->height() - 1;
    const crypto::hash top_id = m_db->top_block_hash();
    const block top_block = m_db->get_top_block();
    const uint8_t ideal_hf_version = get_ideal_hard_fork_version(top_height);
    if (ideal_hf_version <= 1 || ideal_hf_version == top_block.major_version)
    {
      if (num_popped_blocks > 0)
        MGINFO("Initial popping done, top block: " << top_id << ", top height: " << top_height << ", block version: " << (uint64_t)top_block.major_version);
      break;
    }
    else
    {
      if (num_popped_blocks == 0)
        MGINFO("Current top block " << top_id << " at height " << top_height << " has version " << (uint64_t)top_block.major_version << " which disagrees with the ideal version " << (uint64_t)ideal_hf_version);
      if (num_popped_blocks % 100 == 0)
        MGINFO("Popping blocks... " << top_height);
      ++num_popped_blocks;
      block popped_block;
      std::vector<transaction> popped_txs;
      try
      {
        m_db->pop_block(popped_block, popped_txs);
      }
      // anything that could cause this to throw is likely catastrophic,
      // so we re-throw
      catch (const std::exception& e)
      {
        MERROR("Error popping block from blockchain: " << e.what());
        throw;
      }
      catch (...)
      {
        MERROR("Error popping block from blockchain, throwing!");
        throw;
      }
    }
  }
  if (num_popped_blocks > 0)
  {
    m_timestamps_and_difficulties_height = 0;
    m_hardfork->reorganize_from_chain_height(get_current_blockchain_height());
    m_tx_pool.on_blockchain_dec(m_db->height()-1, get_tail_id());
  }

  update_next_cumulative_size_limit();
  return true;
}
//------------------------------------------------------------------
bool Blockchain::init(BlockchainDB* db, HardFork*& hf, const network_type nettype, bool offline)
{
  if (hf != nullptr)
    m_hardfork = hf;
  bool res = init(db, nettype, offline, NULL);
  if (hf == nullptr)
    hf = m_hardfork;
  return res;
}
//------------------------------------------------------------------
bool Blockchain::store_blockchain()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // lock because the rpc_thread command handler also calls this
  CRITICAL_REGION_LOCAL(m_db->m_synchronization_lock);

  TIME_MEASURE_START(save);
  // TODO: make sure sync(if this throws that it is not simply ignored higher
  // up the call stack
  try
  {
    m_db->sync();
  }
  catch (const std::exception& e)
  {
    MERROR(std::string("Error syncing blockchain db: ") + e.what() + "-- shutting down now to prevent issues!");
    throw;
  }
  catch (...)
  {
    MERROR("There was an issue storing the blockchain, shutting down now to prevent issues!");
    throw;
  }

  TIME_MEASURE_FINISH(save);
  if(m_show_time_stats)
    MINFO("Blockchain stored OK, took: " << save << " ms");
  return true;
}
//------------------------------------------------------------------
bool Blockchain::deinit()
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  MTRACE("Stopping blockchain read/write activity");

 // stop async service
  m_async_work_idle.reset();
  m_async_pool.join_all();
  m_async_service.stop();

  // as this should be called if handling a SIGSEGV, need to check
  // if m_db is a NULL pointer (and thus may have caused the illegal
  // memory operation), otherwise we may cause a loop.
  if (m_db == NULL)
  {
    throw DB_ERROR("The db pointer is null in Blockchain, the blockchain may be corrupt!");
  }

  try
  {
    m_db->close();
    MTRACE("Local blockchain read/write activity stopped successfully");
  }
  catch (const std::exception& e)
  {
    LOG_ERROR(std::string("Error closing blockchain db: ") + e.what());
  }
  catch (...)
  {
    LOG_ERROR("There was an issue closing/storing the blockchain, shutting down now to prevent issues!");
  }

  delete m_hardfork;
  m_hardfork = NULL;
  delete m_db;
  m_db = NULL;
  return true;
}
//------------------------------------------------------------------
// This function tells BlockchainDB to remove the top block from the
// blockchain and then returns all transactions (except the miner tx, of course)
// from it to the tx_pool
block Blockchain::pop_block_from_blockchain()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  m_timestamps_and_difficulties_height = 0;

  block popped_block;
  std::vector<transaction> popped_txs;

  try
  {
    m_db->pop_block(popped_block, popped_txs);
  }
  // anything that could cause this to throw is likely catastrophic,
  // so we re-throw
  catch (const std::exception& e)
  {
    LOG_ERROR("Error popping block from blockchain: " << e.what());
    throw;
  }
  catch (...)
  {
    LOG_ERROR("Error popping block from blockchain, throwing!");
    throw;
  }

  // return transactions from popped block to the tx_pool
  for (transaction& tx : popped_txs)
  {
    if (!is_coinbase(tx))
    {
      cryptonote::tx_verification_context tvc = AUTO_VAL_INIT(tvc);

      // FIXME: HardFork
      // Besides the below, popping a block should also remove the last entry
      // in hf_versions.
      //
      // FIXME: HardFork
      // This is not quite correct, as we really want to add the txes
      // to the pool based on the hf_version determined after all blocks
      // are popped.
      uint8_t hf_version = get_current_hard_fork_version();

      // We assume that if they were in a block, the transactions are already
      // known to the network as a whole. However, if we had mined that block,
      // that might not be always true. Unlikely though, and always relaying
      // these again might cause a spike of traffic as many nodes re-relay
      // all the transactions in a popped block when a reorg happens.
      bool r = m_tx_pool.add_tx(tx, tvc, true, true, false, hf_version);
      if (!r)
      {
        LOG_ERROR("Error returning transaction to tx_pool");
      }
    }
  }

  m_blocks_longhash_table.clear();
  m_scan_table.clear();
  m_scan_table_adv.clear();
  m_blocks_txs_check.clear();
  m_check_txin_table.clear();

  update_next_cumulative_size_limit();
  m_tx_pool.on_blockchain_dec(m_db->height()-1, get_tail_id());

  return popped_block;
}
//------------------------------------------------------------------
bool Blockchain::reset_and_set_genesis_block(const block& b)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  m_timestamps_and_difficulties_height = 0;
  m_alternative_chains.clear();
  m_db->reset();
  m_hardfork->init();

  block_verification_context bvc = boost::value_initialized<block_verification_context>();
  add_new_block(b, bvc);
  update_next_cumulative_size_limit();
  return bvc.m_added_to_main_chain && !bvc.m_verifivation_failed;
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_tail_id(uint64_t& height) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  height = m_db->height() - 1;
  return get_tail_id();
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_tail_id() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return m_db->top_block_hash();
}
//------------------------------------------------------------------
/*TODO: this function was...poorly written.  As such, I'm not entirely
 *      certain on what it was supposed to be doing.  Need to look into this,
 *      but it doesn't seem terribly important just yet.
 *
 * puts into list <ids> a list of hashes representing certain blocks
 * from the blockchain in reverse chronological order
 *
 * the blocks chosen, at the time of this writing, are:
 *   the most recent 11
 *   powers of 2 less recent from there, so 13, 17, 25, etc...
 *
 */
bool Blockchain::get_short_chain_history(std::list<crypto::hash>& ids) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  uint64_t i = 0;
  uint64_t current_multiplier = 1;
  uint64_t sz = m_db->height();

  if(!sz)
    return true;

  m_db->block_txn_start(true);
  bool genesis_included = false;
  uint64_t current_back_offset = 1;
  while(current_back_offset < sz)
  {
    ids.push_back(m_db->get_block_hash_from_height(sz - current_back_offset));

    if(sz-current_back_offset == 0)
    {
      genesis_included = true;
    }
    if(i < 10)
    {
      ++current_back_offset;
    }
    else
    {
      current_multiplier *= 2;
      current_back_offset += current_multiplier;
    }
    ++i;
  }

  if (!genesis_included)
  {
    ids.push_back(m_db->get_block_hash_from_height(0));
  }
  m_db->block_txn_stop();

  return true;
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_block_id_by_height(uint64_t height) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  try
  {
    return m_db->get_block_hash_from_height(height);
  }
  catch (const BLOCK_DNE& e)
  {
  }
  catch (const std::exception& e)
  {
    MERROR(std::string("Something went wrong fetching block hash by height: ") + e.what());
    throw;
  }
  catch (...)
  {
    MERROR(std::string("Something went wrong fetching block hash by height"));
    throw;
  }
  return null_hash;
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_pending_block_id_by_height(uint64_t height) const
{
  if (m_prepare_height && height >= m_prepare_height && height - m_prepare_height < m_prepare_nblocks)
  {
    std::size_t block_index = height - m_prepare_height;
    for (auto &blocks_batches : *m_prepare_blocks)
    {
      if (block_index < blocks_batches.size())
       return blocks_batches[block_index].hash;
      block_index -= blocks_batches.size();
    }
  }
  return get_block_id_by_height(height);
}
//------------------------------------------------------------------
bool Blockchain::get_block_by_hash(const crypto::hash &h, block &blk, bool *orphan) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // try to find block in main chain
  try
  {
    blk = m_db->get_block(h);
    if (orphan)
      *orphan = false;
    return true;
  }
  // try to find block in alternative chain
  catch (const BLOCK_DNE& e)
  {
    blocks_ext_by_hash::const_iterator it_alt = m_alternative_chains.find(h);
    if (m_alternative_chains.end() != it_alt)
    {
      blk = it_alt->second.bl;
      if (orphan)
        *orphan = true;
      return true;
    }
  }
  catch (const std::exception& e)
  {
    MERROR(std::string("Something went wrong fetching block by hash: ") + e.what());
    throw;
  }
  catch (...)
  {
    MERROR(std::string("Something went wrong fetching block hash by hash"));
    throw;
  }

  return false;
}
//------------------------------------------------------------------
// This function aggregates the cumulative difficulties and timestamps of the
// last DIFFICULTY_BLOCKS_COUNT blocks and passes them to next_difficulty,
// returning the result of that call.  Ignores the genesis block, and can use
// less blocks than desired if there aren't enough.
difficulty_type Blockchain::get_difficulty_for_next_block()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  std::vector<uint64_t> timestamps;
  std::vector<difficulty_type> difficulties;
  auto height = m_db->height();
  size_t difficulty_blocks_count;

  if (m_hardfork->get_current_version() < HF_VERSION_DIFFICULTY_V2)
  {
    difficulty_blocks_count = DIFFICULTY_BLOCKS_COUNT;
  }
  else
  {
    difficulty_blocks_count = DIFFICULTY_BLOCKS_COUNT_V2;
  }


  // ND: Speedup
  // 1. Keep a list of the last 735 (or less) blocks that is used to compute difficulty,
  //    then when the next block difficulty is queried, push the latest height data and
  //    pop the oldest one from the list. This only requires 1x read per height instead
  //    of doing 735 (DIFFICULTY_BLOCKS_COUNT).
  if (m_timestamps_and_difficulties_height != 0 && ((height - m_timestamps_and_difficulties_height) == 1) && m_timestamps.size() >= DIFFICULTY_BLOCKS_COUNT)
  {
    uint64_t index = height - 1;
    m_timestamps.push_back(m_db->get_block_timestamp(index));
    m_difficulties.push_back(m_db->get_block_cumulative_difficulty(index));

    while (m_timestamps.size() > difficulty_blocks_count)
      m_timestamps.erase(m_timestamps.begin());
    while (m_difficulties.size() > difficulty_blocks_count)
      m_difficulties.erase(m_difficulties.begin());

    m_timestamps_and_difficulties_height = height;
    timestamps = m_timestamps;
    difficulties = m_difficulties;
  }
  else
  {
    size_t offset = height - std::min < size_t > (height, static_cast<size_t>(difficulty_blocks_count));
    if (offset == 0)
      ++offset;

    timestamps.clear();
    difficulties.clear();
    for (; offset < height; offset++)
    {
      timestamps.push_back(m_db->get_block_timestamp(offset));
      difficulties.push_back(m_db->get_block_cumulative_difficulty(offset));
    }

    m_timestamps_and_difficulties_height = height;
    m_timestamps = timestamps;
    m_difficulties = difficulties;
  }
  size_t target = get_difficulty_target();

  return get_hard_fork_difficulty(timestamps, difficulties, target);

}

difficulty_type Blockchain::get_hard_fork_difficulty( std::vector<std::uint64_t>& timestamps,
                        std::vector<difficulty_type>& difficulties, size_t& target){

    uint8_t curr_hardfork_version = m_hardfork->get_current_version();
    auto height = m_db->height();

    if (curr_hardfork_version < HF_VERSION_DIFFICULTY_V2)
    {
        return next_difficulty(timestamps, difficulties, target);
    }
    else
    {
        uint64_t start_height = 0;
        uint64_t random_x_diff = 0;
        switch (m_nettype)
        {
            case STAGENET:
                start_height = stagenet_hard_forks[3].height;
                random_x_diff = config::stagenet::HARDFORK_V4_INIT_DIFF;
                break;
            case TESTNET:
                start_height = testnet_hard_forks[3].height;
                random_x_diff = config::testnet::HARDFORK_V4_INIT_DIFF;
                break;
            case MAINNET:
                start_height = mainnet_hard_forks[3].height;
                random_x_diff = config::HARDFORK_V4_INIT_DIFF;
                break;
            default:
                break;
        }

        if(height >= start_height && height <= start_height + DIFFICULTY_BLOCKS_COUNT_V2 )
            return random_x_diff;
        else
            return next_difficulty_v2(timestamps, difficulties, target);
    }
}

//------------------------------------------------------------------
// This function removes blocks from the blockchain until it gets to the
// position where the blockchain switch started and then re-adds the blocks
// that had been removed.
bool Blockchain::rollback_blockchain_switching(std::list<block>& original_chain, uint64_t rollback_height)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // fail if rollback_height passed is too high
  if (rollback_height > m_db->height())
  {
    return true;
  }

  m_timestamps_and_difficulties_height = 0;

  // remove blocks from blockchain until we get back to where we should be.
  while (m_db->height() != rollback_height)
  {
    pop_block_from_blockchain();
  }

  // make sure the hard fork object updates its current version
  m_hardfork->reorganize_from_chain_height(rollback_height);

  //return back original chain
  for (auto& bl : original_chain)
  {
    block_verification_context bvc = boost::value_initialized<block_verification_context>();
    bool r = handle_block_to_main_chain(bl, bvc);
    CHECK_AND_ASSERT_MES(r && bvc.m_added_to_main_chain, false, "PANIC! failed to add (again) block while chain switching during the rollback!");
  }

  m_hardfork->reorganize_from_chain_height(rollback_height);

  MINFO("Rollback to height " << rollback_height << " was successful.");
  if (original_chain.size())
  {
    MINFO("Restoration to previous blockchain successful as well.");
  }
  return true;
}
//------------------------------------------------------------------
// This function attempts to switch to an alternate chain, returning
// boolean based on success therein.
bool Blockchain::switch_to_alternative_blockchain(std::list<blocks_ext_by_hash::iterator>& alt_chain, bool discard_disconnected_chain)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  m_timestamps_and_difficulties_height = 0;

  // if empty alt chain passed (not sure how that could happen), return false
  CHECK_AND_ASSERT_MES(alt_chain.size(), false, "switch_to_alternative_blockchain: empty chain passed");

  // verify that main chain has front of alt chain's parent block
  if (!m_db->block_exists(alt_chain.front()->second.bl.prev_id))
  {
    LOG_ERROR("Attempting to move to an alternate chain, but it doesn't appear to connect to the main chain!");
    return false;
  }

  // pop blocks from the blockchain until the top block is the parent
  // of the front block of the alt chain.
  std::list<block> disconnected_chain;
  while (m_db->top_block_hash() != alt_chain.front()->second.bl.prev_id)
  {
    block b = pop_block_from_blockchain();
    disconnected_chain.push_front(b);
  }

  auto split_height = m_db->height();

  //connecting new alternative chain
  for(auto alt_ch_iter = alt_chain.begin(); alt_ch_iter != alt_chain.end(); alt_ch_iter++)
  {
    auto ch_ent = *alt_ch_iter;
    block_verification_context bvc = boost::value_initialized<block_verification_context>();

    // add block to main chain
    bool r = handle_block_to_main_chain(ch_ent->second.bl, bvc);

    // if adding block to main chain failed, rollback to previous state and
    // return false
    if(!r || !bvc.m_added_to_main_chain)
    {
      MERROR("Failed to switch to alternative blockchain");

      // rollback_blockchain_switching should be moved to two different
      // functions: rollback and apply_chain, but for now we pretend it is
      // just the latter (because the rollback was done above).
      rollback_blockchain_switching(disconnected_chain, split_height);

      // FIXME: Why do we keep invalid blocks around?  Possibly in case we hear
      // about them again so we can immediately dismiss them, but needs some
      // looking into.
      add_block_as_invalid(ch_ent->second, get_block_hash(ch_ent->second.bl));
      MERROR("The block was inserted as invalid while connecting new alternative chain, block_id: " << get_block_hash(ch_ent->second.bl));
      m_alternative_chains.erase(*alt_ch_iter++);

      for(auto alt_ch_to_orph_iter = alt_ch_iter; alt_ch_to_orph_iter != alt_chain.end(); )
      {
        add_block_as_invalid((*alt_ch_to_orph_iter)->second, (*alt_ch_to_orph_iter)->first);
        m_alternative_chains.erase(*alt_ch_to_orph_iter++);
      }
      return false;
    }
  }

  // if we're to keep the disconnected blocks, add them as alternates
  if(!discard_disconnected_chain)
  {
    //pushing old chain as alternative chain
    for (auto& old_ch_ent : disconnected_chain)
    {
      block_verification_context bvc = boost::value_initialized<block_verification_context>();
      bool r = handle_alternative_block(old_ch_ent, get_block_hash(old_ch_ent), bvc);
      if(!r)
      {
        MERROR("Failed to push ex-main chain blocks to alternative chain ");
        // previously this would fail the blockchain switching, but I don't
        // think this is bad enough to warrant that.
      }
    }
  }

  //removing alt_chain entries from alternative chains container
  for (auto ch_ent: alt_chain)
  {
    m_alternative_chains.erase(ch_ent);
  }

  m_hardfork->reorganize_from_chain_height(split_height);
  get_block_longhash_reorg(split_height);

  MGINFO_GREEN("REORGANIZE SUCCESS! on height: " << split_height << ", new blockchain size: " << m_db->height());
  return true;
}
//------------------------------------------------------------------
// This function calculates the difficulty target for the block being added to
// an alternate chain.
difficulty_type Blockchain::get_next_difficulty_for_alternative_chain(const std::list<blocks_ext_by_hash::iterator>& alt_chain, block_extended_info& bei)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::vector<uint64_t> timestamps;
  std::vector<difficulty_type> cumulative_difficulties;

  size_t difficulty_blocks_count;

  if (m_hardfork->get_current_version() < HF_VERSION_DIFFICULTY_V2)
  {
    difficulty_blocks_count = DIFFICULTY_BLOCKS_COUNT;
  }
  else
  {
    difficulty_blocks_count = DIFFICULTY_BLOCKS_COUNT_V2;
  }


  // if the alt chain isn't long enough to calculate the difficulty target
  // based on its blocks alone, need to get more blocks from the main chain
  if(alt_chain.size()< difficulty_blocks_count)
  {
    CRITICAL_REGION_LOCAL(m_blockchain_lock);

    // Figure out start and stop offsets for main chain blocks
    size_t main_chain_stop_offset = alt_chain.size() ? alt_chain.front()->second.height : bei.height;
    size_t main_chain_count = difficulty_blocks_count - std::min(static_cast<size_t>(difficulty_blocks_count), alt_chain.size());
    main_chain_count = std::min(main_chain_count, main_chain_stop_offset);
    size_t main_chain_start_offset = main_chain_stop_offset - main_chain_count;

    if(!main_chain_start_offset)
      ++main_chain_start_offset; //skip genesis block

    // get difficulties and timestamps from relevant main chain blocks
    for(; main_chain_start_offset < main_chain_stop_offset; ++main_chain_start_offset)
    {
      timestamps.push_back(m_db->get_block_timestamp(main_chain_start_offset));
      cumulative_difficulties.push_back(m_db->get_block_cumulative_difficulty(main_chain_start_offset));
    }

    // make sure we haven't accidentally grabbed too many blocks...maybe don't need this check?
    CHECK_AND_ASSERT_MES((alt_chain.size() + timestamps.size()) <= difficulty_blocks_count, false, "Internal error, alt_chain.size()[" << alt_chain.size() << "] + vtimestampsec.size()[" << timestamps.size() << "] NOT <= DIFFICULTY_WINDOW[]" << difficulty_blocks_count);

    for (auto it : alt_chain)
    {
      timestamps.push_back(it->second.bl.timestamp);
      cumulative_difficulties.push_back(it->second.cumulative_difficulty);
    }
  }
  // if the alt chain is long enough for the difficulty calc, grab difficulties
  // and timestamps from it alone
  else
  {
    timestamps.resize(static_cast<size_t>(difficulty_blocks_count));
    cumulative_difficulties.resize(static_cast<size_t>(difficulty_blocks_count));
    size_t count = 0;
    size_t max_i = timestamps.size()-1;
    // get difficulties and timestamps from most recent blocks in alt chain
    for(auto it: boost::adaptors::reverse(alt_chain))
    {
      timestamps[max_i - count] = it->second.bl.timestamp;
      cumulative_difficulties[max_i - count] = it->second.cumulative_difficulty;
      count++;
      if(count >= difficulty_blocks_count)
        break;
    }
  }

  size_t target = get_difficulty_target();

  return get_hard_fork_difficulty(timestamps, cumulative_difficulties, target);
}
//------------------------------------------------------------------
// This function does a sanity check on basic things that all miner
// transactions have in common, such as:
//   one input, of type txin_gen, with height set to the block's height
//   correct miner tx unlock time
//   a non-overflowing tx amount (dubious necessity on this check)
bool Blockchain::prevalidate_miner_transaction(const block& b, uint64_t height)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CHECK_AND_ASSERT_MES(b.miner_tx.vin.size() == 1, false, "coinbase transaction in the block has no inputs");
  CHECK_AND_ASSERT_MES(b.miner_tx.vin[0].type() == typeid(txin_gen), false, "coinbase transaction in the block has the wrong type");
  if(boost::get<txin_gen>(b.miner_tx.vin[0]).height != height)
  {
    MWARNING("The miner transaction in block has invalid height: " << boost::get<txin_gen>(b.miner_tx.vin[0]).height << ", expected: " << height);
    return false;
  }
  MDEBUG("Miner tx hash: " << get_transaction_hash(b.miner_tx));
  CHECK_AND_ASSERT_MES(b.miner_tx.unlock_time == height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, false, "coinbase transaction transaction has the wrong unlock time=" << b.miner_tx.unlock_time << ", expected " << height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW);

  //check outs overflow
  //NOTE: not entirely sure this is necessary, given that this function is
  //      designed simply to make sure the total amount for a transaction
  //      does not overflow a uint64_t, and this transaction *is* a uint64_t...
  if(!check_outs_overflow(b.miner_tx))
  {
    MERROR("miner transaction has money overflow in block " << get_block_hash(b));
    return false;
  }

  return true;
}
//------------------------------------------------------------------
// This function validates the miner transaction reward
bool Blockchain::validate_miner_transaction(const block& b, size_t cumulative_block_size, uint64_t fee, uint64_t& base_reward, uint64_t already_generated_coins, bool &partial_block_reward, uint8_t hf_version)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  //validate reward
  uint64_t money_in_use = 0;

  if(!are_miner_tx_outputs_valid(b.miner_tx)){
      MERROR_VER("miner tx output has output that is not txout_to_key");
      return false;
  }

  for (auto& o: b.miner_tx.vout)
    money_in_use += o.amount;
  partial_block_reward = false;


  if (hf_version == HF_VERSION_VALID_DECOMPOSED_MINER_TX_1 || hf_version == HF_VERSION_VALID_DECOMPOSED_MINER_TX_2) {
    for (auto &o: b.miner_tx.vout) {
      if (!is_valid_decomposed_amount(o.amount)) {
        MERROR_VER("miner tx output " << print_money(o.amount) << " is not a valid decomposed amount");
        return false;
      }
    }
  }

  std::vector<size_t> last_blocks_sizes;
  get_last_n_blocks_sizes(last_blocks_sizes, CRYPTONOTE_REWARD_BLOCKS_WINDOW);
  if (!get_block_reward(epee::misc_utils::median(last_blocks_sizes), cumulative_block_size, already_generated_coins, base_reward, hf_version, m_db->height()))
  {
    MERROR_VER("block size " << cumulative_block_size << " is bigger than allowed for this blockchain");
    return false;
  }
  if(base_reward + fee < money_in_use)
  {
    MERROR_VER("coinbase transaction spend too much money (" << print_money(money_in_use) << "). Block reward is " << print_money(base_reward + fee) << "(" << print_money(base_reward) << "+" << print_money(fee) << ")");
    return false;
  }
  // From hard fork 2, we allow a miner to claim less block reward than is allowed, in case a miner wants less dust
  if (m_hardfork->get_current_version() < HF_VERSION_ALLOW_LESS_BLOCK_REWARD)
  {
    if(base_reward + fee != money_in_use)
    {
      MDEBUG("coinbase transaction doesn't use full amount of block reward:  spent: " << money_in_use << ",  block reward " << base_reward + fee << "(" << base_reward << "+" << fee << ")");
      return false;
    }
  }
  else
  {
    // from hard fork 2 defined as HF_VERSION_ALLOW_LESS_BLOCK_REWARD, since a miner can claim less than the full block reward, we update the base_reward
    // to show the amount of coins that were actually generated, the remainder will be pushed back for later
    // emission. This modifies the emission curve very slightly.
    CHECK_AND_ASSERT_MES(money_in_use - fee <= base_reward, false, "base reward calculation bug");
    if(base_reward + fee != money_in_use)
      partial_block_reward = true;
    base_reward = money_in_use - fee;
  }
  return true;
}
//------------------------------------------------------------------
bool Blockchain::are_miner_tx_outputs_valid(const transaction& miner_tx) const
{

    std::vector<std::string> problematic_txs = {"0d3772e79491a02b6c08d0536d17f5f224170e8d78c2ea338265eaccab266c64",
                                                "f9c018cc6cdc7898b3e9ac09f9d2ff9afd594c96bc7bbce6f532707c7da7edb1",
                                                "4ee9bcc7ae4dd0ee77340554173e37d7de51b14b3a3259c17279e3e1e532ad5b",
                                                "434976fdd6a91f04b84383bc021c243e88fb6c89ed9ceee105604abcf8ac8020",
                                                "9233ebddc017f049ce3918d4ba9a8dca3a5db0112a98583fed56136e24344bdb"};

    for(auto& it: problematic_txs){
        crypto::hash problematic_tx;
        if (!epee::string_tools::hex_to_pod(it, problematic_tx))
            return false;
        if( problematic_tx == miner_tx.hash)
            return true;
    }

    for (auto& o: miner_tx.vout){
        if(o.target.type() != typeid(txout_to_key) ){
            return false;
        }
    }
    return true;
}
//------------------------------------------------------------------
// get the block sizes of the last <count> blocks, and return by reference <sz>.
void Blockchain::get_last_n_blocks_sizes(std::vector<size_t>& sz, size_t count) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  auto h = m_db->height();

  // this function is meaningless for an empty blockchain...granted it should never be empty
  if(h == 0)
    return;

  m_db->block_txn_start(true);
  // add size of last <count> blocks to vector <sz> (or less, if blockchain size < count)
  size_t start_offset = h - std::min<size_t>(h, count);
  for(size_t i = start_offset; i < h; i++)
  {
    sz.push_back(m_db->get_block_size(i));
  }
  m_db->block_txn_stop();
}
//------------------------------------------------------------------
uint64_t Blockchain::get_current_cumulative_blocksize_limit() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  return m_current_block_cumul_sz_limit;
}
//------------------------------------------------------------------
uint64_t Blockchain::get_current_cumulative_blocksize_median() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  return m_current_block_cumul_sz_median;
}
//------------------------------------------------------------------
//TODO: This function only needed minor modification to work with BlockchainDB,
//      and *works*.  As such, to reduce the number of things that might break
//      in moving to BlockchainDB, this function will remain otherwise
//      unchanged for the time being.
//
// This function makes a new block for a miner to mine the hash for
//
// FIXME: this codebase references #if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
// in a lot of places.  That flag is not referenced in any of the code
// nor any of the makefiles, howeve.  Need to look into whether or not it's
// necessary at all.
bool Blockchain::create_block_template(block& b, const account_public_address& miner_address, difficulty_type& diffic, uint64_t& height, uint64_t& expected_reward, const blobdata& ex_nonce)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  size_t median_size;
  uint64_t already_generated_coins;

  CRITICAL_REGION_BEGIN(m_blockchain_lock);
  height = m_db->height();

  b.major_version = m_hardfork->get_current_version();
  b.minor_version = m_hardfork->get_ideal_version();
  b.prev_id = get_tail_id();
  b.timestamp = time(NULL);

  uint64_t median_ts;
  if (!check_block_timestamp(b, median_ts))
  {
    b.timestamp = median_ts;
  }

  diffic = get_difficulty_for_next_block();
  CHECK_AND_ASSERT_MES(diffic, false, "difficulty overhead.");

  median_size = m_current_block_cumul_sz_limit / 2;
  already_generated_coins = m_db->get_block_already_generated_coins(height - 1);

  CRITICAL_REGION_END();

  size_t txs_size;
  uint64_t fee;
  if (!m_tx_pool.fill_block_template(b, median_size, already_generated_coins, txs_size, fee, expected_reward, m_hardfork->get_current_version(), height))
  {
    return false;
  }
#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
  size_t real_txs_size = 0;
  uint64_t real_fee = 0;
  CRITICAL_REGION_BEGIN(m_tx_pool.m_transactions_lock);
  for(crypto::hash &cur_hash: b.tx_hashes)
  {
    auto cur_res = m_tx_pool.m_transactions.find(cur_hash);
    if (cur_res == m_tx_pool.m_transactions.end())
    {
      LOG_ERROR("Creating block template: error: transaction not found");
      continue;
    }
    tx_memory_pool::tx_details &cur_tx = cur_res->second;
    real_txs_size += cur_tx.blob_size;
    real_fee += cur_tx.fee;
    if (cur_tx.blob_size != get_object_blobsize(cur_tx.tx))
    {
      LOG_ERROR("Creating block template: error: invalid transaction size");
    }
    if (cur_tx.tx.version == 1)
    {
      uint64_t inputs_amount;
      if (!get_inputs_money_amount(cur_tx.tx, inputs_amount))
      {
        LOG_ERROR("Creating block template: error: cannot get inputs amount");
      }
      else if (cur_tx.fee != inputs_amount - get_outs_money_amount(cur_tx.tx))
      {
        LOG_ERROR("Creating block template: error: invalid fee");
      }
    }
    else
    {
        //todo ATANA implement tx version 2 checks
        LOG_ERROR("Transacdtion version 2 not yet supported");
    }
  }
  if (txs_size != real_txs_size)
  {
    LOG_ERROR("Creating block template: error: wrongly calculated transaction size");
  }
  if (fee != real_fee)
  {
    LOG_ERROR("Creating block template: error: wrongly calculated fee");
  }
  CRITICAL_REGION_END();
  MDEBUG("Creating block template: height " << height <<
      ", median size " << median_size <<
      ", already generated coins " << already_generated_coins <<
      ", transaction size " << txs_size <<
      ", fee " << fee);
#endif

  /*
   two-phase miner transaction generation: we don't know exact block size until we prepare block, but we don't know reward until we know
   block size, so first miner transaction generated with fake amount of money, and with phase we know think we know expected block size
   */
  //make blocks coin-base tx looks close to real coinbase tx to get truthful blob size
  uint8_t hf_version = m_hardfork->get_current_version();
  size_t max_outs = hf_version >= HF_VERSION_CHANGE_MINER_DUST_HANDLING && hf_version < HF_VERSION_MINER_DUST_HANDLE_DIGIT ? 1 : HF_VERSION_MINER_TX_MAX_OUTS;
  bool r = construct_miner_tx(height, median_size, already_generated_coins, txs_size, fee, miner_address, b.miner_tx, ex_nonce, max_outs, hf_version);
  CHECK_AND_ASSERT_MES(r, false, "Failed to construct miner tx, first chance");
  size_t cumulative_size = txs_size + get_object_blobsize(b.miner_tx);
#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
  MDEBUG("Creating block template: miner tx size " << get_object_blobsize(b.miner_tx) <<
      ", cumulative size " << cumulative_size);
#endif
  for (size_t try_count = 0; try_count != 10; ++try_count)
  {
    r = construct_miner_tx(height, median_size, already_generated_coins, cumulative_size, fee, miner_address, b.miner_tx, ex_nonce, max_outs, hf_version);

    CHECK_AND_ASSERT_MES(r, false, "Failed to construct miner tx, second chance");
    size_t coinbase_blob_size = get_object_blobsize(b.miner_tx);
    if (coinbase_blob_size > cumulative_size - txs_size)
    {
      cumulative_size = txs_size + coinbase_blob_size;
#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
      MDEBUG("Creating block template: miner tx size " << coinbase_blob_size <<
          ", cumulative size " << cumulative_size << " is greater than before");
#endif
      continue;
    }

    if (coinbase_blob_size < cumulative_size - txs_size)
    {
      size_t delta = cumulative_size - txs_size - coinbase_blob_size;
#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
      MDEBUG("Creating block template: miner tx size " << coinbase_blob_size <<
          ", cumulative size " << txs_size + coinbase_blob_size <<
          " is less than before, adding " << delta << " zero bytes");
#endif
      b.miner_tx.extra.insert(b.miner_tx.extra.end(), delta, 0);
      //here  could be 1 byte difference, because of extra field counter is varint, and it can become from 1-byte len to 2-bytes len.
      if (cumulative_size != txs_size + get_object_blobsize(b.miner_tx))
      {
        CHECK_AND_ASSERT_MES(cumulative_size + 1 == txs_size + get_object_blobsize(b.miner_tx), false, "unexpected case: cumulative_size=" << cumulative_size << " + 1 is not equal txs_cumulative_size=" << txs_size << " + get_object_blobsize(b.miner_tx)=" << get_object_blobsize(b.miner_tx));
        b.miner_tx.extra.resize(b.miner_tx.extra.size() - 1);
        if (cumulative_size != txs_size + get_object_blobsize(b.miner_tx))
        {
          //fuck, not lucky, -1 makes varint-counter size smaller, in that case we continue to grow with cumulative_size
          MDEBUG("Miner tx creation has no luck with delta_extra size = " << delta << " and " << delta - 1);
          cumulative_size += delta - 1;
          continue;
        }
        MDEBUG("Setting extra for block: " << b.miner_tx.extra.size() << ", try_count=" << try_count);
      }
    }
    CHECK_AND_ASSERT_MES(cumulative_size == txs_size + get_object_blobsize(b.miner_tx), false, "unexpected case: cumulative_size=" << cumulative_size << " is not equal txs_cumulative_size=" << txs_size << " + get_object_blobsize(b.miner_tx)=" << get_object_blobsize(b.miner_tx));
#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
    MDEBUG("Creating block template: miner tx size " << coinbase_blob_size <<
        ", cumulative size " << cumulative_size << " is now good");
#endif
    return true;
  }
  LOG_ERROR("Failed to create_block_template with " << 10 << " tries");
  return false;
}
//------------------------------------------------------------------
// for an alternate chain, get the timestamps from the main chain to complete
// the needed number of timestamps for the BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW.
bool Blockchain::complete_timestamps_vector(uint64_t start_top_height, std::vector<uint64_t>& timestamps)
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  if(timestamps.size() >= BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW)
    return true;

  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  size_t need_elements = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW - timestamps.size();
  CHECK_AND_ASSERT_MES(start_top_height < m_db->height(), false, "internal error: passed start_height not < " << " m_db->height() -- " << start_top_height << " >= " << m_db->height());
  size_t stop_offset = start_top_height > need_elements ? start_top_height - need_elements : 0;
  while (start_top_height != stop_offset)
  {
    timestamps.push_back(m_db->get_block_timestamp(start_top_height));
    --start_top_height;
  }
  return true;
}
//------------------------------------------------------------------
// If a block is to be added and its parent block is not the current
// main chain top block, then we need to see if we know about its parent block.
// If its parent block is part of a known forked chain, then we need to see
// if that chain is long enough to become the main chain and re-org accordingly
// if so.  If not, we need to hang on to the block in case it becomes part of
// a long forked chain eventually.
bool Blockchain::handle_alternative_block(const block& b, const crypto::hash& id, block_verification_context& bvc)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  m_timestamps_and_difficulties_height = 0;
  uint64_t block_height = get_block_height(b);
  if(0 == block_height)
  {
    MERROR_VER("Block with id: " << epee::string_tools::pod_to_hex(id) << " (as alternative), but miner tx says height is 0.");
    bvc.m_verifivation_failed = true;
    return false;
  }
  // this basically says if the blockchain is smaller than the first
  // checkpoint then alternate blocks are allowed.  Alternatively, if the
  // last checkpoint *before* the end of the current chain is also before
  // the block to be added, then this is fine.
  if (!m_checkpoints.is_alternative_block_allowed(get_current_blockchain_height(), block_height))
  {
    MERROR_VER("Block with id: " << id << std::endl << " can't be accepted for alternative chain, block height: " << block_height << std::endl << " blockchain height: " << get_current_blockchain_height());
    bvc.m_verifivation_failed = true;
    return false;
  }

  // this is a cheap test
  if (!m_hardfork->check_for_height(b, block_height))
  {
    LOG_PRINT_L1("Block with id: " << id << std::endl << "has old version for height " << block_height);
    bvc.m_verifivation_failed = true;
    return false;
  }

  //block is not related with head of main chain
  //first of all - look in alternative chains container
  auto it_prev = m_alternative_chains.find(b.prev_id);
  bool parent_in_main = m_db->block_exists(b.prev_id);
  if(it_prev != m_alternative_chains.end() || parent_in_main)
  {
    //we have new block in alternative chain

    //build alternative subchain, front -> mainchain, back -> alternative head
    blocks_ext_by_hash::iterator alt_it = it_prev; //m_alternative_chains.find()
    std::list<blocks_ext_by_hash::iterator> alt_chain;
    std::vector<uint64_t> timestamps;
    while(alt_it != m_alternative_chains.end())
    {
      alt_chain.push_front(alt_it);
      timestamps.push_back(alt_it->second.bl.timestamp);
      alt_it = m_alternative_chains.find(alt_it->second.bl.prev_id);
    }

    // if block to be added connects to known blocks that aren't part of the
    // main chain -- that is, if we're adding on to an alternate chain
    if(alt_chain.size())
    {
      // make sure alt chain doesn't somehow start past the end of the main chain
      CHECK_AND_ASSERT_MES(m_db->height() > alt_chain.front()->second.height, false, "main blockchain wrong height");

      // make sure that the blockchain contains the block that should connect
      // this alternate chain with it.
      if (!m_db->block_exists(alt_chain.front()->second.bl.prev_id))
      {
        MERROR("alternate chain does not appear to connect to main chain...");
        return false;
      }

      // make sure block connects correctly to the main chain
      auto h = m_db->get_block_hash_from_height(alt_chain.front()->second.height - 1);
      CHECK_AND_ASSERT_MES(h == alt_chain.front()->second.bl.prev_id, false, "alternative chain has wrong connection to main chain");
      complete_timestamps_vector(m_db->get_block_height(alt_chain.front()->second.bl.prev_id), timestamps);
    }
    // if block not associated with known alternate chain
    else
    {
      // if block parent is not part of main chain or an alternate chain,
      // we ignore it
      CHECK_AND_ASSERT_MES(parent_in_main, false, "internal error: broken imperative condition: parent_in_main");

      complete_timestamps_vector(m_db->get_block_height(b.prev_id), timestamps);
    }

    // verify that the block's timestamp is within the acceptable range
    // (not earlier than the median of the last X blocks)
    if(!check_block_timestamp(timestamps, b))
    {
      MERROR_VER("Block with id: " << id << std::endl << " for alternative chain, has invalid timestamp: " << b.timestamp);
      bvc.m_verifivation_failed = true;
      return false;
    }

    // FIXME: consider moving away from block_extended_info at some point
    block_extended_info bei = boost::value_initialized<block_extended_info>();
    bei.bl = b;
    bei.height = alt_chain.size() ? it_prev->second.height + 1 : m_db->get_block_height(b.prev_id) + 1;

    bool is_a_checkpoint;
    if(!m_checkpoints.check_block(bei.height, id, is_a_checkpoint))
    {
      LOG_ERROR("CHECKPOINT VALIDATION FAILED");
      bvc.m_verifivation_failed = true;
      return false;
    }

    // Check the block's hash against the difficulty target for its alt chain
    difficulty_type current_diff = get_next_difficulty_for_alternative_chain(alt_chain, bei);
    CHECK_AND_ASSERT_MES(current_diff, false, "!!!!!!! DIFFICULTY OVERHEAD !!!!!!!");
    crypto::hash proof_of_work = null_hash;
    if (b.major_version >= RX_BLOCK_VERSION)
    {
      crypto::hash seedhash = null_hash;
      uint64_t seedheight = rx_seedheight(bei.height);
      // seedblock is on the alt chain somewhere
      if (alt_chain.size() && alt_chain.front()->second.height <= seedheight)
      {
        for (auto it = alt_chain.begin(); it != alt_chain.end(); it++)
        {
          if ((*it)->second.height == seedheight + 1)
          {
            seedhash = (*it)->second.bl.prev_id;
            break;
          }
        }
      }
      else
      {
        seedhash = get_block_id_by_height(seedheight);
      }
      get_altblock_longhash(bei.bl, proof_of_work, get_current_blockchain_height(), bei.height, seedheight, seedhash);
    }
    else
    {
      get_block_longhash(this, bei.bl, proof_of_work, bei.height, 0);
    }

    if(!check_hash(proof_of_work, current_diff))
    {
      MERROR_VER("Block with id: " << id << std::endl << " for alternative chain, does not have enough proof of work: " << proof_of_work << std::endl << " expected difficulty: " << current_diff);
      bvc.m_verifivation_failed = true;
      return false;
    }

    if(!prevalidate_miner_transaction(b, bei.height))
    {
      MERROR_VER("Block with id: " << epee::string_tools::pod_to_hex(id) << " (as alternative) has incorrect miner transaction.");
      bvc.m_verifivation_failed = true;
      return false;
    }

    // FIXME:
    // this brings up an interesting point: consider allowing to get block
    // difficulty both by height OR by hash, not just height.
    difficulty_type main_chain_cumulative_difficulty = m_db->get_block_cumulative_difficulty(m_db->height() - 1);
    if (alt_chain.size())
    {
      bei.cumulative_difficulty = it_prev->second.cumulative_difficulty;
    }
    else
    {
      // passed-in block's previous block's cumulative difficulty, found on the main chain
      bei.cumulative_difficulty = m_db->get_block_cumulative_difficulty(m_db->get_block_height(b.prev_id));
    }
    bei.cumulative_difficulty += current_diff;

    // add block to alternate blocks storage,
    // as well as the current "alt chain" container
    auto i_res = m_alternative_chains.insert(blocks_ext_by_hash::value_type(id, bei));
    CHECK_AND_ASSERT_MES(i_res.second, false, "insertion of new alternative block returned as it already exist");
    alt_chain.push_back(i_res.first);

    // FIXME: is it even possible for a checkpoint to show up not on the main chain?
    if(is_a_checkpoint)
    {
      //do reorganize!
      MGINFO_GREEN("###### REORGANIZE on height: " << alt_chain.front()->second.height << " of " << m_db->height() - 1 << ", checkpoint is found in alternative chain on height " << bei.height);

      bool r = switch_to_alternative_blockchain(alt_chain, true);

      if(r) bvc.m_added_to_main_chain = true;
      else bvc.m_verifivation_failed = true;

      return r;
    }
    else if(main_chain_cumulative_difficulty < bei.cumulative_difficulty) //check if difficulty bigger then in main chain
    {
      //do reorganize!
      MGINFO_GREEN("###### REORGANIZE on height: " << alt_chain.front()->second.height << " of " << m_db->height() - 1 << " with cum_difficulty " << m_db->get_block_cumulative_difficulty(m_db->height() - 1) << std::endl << " alternative blockchain size: " << alt_chain.size() << " with cum_difficulty " << bei.cumulative_difficulty);

      bool r = switch_to_alternative_blockchain(alt_chain, false);
      if (r)
        bvc.m_added_to_main_chain = true;
      else
        bvc.m_verifivation_failed = true;
      return r;
    }
    else
    {
      MGINFO_BLUE("----- BLOCK ADDED AS ALTERNATIVE ON HEIGHT " << bei.height << std::endl << "id:\t" << id << std::endl << "PoW:\t" << proof_of_work << std::endl << "difficulty:\t" << current_diff);
      return true;
    }
  }
  else
  {
    //block orphaned
    bvc.m_marked_as_orphaned = true;
    MERROR_VER("Block recognized as orphaned and rejected, id = " << id << ", height " << block_height
        << ", parent in alt " << (it_prev != m_alternative_chains.end()) << ", parent in main " << parent_in_main
        << " (parent " << b.prev_id << ", current top " << get_tail_id() << ", chain height " << get_current_blockchain_height() << ")");
  }

  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_blocks(uint64_t start_offset, size_t count, std::list<std::pair<cryptonote::blobdata,block>>& blocks, std::list<cryptonote::blobdata>& txs) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  if(start_offset >= m_db->height())
    return false;

  if (!get_blocks(start_offset, count, blocks))
  {
    return false;
  }

  for(const auto& blk : blocks)
  {
    std::list<crypto::hash> missed_ids;
    get_transactions_blobs(blk.second.tx_hashes, txs, missed_ids);
    CHECK_AND_ASSERT_MES(!missed_ids.size(), false, "has missed transactions in own block in main blockchain");
  }

  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_blocks(uint64_t start_offset, size_t count, std::list<std::pair<cryptonote::blobdata,block>>& blocks) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  if(start_offset >= m_db->height())
    return false;

  for(size_t i = start_offset; i < start_offset + count && i < m_db->height();i++)
  {
    blocks.push_back(std::make_pair(m_db->get_block_blob_from_height(i), block()));
    if (!parse_and_validate_block_from_blob(blocks.back().first, blocks.back().second))
    {
      LOG_ERROR("Invalid block");
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
//TODO: This function *looks* like it won't need to be rewritten
//      to use BlockchainDB, as it calls other functions that were,
//      but it warrants some looking into later.
//
//FIXME: This function appears to want to return false if any transactions
//       that belong with blocks are missing, but not if blocks themselves
//       are missing.
bool Blockchain::handle_get_objects(NOTIFY_REQUEST_GET_OBJECTS::request& arg, NOTIFY_RESPONSE_GET_OBJECTS::request& rsp)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  m_db->block_txn_start(true);
  rsp.current_blockchain_height = get_current_blockchain_height();
  std::list<std::pair<cryptonote::blobdata,block>> blocks;
  get_blocks(arg.blocks, blocks, rsp.missed_ids);

  for (const auto& bl: blocks)
  {
    std::list<crypto::hash> missed_tx_ids;
    std::list<cryptonote::blobdata> txs;

    // FIXME: s/rsp.missed_ids/missed_tx_id/ ?  Seems like rsp.missed_ids
    //        is for missed blocks, not missed transactions as well.
    get_transactions_blobs(bl.second.tx_hashes, txs, missed_tx_ids);

    if (missed_tx_ids.size() != 0)
    {
      LOG_ERROR("Error retrieving blocks, missed " << missed_tx_ids.size()
          << " transactions for block with hash: " << get_block_hash(bl.second)
          << std::endl
      );

      // append missed transaction hashes to response missed_ids field,
      // as done below if any standalone transactions were requested
      // and missed.
      rsp.missed_ids.splice(rsp.missed_ids.end(), missed_tx_ids);
	  m_db->block_txn_stop();
      return false;
    }

    rsp.blocks.push_back(block_complete_entry());
    block_complete_entry& e = rsp.blocks.back();
    //pack block
    e.block = bl.first;
    //pack transactions
    for (const cryptonote::blobdata& tx: txs)
      e.txs.push_back(tx);
  }
  //get another transactions, if need
  std::list<cryptonote::blobdata> txs;
  get_transactions_blobs(arg.txs, txs, rsp.missed_ids);
  //pack aside transactions
  for (const auto& tx: txs)
    rsp.txs.push_back(tx);

  m_db->block_txn_stop();
  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_alternative_blocks(std::list<block>& blocks) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  for (const auto& alt_bl: m_alternative_chains)
  {
    blocks.push_back(alt_bl.second.bl);
  }
  return true;
}
//------------------------------------------------------------------
size_t Blockchain::get_alternative_blocks_count() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  return m_alternative_chains.size();
}
//------------------------------------------------------------------
// This function adds the output specified by <amount, i> to the result_outs container
// unlocked and other such checks should be done by here.
void Blockchain::add_out_to_get_random_outs(COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount& result_outs, uint64_t amount, size_t i) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::out_entry& oen = *result_outs.outs.insert(result_outs.outs.end(), COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::out_entry());
  oen.global_amount_index = i;
  output_data_t data = m_db->get_output_key(amount, i, result_outs.output_type);
  oen.out_key = data.pubkey;
}

uint64_t Blockchain::get_num_mature_outputs(uint64_t amount, const tx_out_type output_type) const
{
  uint64_t num_outs = m_db->get_num_outputs(amount, output_type);
  // ensure we don't include outputs that aren't yet eligible to be used
  // outpouts are sorted by height
  while (num_outs > 0)
  {
    const tx_out_index toi = m_db->get_output_tx_and_index(amount, num_outs - 1, output_type);
    const uint64_t height = m_db->get_tx_block_height(toi.first);
    if (height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE <= m_db->height())
      break;
    --num_outs;
  }

  return num_outs;
}

std::vector<uint64_t> Blockchain::get_random_outputs(uint64_t amount, uint64_t count, const tx_out_type output_type) const
{
  uint64_t num_outs = get_num_mature_outputs(amount, output_type);

  std::vector<uint64_t> indices;

  std::unordered_set<uint64_t> seen_indices;

  // if there aren't enough outputs to mix with (or just enough),
  // use all of them.  Eventually this should become impossible.
  if (num_outs <= count)
  {
    for (uint64_t i = 0; i < num_outs; i++)
    {
      // get tx_hash, tx_out_index from DB
      tx_out_index toi = m_db->get_output_tx_and_index(amount, i, output_type);

      // if tx is unlocked, add output to indices
      if (is_tx_spendtime_unlocked(m_db->get_tx_unlock_time(toi.first)))
      {
        indices.push_back(i);
      }
    }
  }
  else
  {
    // while we still need more mixins
    while (indices.size() < count)
    {
      // if we've gone through every possible output, we've gotten all we can
      if (seen_indices.size() == num_outs)
      {
        break;
      }

      // get a random output index from the DB.  If we've already seen it,
      // return to the top of the loop and try again, otherwise add it to the
      // list of output indices we've seen.

      // triangular distribution over [a,b) with a=0, mode c=b=up_index_limit
      uint64_t r = crypto::rand<uint64_t>() % ((uint64_t)1 << 53);
      double frac = std::sqrt((double)r / ((uint64_t)1 << 53));
      uint64_t i = (uint64_t)(frac*num_outs);
      // just in case rounding up to 1 occurs after sqrt
      if (i == num_outs)
        --i;

      if (seen_indices.count(i))
      {
        continue;
      }
      seen_indices.emplace(i);

      // get tx_hash, tx_out_index from DB
      tx_out_index toi = m_db->get_output_tx_and_index(amount, i, output_type);

      // if the output's transaction is unlocked, add the output's index to
      // our list.
      if (is_tx_spendtime_unlocked(m_db->get_tx_unlock_time(toi.first)))
      {
        indices.push_back(i);
      }
    }
  }

  return indices;
}

crypto::public_key Blockchain::get_output_key(uint64_t amount, uint64_t global_index, const tx_out_type output_type) const
{
  output_data_t data = m_db->get_output_key(amount, global_index, output_type);
  return data.pubkey;
}

//------------------------------------------------------------------
// This function takes an RPC request for mixins and creates an RPC response
// with the requested mixins.
// TODO: figure out why this returns boolean / if we should be returning false
// in some cases
bool Blockchain::get_random_outs_for_amounts(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::request& req, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response& res) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // for each amount that we need to get mixins for, get <n> random outputs
  // from BlockchainDB where <n> is req.outs_count (number of mixins).
  for (uint64_t amount : req.amounts)
  {
    // create outs_for_amount struct and populate amount field
    COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount& result_outs = *res.outs.insert(res.outs.end(), COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount());
    result_outs.amount = amount;

    std::vector<uint64_t> indices = get_random_outputs(amount, req.outs_count, req.output_type);

    for (auto i : indices)
    {
      COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::out_entry& oe = *result_outs.outs.insert(result_outs.outs.end(), COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::out_entry());

      oe.global_amount_index = i;
      oe.out_key = get_output_key(amount, i, req.output_type);
    }
  }
  return true;
}
//------------------------------------------------------------------
// This function adds the ringct output at index i to the list
// unlocked and other such checks should be done by here.
void Blockchain::add_out_to_get_rct_random_outs(std::list<COMMAND_RPC_GET_RANDOM_RCT_OUTPUTS::out_entry>& outs, uint64_t amount, size_t i, const tx_out_type output_type) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  COMMAND_RPC_GET_RANDOM_RCT_OUTPUTS::out_entry& oen = *outs.insert(outs.end(), COMMAND_RPC_GET_RANDOM_RCT_OUTPUTS::out_entry());
  oen.amount = amount;
  oen.global_amount_index = i;
  output_data_t data = m_db->get_output_key(amount, i, output_type);
  oen.out_key = data.pubkey;
  oen.commitment = data.commitment;
}
//------------------------------------------------------------------
// This function takes an RPC request for mixins and creates an RPC response
// with the requested mixins.
// TODO: figure out why this returns boolean / if we should be returning false
// in some cases
bool Blockchain::get_random_rct_outs(const COMMAND_RPC_GET_RANDOM_RCT_OUTPUTS::request& req, COMMAND_RPC_GET_RANDOM_RCT_OUTPUTS::response& res) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // for each amount that we need to get mixins for, get <n> random outputs
  // from BlockchainDB where <n> is req.outs_count (number of mixins).
  auto num_outs = m_db->get_num_outputs(0, req.output_type);
  // ensure we don't include outputs that aren't yet eligible to be used
  // outpouts are sorted by height
  while (num_outs > 0)
  {
    const tx_out_index toi = m_db->get_output_tx_and_index(0, num_outs - 1, req.output_type);
    const uint64_t height = m_db->get_tx_block_height(toi.first);
    if (height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE <= m_db->height())
      break;
    --num_outs;
  }

  std::unordered_set<uint64_t> seen_indices;

  // if there aren't enough outputs to mix with (or just enough),
  // use all of them.  Eventually this should become impossible.
  if (num_outs <= req.outs_count)
  {
    for (uint64_t i = 0; i < num_outs; i++)
    {
      // get tx_hash, tx_out_index from DB
      tx_out_index toi = m_db->get_output_tx_and_index(0, i, req.output_type);

      // if tx is unlocked, add output to result_outs
      if (is_tx_spendtime_unlocked(m_db->get_tx_unlock_time(toi.first)))
      {
        add_out_to_get_rct_random_outs(res.outs, 0, i, req.output_type);
      }
    }
  }
  else
  {
    // while we still need more mixins
    while (res.outs.size() < req.outs_count)
    {
      // if we've gone through every possible output, we've gotten all we can
      if (seen_indices.size() == num_outs)
      {
        break;
      }

      // get a random output index from the DB.  If we've already seen it,
      // return to the top of the loop and try again, otherwise add it to the
      // list of output indices we've seen.

      // triangular distribution over [a,b) with a=0, mode c=b=up_index_limit
      uint64_t r = crypto::rand<uint64_t>() % ((uint64_t)1 << 53);
      double frac = std::sqrt((double)r / ((uint64_t)1 << 53));
      uint64_t i = (uint64_t)(frac*num_outs);
      // just in case rounding up to 1 occurs after sqrt
      if (i == num_outs)
        --i;

      if (seen_indices.count(i))
      {
        continue;
      }
      seen_indices.emplace(i);

      // get tx_hash, tx_out_index from DB
      tx_out_index toi = m_db->get_output_tx_and_index(0, i, req.output_type);

      // if the output's transaction is unlocked, add the output's index to
      // our list.
      if (is_tx_spendtime_unlocked(m_db->get_tx_unlock_time(toi.first)))
      {
        add_out_to_get_rct_random_outs(res.outs, 0, i, req.output_type);
      }
    }
  }

  if (res.outs.size() < req.outs_count)
    return false;
#if 0
  // if we do not have enough RCT inputs, we can pick from the non RCT ones
  // which will have a zero mask
  if (res.outs.size() < req.outs_count)
  {
    LOG_PRINT_L0("Out of RCT inputs (" << res.outs.size() << "/" << req.outs_count << "), using regular ones");

    // TODO: arbitrary selection, needs better
    COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::request req2 = AUTO_VAL_INIT(req2);
    COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response res2 = AUTO_VAL_INIT(res2);
    req2.outs_count = req.outs_count - res.outs.size();
    static const uint64_t amounts[] = {1, 10, 20, 50, 100, 200, 500, 1000, 10000};
    for (uint64_t a: amounts)
      req2.amounts.push_back(a);
    if (!get_random_outs_for_amounts(req2, res2))
      return false;

    // pick random ones from there
    while (res.outs.size() < req.outs_count)
    {
      int list_idx = rand() % (sizeof(amounts)/sizeof(amounts[0]));
      if (!res2.outs[list_idx].outs.empty())
      {
        const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::out_entry oe = res2.outs[list_idx].outs.back();
        res2.outs[list_idx].outs.pop_back();
        add_out_to_get_rct_random_outs(res.outs, res2.outs[list_idx].amount, oe.global_amount_index, req.out_type);
      }
    }
  }
#endif

  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_outs(const COMMAND_RPC_GET_OUTPUTS_BIN::request& req, COMMAND_RPC_GET_OUTPUTS_BIN::response& res) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  res.outs.clear();
  res.outs.reserve(req.outputs.size());
  for (const auto &i: req.outputs)
  {
    // get tx_hash, tx_out_index from DB
    const output_data_t od = m_db->get_output_key(i.amount, i.index, req.out_type);
    tx_out_index toi = m_db->get_output_tx_and_index(i.amount, i.index, req.out_type);
    bool unlocked = is_tx_spendtime_unlocked(m_db->get_tx_unlock_time(toi.first));
    if(req.out_type == cryptonote::tx_out_type::out_token){
      cryptonote::transaction tx = m_db->get_tx(toi.first);
      if(is_create_safex_account_token_fee(tx.vout, od.pubkey))
        unlocked &= od.height + safex::get_safex_minumum_account_create_token_lock_period(m_nettype) <= m_db->height();
   }

    res.outs.push_back({od.pubkey, od.commitment, unlocked, od.height, toi.first});
  }
  return true;
}

//------------------------------------------------------------------
bool Blockchain::get_outs_proto(const COMMAND_RPC_GET_OUTPUTS_PROTOBUF::request& req, safex::outputs_protobuf& proto) const 
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  #ifdef SAFEX_PROTOBUF_RPC
    CRITICAL_REGION_LOCAL(m_blockchain_lock);

    auto out_type = static_cast<cryptonote::tx_out_type>(req.out_type);

    for (const auto &i: req.outputs)
    {
      // get tx_hash, tx_out_index from DB
      const output_data_t od = m_db->get_output_key(i.amount, i.index, out_type);
      tx_out_index toi = m_db->get_output_tx_and_index(i.amount, i.index,  out_type);
      bool unlocked = is_tx_spendtime_unlocked(m_db->get_tx_unlock_time(toi.first));
      if(out_type == cryptonote::tx_out_type::out_token){
        cryptonote::transaction tx = m_db->get_tx(toi.first);
        if(is_create_safex_account_token_fee(tx.vout, od.pubkey))
          unlocked &= od.height + safex::get_safex_minumum_account_create_token_lock_period(m_nettype) <= m_db->height();
     }

      proto.add_out_entry(od.pubkey, unlocked, od.height, toi.first);
    }
  #endif
  return true;
}
//------------------------------------------------------------------
void Blockchain::get_output_key_mask_unlocked(const uint64_t& amount, const uint64_t& index, crypto::public_key& key, rct::key& mask, bool& unlocked, const tx_out_type output_type) const
{
  const auto o_data = m_db->get_output_key(amount, index, output_type);
  key = o_data.pubkey;
  mask = o_data.commitment;
  tx_out_index toi = m_db->get_output_tx_and_index(amount, index, output_type);
  unlocked = is_tx_spendtime_unlocked(m_db->get_tx_unlock_time(toi.first));
}
//------------------------------------------------------------------
bool Blockchain::get_output_distribution(uint64_t amount, const tx_out_type output_type, uint64_t from_height, uint64_t &start_height, std::vector<uint64_t> &distribution, uint64_t &base) const
{
  // rct outputs don't exist before v3
  if (amount == 0)
  {
    switch (m_nettype)
    {
      case STAGENET: start_height = stagenet_hard_forks[2].height; break;
      case TESTNET: start_height = testnet_hard_forks[2].height; break;
      case MAINNET: start_height = mainnet_hard_forks[2].height; break;
      default: return false;
    }
  }
  else
    start_height = 0;
  base = 0;

  const uint64_t real_start_height = start_height;
  if (from_height > start_height)
    start_height = from_height;

  distribution.clear();
  uint64_t db_height = m_db->height();
  if (start_height >= db_height)
    return false;
  distribution.resize(db_height - start_height, 0);
  bool r = for_all_outputs(amount, [&](uint64_t height) {
    CHECK_AND_ASSERT_MES(height >= real_start_height && height <= db_height, false, "Height not in expected range");
    if (height >= start_height)
      distribution[height - start_height]++;
    else
      base++;
    return true;
  }, output_type);
  if (!r)
    return false;
  return true;
}
//------------------------------------------------------------------
// This function takes a list of block hashes from another node
// on the network to find where the split point is between us and them.
// This is used to see what to send another node that needs to sync.
bool Blockchain::find_blockchain_supplement(const std::list<crypto::hash>& qblock_ids, uint64_t& starter_offset) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // make sure the request includes at least the genesis block, otherwise
  // how can we expect to sync from the client that the block list came from?
  if(!qblock_ids.size() /*|| !req.m_total_height*/)
  {
    MCERROR("net.p2p", "Client sent wrong NOTIFY_REQUEST_CHAIN: m_block_ids.size()=" << qblock_ids.size() << /*", m_height=" << req.m_total_height <<*/ ", dropping connection");
    return false;
  }

  m_db->block_txn_start(true);
  // make sure that the last block in the request's block list matches
  // the genesis block
  auto gen_hash = m_db->get_block_hash_from_height(0);
  if(qblock_ids.back() != gen_hash)
  {
    MCERROR("net.p2p", "Client sent wrong NOTIFY_REQUEST_CHAIN: genesis block mismatch: " << std::endl << "id: " << qblock_ids.back() << ", " << std::endl << "expected: " << gen_hash << "," << std::endl << " dropping connection");
	m_db->block_txn_abort();
    return false;
  }

  // Find the first block the foreign chain has that we also have.
  // Assume qblock_ids is in reverse-chronological order.
  auto bl_it = qblock_ids.begin();
  uint64_t split_height = 0;
  for(; bl_it != qblock_ids.end(); bl_it++)
  {
    try
    {
      if (m_db->block_exists(*bl_it, &split_height))
        break;
    }
    catch (const std::exception& e)
    {
      MWARNING("Non-critical error trying to find block by hash in BlockchainDB, hash: " << *bl_it);
	  m_db->block_txn_abort();
      return false;
    }
  }
  m_db->block_txn_stop();

  // this should be impossible, as we checked that we share the genesis block,
  // but just in case...
  if(bl_it == qblock_ids.end())
  {
    MERROR("Internal error handling connection, can't find split point");
    return false;
  }

  //we start to put block ids INCLUDING last known id, just to make other side be sure
  starter_offset = split_height;
  return true;
}
//------------------------------------------------------------------
uint64_t Blockchain::block_difficulty(uint64_t i) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  try
  {
    return m_db->get_block_difficulty(i);
  }
  catch (const BLOCK_DNE& e)
  {
    MERROR("Attempted to get block difficulty for height above blockchain height");
  }
  return 0;
}
//------------------------------------------------------------------
// Find the split point between us and foreign blockchain and return
// (by reference) the most recent common block hash along with up to
// BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT additional (more recent) hashes.
bool Blockchain::find_blockchain_supplement(const std::list<crypto::hash>& qblock_ids, std::list<crypto::hash>& hashes, uint64_t& start_height, uint64_t& current_height) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // if we can't find the split point, return false
  if(!find_blockchain_supplement(qblock_ids, start_height))
  {
    return false;
  }

  m_db->block_txn_start(true);
  current_height = get_current_blockchain_height();
  size_t count = 0;
  for(size_t i = start_height; i < current_height && count < BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT; i++, count++)
  {
    hashes.push_back(m_db->get_block_hash_from_height(i));
  }

  m_db->block_txn_stop();
  return true;
}

bool Blockchain::find_blockchain_supplement(const std::list<crypto::hash>& qblock_ids, NOTIFY_RESPONSE_CHAIN_ENTRY::request& resp) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  bool result = find_blockchain_supplement(qblock_ids, resp.m_block_ids, resp.start_height, resp.total_height);
  resp.cumulative_difficulty = m_db->get_block_cumulative_difficulty(m_db->height() - 1);

  return result;
}
//------------------------------------------------------------------
//FIXME: change argument to std::vector, low priority
// find split point between ours and foreign blockchain (or start at
// blockchain height <req_start_block>), and return up to max_count FULL
// blocks by reference.
bool Blockchain::find_blockchain_supplement(const uint64_t req_start_block, const std::list<crypto::hash>& qblock_ids, std::list<std::pair<cryptonote::blobdata, std::list<cryptonote::blobdata> > >& blocks, uint64_t& total_height, uint64_t& start_height, size_t max_count) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // if a specific start height has been requested
  if(req_start_block > 0)
  {
    // if requested height is higher than our chain, return false -- we can't help
    if (req_start_block >= m_db->height())
    {
      return false;
    }
    start_height = req_start_block;
  }
  else
  {
    if(!find_blockchain_supplement(qblock_ids, start_height))
    {
      return false;
    }
  }

  m_db->block_txn_start(true);
  total_height = get_current_blockchain_height();
  size_t count = 0, size = 0;
  for(size_t i = start_height; i < total_height && count < max_count && (size < FIND_BLOCKCHAIN_SUPPLEMENT_MAX_SIZE || count < 3); i++, count++)
  {
    blocks.resize(blocks.size()+1);
    blocks.back().first = m_db->get_block_blob_from_height(i);
    block b;
    CHECK_AND_ASSERT_MES(parse_and_validate_block_from_blob(blocks.back().first, b), false, "internal error, invalid block");
    std::list<crypto::hash> mis;
    get_transactions_blobs(b.tx_hashes, blocks.back().second, mis);
    CHECK_AND_ASSERT_MES(!mis.size(), false, "internal error, transaction from block not found");
    size += blocks.back().first.size();
    for (const auto &t: blocks.back().second)
      size += t.size();
  }
  m_db->block_txn_stop();
  return true;
}
//------------------------------------------------------------------
bool Blockchain::add_block_as_invalid(const block& bl, const crypto::hash& h)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  block_extended_info bei = AUTO_VAL_INIT(bei);
  bei.bl = bl;
  return add_block_as_invalid(bei, h);
}
//------------------------------------------------------------------
bool Blockchain::add_block_as_invalid(const block_extended_info& bei, const crypto::hash& h)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  auto i_res = m_invalid_blocks.insert(std::map<crypto::hash, block_extended_info>::value_type(h, bei));
  CHECK_AND_ASSERT_MES(i_res.second, false, "at insertion invalid by tx returned status existed");
  MINFO("BLOCK ADDED AS INVALID: " << h << std::endl << ", prev_id=" << bei.bl.prev_id << ", m_invalid_blocks count=" << m_invalid_blocks.size());
  return true;
}
//------------------------------------------------------------------
bool Blockchain::have_block(const crypto::hash& id) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  if(m_db->block_exists(id))
  {
    LOG_PRINT_L3("block exists in main chain");
    return true;
  }

  if(m_alternative_chains.count(id))
  {
    LOG_PRINT_L3("block found in m_alternative_chains");
    return true;
  }

  if(m_invalid_blocks.count(id))
  {
    LOG_PRINT_L3("block found in m_invalid_blocks");
    return true;
  }

  return false;
}
//------------------------------------------------------------------
bool Blockchain::handle_block_to_main_chain(const block& bl, block_verification_context& bvc)
{
    LOG_PRINT_L3("Blockchain::" << __func__);
    crypto::hash id = get_block_hash(bl);
    return handle_block_to_main_chain(bl, id, bvc);
}
//------------------------------------------------------------------
size_t Blockchain::get_total_transactions() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return m_db->get_tx_count();
}
//------------------------------------------------------------------
// This function checks each input in the transaction <tx> to make sure it
// has not been used already, and adds its key to the container <keys_this_block>.
//
// This container should be managed by the code that validates blocks so we don't
// have to store the used keys in a given block in the permanent storage only to
// remove them later if the block fails validation.
bool Blockchain::check_for_double_spend(const transaction& tx, key_images_container& keys_this_block) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  struct add_transaction_input_visitor: public boost::static_visitor<bool>
  {
    key_images_container& m_spent_keys;
    BlockchainDB* m_db;
    add_transaction_input_visitor(key_images_container& spent_keys, BlockchainDB* db) :
      m_spent_keys(spent_keys), m_db(db)
    {
    }
    bool operator()(const txin_to_key& in) const
    {
      const crypto::key_image& ki = in.k_image;

      // attempt to insert the newly-spent key into the container of
      // keys spent this block.  If this fails, the key was spent already
      // in this block, return false to flag that a double spend was detected.
      //
      // if the insert into the block-wide spent keys container succeeds,
      // check the blockchain-wide spent keys container and make sure the
      // key wasn't used in another block already.
      auto r = m_spent_keys.insert(ki);
      if(!r.second || m_db->has_key_image(ki))
      {
        //double spend detected
        return false;
      }

      // if no double-spend detected, return true
      return true;
    }

    bool operator()(const txin_gen& tx) const
    {
      return true;
    }
    bool operator()(const txin_to_script& tx) const
    {
      return false;
    }
    bool operator()(const txin_to_scripthash& tx) const
    {
      return false;
    }

    bool operator()(const txin_token_migration& tx) const
    {
      return true;
    }


    bool operator()(const txin_token_to_key& in) const
    {
      const crypto::key_image& ki = in.k_image;

      // attempt to insert the newly-spent key into the container of
      // keys spent this block.  If this fails, the key was spent already
      // in this block, return false to flag that a double spend was detected.
      //
      // if the insert into the block-wide spent keys container succeeds,
      // check the blockchain-wide spent keys container and make sure the
      // key wasn't used in another block already.
      auto r = m_spent_keys.insert(ki);
      if(!r.second || m_db->has_key_image(ki))
      {
        //double spend detected
        return false;
      }

      // if no double-spend detected, return true
      return true;
    }

  };

  for (const txin_v& in : tx.vin)
  {
    if(!boost::apply_visitor(add_transaction_input_visitor(keys_this_block, m_db), in))
    {
      LOG_ERROR("Double spend detected!");
      return false;
    }
  }

  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_tx_outputs_gindexs(const crypto::hash& tx_id, std::vector<uint64_t>& indexs) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  uint64_t tx_index;
  if (!m_db->tx_exists(tx_id, tx_index))
  {
    MERROR_VER("get_tx_outputs_gindexs failed to find transaction with id = " << tx_id);
    return false;
  }

  // get amount output indexes, currently referred to in parts as "output global indices", but they are actually specific to amounts
  indexs = m_db->get_tx_amount_output_indices(tx_index);
  if (indexs.empty())
  {
    // empty indexs is only valid if the vout is empty, which is legal but rare
    cryptonote::transaction tx = m_db->get_tx(tx_id);
    CHECK_AND_ASSERT_MES(tx.vout.empty(), false, "internal error: global indexes for transaction " << tx_id << " is empty, and tx vout is not");
  }

  return true;
}
//------------------------------------------------------------------
void Blockchain::on_new_tx_from_block(const cryptonote::transaction &tx)
{
#if defined(PER_BLOCK_CHECKPOINT)
  // check if we're doing per-block checkpointing
  if (m_db->height() < m_blocks_hash_check.size())
  {
    TIME_MEASURE_START(a);
    m_blocks_txs_check.push_back(get_transaction_hash(tx));
    TIME_MEASURE_FINISH(a);
    if(m_show_time_stats)
    {
      size_t ring_size = !tx.vin.empty() && tx.vin[0].type() == typeid(txin_to_key) ? boost::get<txin_to_key>(tx.vin[0]).key_offsets.size() : 0;
      MINFO("HASH: " << "-" << " I/M/O: " << tx.vin.size() << "/" << ring_size << "/" << tx.vout.size() << " H: " << 0 << " chcktx: " << a);
    }
  }
#endif
}
//------------------------------------------------------------------
//FIXME: it seems this function is meant to be merely a wrapper around
//       another function of the same name, this one adding one bit of
//       functionality.  Should probably move anything more than that
//       (getting the hash of the block at height max_used_block_id)
//       to the other function to keep everything in one place.
// This function overloads its sister function with
// an extra value (hash of highest block that holds an output used as input)
// as a return-by-reference.
bool Blockchain::check_tx_inputs(transaction& tx, uint64_t& max_used_block_height, crypto::hash& max_used_block_id, tx_verification_context &tvc, bool kept_by_block)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

#if defined(PER_BLOCK_CHECKPOINT)
  // check if we're doing per-block checkpointing
  if (m_db->height() < m_blocks_hash_check.size() && kept_by_block)
  {
    max_used_block_id = null_hash;
    max_used_block_height = 0;
    return true;
  }
#endif

  TIME_MEASURE_START(a);
  bool res = check_tx_inputs(tx, tvc, &max_used_block_height);
  TIME_MEASURE_FINISH(a);
  if(m_show_time_stats)
  {
    size_t ring_size = !tx.vin.empty() && tx.vin[0].type() == typeid(txin_to_key) ? boost::get<txin_to_key>(tx.vin[0]).key_offsets.size() : 0;
    MINFO("HASH: " <<  get_transaction_hash(tx) << " I/M/O: " << tx.vin.size() << "/" << ring_size << "/" << tx.vout.size() << " H: " << max_used_block_height << " ms: " << a + m_fake_scan_time << " B: " << get_object_blobsize(tx));
  }
  if (!res)
    return false;

  CHECK_AND_ASSERT_MES(max_used_block_height < m_db->height(), false,  "internal error: max used block index=" << max_used_block_height << " is not less then blockchain size = " << m_db->height());
  max_used_block_id = m_db->get_block_hash_from_height(max_used_block_height);
  return true;
}
//------------------------------------------------------------------
bool Blockchain::check_tx_outputs(const transaction& tx, tx_verification_context &tvc)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  const uint8_t hf_version = m_hardfork->get_current_version();

  //From some hard fork version in the future, forbid dust and compound outputs
  if (hf_version >= HF_VERSION_FORBID_DUST)
  {
    for (auto &o: tx.vout)
    {
      if (!is_valid_decomposed_amount(o.amount) && !is_valid_decomposed_amount(o.token_amount))
      {
        tvc.m_invalid_output = true;
        return false;
      }
    }
  }

  // check that the outputs are whole amounts for token transfers
  for (auto &o: tx.vout)
  {
    if ((o.target.type() == typeid(txout_token_to_key)))
    {
      if (!tools::is_whole_token_amount(o.token_amount))
      {
        tvc.m_invalid_output = true;
        return false;
      }
    }
  }

  //forbid invalid pubkeys
  for (const auto &o: tx.vout)
  {
    if (is_valid_transaction_output_type(o.target))
    {
      const crypto::public_key &out_key = *boost::apply_visitor(cryptonote::destination_public_key_visitor(), o.target);
      if (!crypto::check_key(out_key))
      {
        tvc.m_invalid_output = true;
        return false;
      }
    }
  }

  // allow bulletproofs
  if (hf_version < HF_VERSION_ALLOW_BULLETPROOFS) {
    const bool bulletproof = tx.rct_signatures.type == rct::RCTTypeFullBulletproof || tx.rct_signatures.type == rct::RCTTypeSimpleBulletproof;
    if (bulletproof || !tx.rct_signatures.p.bulletproofs.empty())
    {
      MERROR("Bulletproofs are not allowed before hard fork " << HF_VERSION_ALLOW_BULLETPROOFS);
      tvc.m_invalid_output = true;
      return false;
    }
  }

  return true;
}
//------------------------------------------------------------------
bool Blockchain::check_safex_tx(const transaction &tx, tx_verification_context &tvc)
{

  if (tx.version == 1) return true;

  std::vector<txin_to_script> input_commands_to_execute;
  safex::command_t input_command_to_check;

  bool only_donate_seen = true;
  bool only_stake_seen = true;

  for (auto txin: tx.vin)
  {
    if ((txin.type() == typeid(txin_to_script)))
    {
      const txin_to_script &txin_script = boost::get<txin_to_script>(txin);

      if(txin_script.command_type != safex::command_t::donate_network_fee)
        only_donate_seen = false;

      if(txin_script.command_type != safex::command_t::token_stake)
        only_stake_seen = false;

      input_commands_to_execute.push_back(txin_script);
      input_command_to_check = txin_script.command_type;
    }
  }

    // Per TX there can be :
    // * 1  command for all types
    // * >1 commands if they are all stake token or donate_network_fee
    if (!(input_commands_to_execute.size() == 1
            || (input_commands_to_execute.size() > 1 && (only_donate_seen || only_stake_seen)))) {
      tvc.m_safex_invalid_command = true;
      return false;
  }


  std::vector<tx_out_type> advanced_outputs;
  bool network_fee_out = false;
  bool purchase_out = false;
  bool feedback_token_out = false;

  for (auto txout: tx.vout)
  {
      if ((txout.target.type() == typeid(txout_to_script)))
      {
          auto txout_type = get_tx_out_type(txout.target);
          advanced_outputs.push_back(txout_type);
          if(txout_type == cryptonote::tx_out_type::out_safex_purchase)
              purchase_out = true;
          if(txout_type == cryptonote::tx_out_type::out_safex_feedback_token)
              feedback_token_out = true;
          if(txout_type == cryptonote::tx_out_type::out_network_fee)
              network_fee_out = true;
      }
  }

  // Per TX there can be :
  // * 1  advanced output for all types
  // * 3 outputs if tx is safex_purchase
  // * 0 outputs if tx is token_unstake
  if (!(advanced_outputs.size() == 1
        || (advanced_outputs.size() == 3 && network_fee_out && purchase_out && feedback_token_out)
        || (advanced_outputs.size() == 0 && input_command_to_check== safex::command_t::token_unstake))) {
      tvc.m_safex_invalid_command = true;
      return false;
  }

  //validate all command logic
  for (const txin_to_script& cmd: input_commands_to_execute)
      if (!safex::validate_safex_command(*m_db, cmd)) {
        tvc.m_safex_command_execution_failed = true;
        return false;
      }

  //check all commands tx restrictions
  if (!check_safex_tx_command(tx, input_command_to_check)){
      tvc.m_safex_invalid_input = true;
      return false;
  }

  return true;
}
//------------------------------------------------------------------
bool Blockchain::check_safex_tx_command(const transaction &tx, const safex::command_t &command_type){

    if (command_type == safex::command_t::token_stake)
    {
        /* Find amount of input staked tokens */
        uint64_t inputs_staked_token_amount = 0;
        for(const auto &vin: tx.vin)
            if ((vin.type() == typeid(txin_to_script))){
                const txin_to_script &txin_script = boost::get<txin_to_script>(vin);
                if(txin_script.command_type == safex::command_t::token_stake)
                    inputs_staked_token_amount += txin_script.token_amount;
            }

        /* Find amount of output staked tokens */
        uint64_t outputs_staked_token_amount = 0;
        for (const auto &vout: tx.vout)
            if (vout.target.type() == typeid(txout_to_script) && get_tx_out_type(vout.target) == cryptonote::tx_out_type::out_staked_token)
            {
                const txout_to_script &out = boost::get<txout_to_script>(vout.target);
                if (out.output_type == static_cast<uint8_t>(tx_out_type::out_staked_token))
                    outputs_staked_token_amount += vout.token_amount;
            }

        /* Check if minumum amount of tokens is staked */
        if (outputs_staked_token_amount < safex::get_minimum_token_stake_amount(m_nettype))
        {
            MERROR("Safex token stake amount too small, must be at least "<< cryptonote::print_money(safex::get_minimum_token_stake_amount(m_nettype)));
            return false;
        }
        /* Check if amount of staked tokens in the output is less or equal to the amount in the input*/
        if (inputs_staked_token_amount < outputs_staked_token_amount)
        {
            MERROR("Safex token stake output amount higher than input amount");
            return false;
        }
    }
    else if (command_type == safex::command_t::token_unstake)
    {

    }
    else if (command_type == safex::command_t::donate_network_fee)
    {
        /* Find cash amount on output that is donated */
        uint64_t outputs_donated_cash_amount = 0;
        for (const auto &vout: tx.vout)
        {
            if (vout.target.type() == typeid(txout_to_script) && get_tx_out_type(vout.target) == cryptonote::tx_out_type::out_network_fee)
            {
                const txout_to_script &out = boost::get<txout_to_script>(vout.target);
                if (out.output_type == static_cast<uint8_t>(tx_out_type::out_network_fee))
                    outputs_donated_cash_amount += vout.amount;
            }
        }

        uint64_t input_cash_amount = 0;
        for (const auto &txin: tx.vin)
        {
            input_cash_amount += get_tx_input_cash_amount(txin);
        }

        /* Check if donated cash amount matches */
        if (outputs_donated_cash_amount >= input_cash_amount || outputs_donated_cash_amount == 0)
        {
            MERROR("Invalid safex cash input amount");
            return false;
        }
    }
    else if (command_type == safex::command_t::create_account)
    {

        uint64_t total_locked_tokens = 0;
        bool create_account_seen = false;
        txin_to_script command;
        for(auto txin: tx.vin){
            if (txin.type() == typeid(txin_to_script))
            {
                const txin_to_script &stxin = boost::get<txin_to_script>(txin);
                if (stxin.command_type == safex::command_t::create_account)
                {
                    command = stxin;
                }
            }
        }
        std::unique_ptr<safex::create_account> cmd = safex::safex_command_serializer::parse_safex_command<safex::create_account>(command.script);

        for (const auto &vout: tx.vout)
        {
            if (vout.target.type() == typeid(txout_to_script) && get_tx_out_type(vout.target) == cryptonote::tx_out_type::out_safex_account)
            {
                if(create_account_seen)
                {
                    MERROR("Multiple Safex account creation outputs");
                    return false;
                }
                create_account_seen = true;

                const txout_to_script &out = boost::get<txout_to_script>(vout.target);
                safex::create_account_data account;
                const cryptonote::blobdata accblob(std::begin(out.data), std::end(out.data));
                cryptonote::parse_and_validate_from_blob(accblob, account);
                std::string account_username(std::begin(account.username), std::end(account.username));


                if(cmd->get_username() != account_username || cmd->get_account_key() != account.pkey || cmd->get_account_data() != account.account_data){
                    MERROR("Output data not matching input command data");
                    return false;
                }

            }
            if (vout.target.type() == typeid(txout_token_to_key) && get_tx_out_type(vout.target) == cryptonote::tx_out_type::out_token && vout.token_amount == SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_FEE)
            {
                total_locked_tokens += vout.token_amount;
            }

        }

        if(!create_account_seen){
            MERROR("Create account output not found");
            return false;
        }

        if(total_locked_tokens < SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_FEE){
            MERROR("Not enough tokens given as output. Needed: " + std::to_string(SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_FEE) + ", actual sent: "+std::to_string(total_locked_tokens) );
            return false;
        }

    }
    else if (command_type == safex::command_t::edit_account)
    {
        bool edit_account_seen = false;
        txin_to_script command;
        for(auto txin: tx.vin){
            if (txin.type() == typeid(txin_to_script))
            {
                const txin_to_script &stxin = boost::get<txin_to_script>(txin);
                if (stxin.command_type == safex::command_t::edit_account)
                {
                    command = stxin;
                }
            }
        }
        std::unique_ptr<safex::edit_account> cmd = safex::safex_command_serializer::parse_safex_command<safex::edit_account>(command.script);


        for (const auto &vout: tx.vout)
        {
            if (vout.target.type() == typeid(txout_to_script) && get_tx_out_type(vout.target) == cryptonote::tx_out_type::out_safex_account_update)
            {
                if(edit_account_seen)
                {
                    MERROR("Multiple Safex account edit outputs");
                    return false;
                }
                edit_account_seen = true;

                const txout_to_script &out = boost::get<txout_to_script>(vout.target);
                safex::edit_account_data account;
                const cryptonote::blobdata accblob(std::begin(out.data), std::end(out.data));
                cryptonote::parse_and_validate_from_blob(accblob, account);
                std::string account_username(std::begin(account.username), std::end(account.username));


                if(cmd->get_username() != account_username || cmd->get_new_account_data() != account.account_data){
                    MERROR("Output data not matching input command data");
                    return false;
                }

            }
        }

        if(!edit_account_seen){
            MERROR("Edit account output not found");
            return false;
        }
    }
    else if (command_type == safex::command_t::create_offer)
    {
        bool create_offer_seen = false;
        txin_to_script command;
        for(auto txin: tx.vin){
            if (txin.type() == typeid(txin_to_script))
            {
                const txin_to_script &stxin = boost::get<txin_to_script>(txin);
                if (stxin.command_type == safex::command_t::create_offer)
                {
                    command = stxin;
                }
            }
        }
        std::unique_ptr<safex::create_offer> cmd = safex::safex_command_serializer::parse_safex_command<safex::create_offer>(command.script);


        for (const auto &vout: tx.vout)
        {
            if (vout.target.type() == typeid(txout_to_script) && get_tx_out_type(vout.target) == cryptonote::tx_out_type::out_safex_offer)
            {
                if(create_offer_seen)
                {
                    MERROR("Multiple Safex offer create outputs");
                    return false;
                }
                create_offer_seen = true;

                const txout_to_script &out = boost::get<txout_to_script>(vout.target);
                safex::create_offer_data offer;
                const cryptonote::blobdata offerblob(std::begin(out.data), std::end(out.data));
                cryptonote::parse_and_validate_from_blob(offerblob, offer);

                if(cmd->get_offerid() != offer.offer_id || cmd->get_price_peg_id() != offer.price_peg_id || cmd->get_seller() != offer.seller
                    || cmd->get_title() != offer.title || cmd->get_price() != offer.price || cmd->get_min_sfx_price() != offer.min_sfx_price
                    || cmd->get_quantity() != offer.quantity || cmd->get_active() != offer.active || cmd->get_price_peg_used() != offer.price_peg_used
                    || cmd->get_description() != offer.description || cmd->get_seller_private_view_key() != offer.seller_private_view_key
                    || cmd->get_seller_address() != offer.seller_address){
                    MERROR("Output data not matching input command data");
                    return false;
                }

            }
        }

        if(!create_offer_seen){
            MERROR("Create offer output not found");
            return false;
        }
    }
    else if (command_type == safex::command_t::edit_offer)
    {
        bool edit_offer_seen = false;
        txin_to_script command;
        for(auto txin: tx.vin){
            if (txin.type() == typeid(txin_to_script))
            {
                const txin_to_script &stxin = boost::get<txin_to_script>(txin);
                if (stxin.command_type == safex::command_t::edit_offer)
                {
                    command = stxin;
                }
            }
        }
        std::unique_ptr<safex::edit_offer> cmd = safex::safex_command_serializer::parse_safex_command<safex::edit_offer>(command.script);

        for (const auto &vout: tx.vout)
        {
            if (vout.target.type() == typeid(txout_to_script) && get_tx_out_type(vout.target) == cryptonote::tx_out_type::out_safex_offer_update)
            {
                if(edit_offer_seen)
                {
                    MERROR("Multiple Safex offer edit outputs");
                    return false;
                }
                edit_offer_seen = true;

                const txout_to_script &out = boost::get<txout_to_script>(vout.target);
                safex::edit_offer_data offer;
                const cryptonote::blobdata offerblob(std::begin(out.data), std::end(out.data));
                cryptonote::parse_and_validate_from_blob(offerblob, offer);

                if(cmd->get_offerid() != offer.offer_id || cmd->get_price_peg_id() != offer.price_peg_id || cmd->get_seller() != offer.seller
                    || cmd->get_title() != offer.title || cmd->get_price() != offer.price || cmd->get_min_sfx_price() != offer.min_sfx_price
                    || cmd->get_quantity() != offer.quantity || cmd->get_active() != offer.active || cmd->get_price_peg_used() != offer.price_peg_used
                    || cmd->get_description() != offer.description){
                    MERROR("Output data not matching input command data");
                    return false;
                }
            }
        }
        if(!edit_offer_seen){
            MERROR("Edit offer output not found");
            return false;
        }
    }
    else if (command_type == safex::command_t::simple_purchase)
    {
        uint64_t network_fee = 0;
        uint64_t product_payment = 0;
        uint64_t total_payment = 0;
        crypto::secret_key secret_seller_view_key;
        crypto::public_key public_seller_spend_key;
        bool purchase_seen = false;
        txin_to_script command;
        for(auto txin: tx.vin){
            if (txin.type() == typeid(txin_to_script))
            {
                const txin_to_script &stxin = boost::get<txin_to_script>(txin);
                if (stxin.command_type == safex::command_t::simple_purchase)
                {
                    command = stxin;
                }
            }
        }
        std::unique_ptr<safex::simple_purchase> cmd = safex::safex_command_serializer::parse_safex_command<safex::simple_purchase>(command.script);


        if (tx.unlock_time > m_db->height())
        {
            MERROR("Purchase TX should not be locked");
            return false;
        }

        for (const auto &vout: tx.vout) {
            if (vout.target.type() == typeid(txout_to_script) && get_tx_out_type(vout.target) == cryptonote::tx_out_type::out_safex_purchase)
            {
                if(purchase_seen)
                {
                    MERROR("Multiple Safex purchase outputs");
                    return false;
                }
                purchase_seen = true;

                const txout_to_script &out = boost::get<txout_to_script>(vout.target);
                safex::safex_offer offer_to_purchase;
                safex::create_purchase_data purchase;
                const cryptonote::blobdata purchaseblob(std::begin(out.data), std::end(out.data));
                cryptonote::parse_and_validate_from_blob(purchaseblob, purchase);

                if(cmd->get_offerid() != purchase.offer_id
                    || cmd->get_price() != purchase.price
                    || cmd->get_quantity() != purchase.quantity
                    || cmd->get_shipping() != purchase.shipping){
                    MERROR("Output data not matching input command data");
                    return false;
                }

                total_payment = purchase.price;
                get_safex_offer(purchase.offer_id, offer_to_purchase);

                secret_seller_view_key = offer_to_purchase.seller_private_view_key;
                public_seller_spend_key = offer_to_purchase.seller_address.m_spend_public_key;

            } else if (vout.target.type() == typeid(txout_to_script) && get_tx_out_type(vout.target) == cryptonote::tx_out_type::out_safex_feedback_token)
            {

                const txout_to_script &out = boost::get<txout_to_script>(vout.target);
                safex::create_feedback_token_data feedback_token;
                const cryptonote::blobdata feedbacktokenblob(std::begin(out.data), std::end(out.data));
                cryptonote::parse_and_validate_from_blob(feedbacktokenblob, feedback_token);


                if(cmd->get_offerid() != feedback_token.offer_id){
                    MERROR("Output data not matching input command data");
                    return false;
                }
            }
        }

        std::vector<crypto::public_key> seller_outs= is_safex_purchase_right_address(secret_seller_view_key, public_seller_spend_key, tx);

        for (const auto &vout: tx.vout)
        {
            if (vout.target.type() == typeid(txout_to_script) && get_tx_out_type(vout.target) == cryptonote::tx_out_type::out_network_fee)
            {
                network_fee += vout.amount;
            }
            else if (vout.target.type() == typeid(txout_to_key) && get_tx_out_type(vout.target) == cryptonote::tx_out_type::out_cash)
            {
                const crypto::public_key &out = *boost::apply_visitor(destination_public_key_visitor(), vout.target);
                auto it = std::find(seller_outs.begin(),seller_outs.end(),out);
                if(it!=seller_outs.end())
                    product_payment += vout.amount;
            }
        }

        uint64_t calculated_network_fee = calculate_safex_network_fee(total_payment, m_nettype, command_type);
        //check network fee payment
        if (calculated_network_fee > network_fee)
        {
            MERROR("Not enough cash given for network fee");
            return false;
        }
        //check purchase cash payment
        if (total_payment - calculated_network_fee > product_payment)
        {
            MERROR("Not enough cash given for product payment");
            return false;
        }
    }
    else if (command_type == safex::command_t::create_feedback)
    {
        bool feedback_seen = false;
        txin_to_script command;
        for(auto txin: tx.vin){
            if (txin.type() == typeid(txin_to_script))
            {
                const txin_to_script &stxin = boost::get<txin_to_script>(txin);
                if (stxin.command_type == safex::command_t::create_feedback)
                {
                    command = stxin;
                }
            }
        }
        std::unique_ptr<safex::create_feedback> cmd = safex::safex_command_serializer::parse_safex_command<safex::create_feedback>(command.script);

        for (const auto &vout: tx.vout)
        {
            if (vout.target.type() == typeid(txout_to_script) && get_tx_out_type(vout.target) == cryptonote::tx_out_type::out_safex_feedback)
            {
                if(feedback_seen)
                {
                    MERROR("Multiple Safex feedback outputs");
                    return false;
                }
                feedback_seen = true;

                const txout_to_script &out = boost::get<txout_to_script>(vout.target);
                safex::create_feedback_data feedback;
                const cryptonote::blobdata feedbackblob(std::begin(out.data), std::end(out.data));
                cryptonote::parse_and_validate_from_blob(feedbackblob, feedback);

                if(cmd->get_offerid() != feedback.offer_id
                    || cmd->get_stars_given() != feedback.stars_given
                    || cmd->get_comment() != feedback.comment){
                    MERROR("Output data not matching input command data");
                    return false;
                }
            }
        }
        if(!feedback_seen){
            MERROR("Create feedback output not found");
            return false;
        }
    }
    else if (command_type == safex::command_t::create_price_peg)
    {
        bool create_price_peg_seen = false;
        txin_to_script command;
        for(auto txin: tx.vin){
            if (txin.type() == typeid(txin_to_script))
            {
                const txin_to_script &stxin = boost::get<txin_to_script>(txin);
                if (stxin.command_type == safex::command_t::create_price_peg)
                {
                    command = stxin;
                }
            }
        }
        std::unique_ptr<safex::create_price_peg> cmd = safex::safex_command_serializer::parse_safex_command<safex::create_price_peg>(command.script);

        for (const auto &vout: tx.vout)
        {
            if (vout.target.type() == typeid(txout_to_script) && get_tx_out_type(vout.target) == cryptonote::tx_out_type::out_safex_price_peg)
            {
                if(create_price_peg_seen)
                {
                    MERROR("Multiple Safex create price peg outputs");
                    return false;
                }
                create_price_peg_seen = true;

                const txout_to_script &out = boost::get<txout_to_script>(vout.target);
                safex::create_price_peg_data price_peg;
                const cryptonote::blobdata price_peg_blob(std::begin(out.data), std::end(out.data));
                cryptonote::parse_and_validate_from_blob(price_peg_blob, price_peg);

                if(cmd->get_title() != price_peg.title
                    || cmd->get_price_peg_id() != price_peg.price_peg_id
                    || cmd->get_creator() != price_peg.creator
                    || cmd->get_description() != price_peg.description
                    || cmd->get_currency() != price_peg.currency
                    || cmd->get_rate() != price_peg.rate){
                    MERROR("Output data not matching input command data");
                    return false;
                }
            }
        }
        if(!create_price_peg_seen){
            MERROR("Create price peg output not found");
            return false;
        }
    }
    else if (command_type == safex::command_t::update_price_peg)
    {
        bool update_price_peg_seen = false;
        txin_to_script command;
        for(auto txin: tx.vin){
            if (txin.type() == typeid(txin_to_script))
            {
                const txin_to_script &stxin = boost::get<txin_to_script>(txin);
                if (stxin.command_type == safex::command_t::update_price_peg)
                {
                    command = stxin;
                }
            }
        }
        std::unique_ptr<safex::update_price_peg> cmd = safex::safex_command_serializer::parse_safex_command<safex::update_price_peg>(command.script);

        for (const auto &vout: tx.vout)
        {
            if (vout.target.type() == typeid(txout_to_script) && get_tx_out_type(vout.target) == cryptonote::tx_out_type::out_safex_price_peg_update)
            {
                if(update_price_peg_seen)
                {
                    MERROR("Multiple Safex update price peg outputs");
                    return false;
                }
                update_price_peg_seen = true;

                const txout_to_script &out = boost::get<txout_to_script>(vout.target);
                safex::update_price_peg_data price_peg;
                const cryptonote::blobdata price_peg_blob(std::begin(out.data), std::end(out.data));
                cryptonote::parse_and_validate_from_blob(price_peg_blob, price_peg);

                if(cmd->get_price_peg_id() != price_peg.price_peg_id
                    || cmd->get_rate() != price_peg.rate){
                    MERROR("Output data not matching input command data");
                    return false;
                }

            }
        }
        if(!update_price_peg_seen){
            MERROR("Update price peg output not found");
            return false;
        }
    }
    else
    {
        MERROR("Unsupported safex command");
        return false;
    }

    return true;
}
//------------------------------------------------------------------
bool Blockchain::have_tx_keyimges_as_spent(const transaction &tx) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  for (const txin_v& in: tx.vin)
  {
    //CHECKED_GET_SPECIFIC_VARIANT(in, const txin_to_key, in_to_key, true);
    if (cryptonote::is_valid_transaction_input_type(in, tx.version)) {
      auto k_image_opt = boost::apply_visitor(key_image_visitor(), in);  //key image boost optional of currently checked input
      CHECK_AND_ASSERT_MES(k_image_opt, true, "key image is not available in input");
      const crypto::key_image &k_image = *k_image_opt;

      if (in.type() == typeid(txin_to_script))
      {
          const txin_to_script& in_to_script = boost::get<txin_to_script>(in);
          if(!safex::is_safex_key_image_verification_needed(in_to_script.command_type))
              continue;
      }

      if(have_tx_keyimg_as_spent(k_image))
        return true;
    } else {
      LOG_ERROR("wrong input variant type: " << in.type().name() << ", expected " << typeid(txin_to_key).name() << ", " << typeid(txin_token_to_key).name() << " or " << typeid(txin_token_migration).name());
      return true;
    }
  }
  return false;
}

bool Blockchain::expand_transaction_2(transaction &tx, const crypto::hash &tx_prefix_hash, const std::vector<std::vector<rct::ctkey>> &pubkeys)
{
  PERF_TIMER(expand_transaction_2);
  CHECK_AND_ASSERT_MES(tx.version >= 2, false, "Transaction version is not 2");

  rct::rctSig &rv = tx.rct_signatures;

  // message - hash of the transaction prefix
  rv.message = rct::hash2rct(tx_prefix_hash);

  // mixRing - full and simple store it in opposite ways
  if (rv.type == rct::RCTTypeFull || rv.type == rct::RCTTypeFullBulletproof)
  {
    CHECK_AND_ASSERT_MES(!pubkeys.empty() && !pubkeys[0].empty(), false, "empty pubkeys");
    rv.mixRing.resize(pubkeys[0].size());
    for (size_t m = 0; m < pubkeys[0].size(); ++m)
      rv.mixRing[m].clear();
    for (size_t n = 0; n < pubkeys.size(); ++n)
    {
      CHECK_AND_ASSERT_MES(pubkeys[n].size() <= pubkeys[0].size(), false, "More inputs that first ring");
      for (size_t m = 0; m < pubkeys[n].size(); ++m)
      {
        rv.mixRing[m].push_back(pubkeys[n][m]);
      }
    }
  }
  else if (rv.type == rct::RCTTypeSimple || rv.type == rct::RCTTypeSimpleBulletproof)
  {
    CHECK_AND_ASSERT_MES(!pubkeys.empty() && !pubkeys[0].empty(), false, "empty pubkeys");
    rv.mixRing.resize(pubkeys.size());
    for (size_t n = 0; n < pubkeys.size(); ++n)
    {
      rv.mixRing[n].clear();
      for (size_t m = 0; m < pubkeys[n].size(); ++m)
      {
        rv.mixRing[n].push_back(pubkeys[n][m]);
      }
    }
  }
  else
  {
    CHECK_AND_ASSERT_MES(false, false, "Unsupported rct tx type: " + boost::lexical_cast<std::string>(rv.type));
  }

  // II
  if (rv.type == rct::RCTTypeFull || rv.type == rct::RCTTypeFullBulletproof)
  {
    rv.p.MGs.resize(1);
    rv.p.MGs[0].II.resize(tx.vin.size());
    for (size_t n = 0; n < tx.vin.size(); ++n)
      rv.p.MGs[0].II[n] = rct::ki2rct(boost::get<txin_to_key>(tx.vin[n]).k_image);
  }
  else if (rv.type == rct::RCTTypeSimple || rv.type == rct::RCTTypeSimpleBulletproof)
  {
    CHECK_AND_ASSERT_MES(rv.p.MGs.size() == tx.vin.size(), false, "Bad MGs size");
    for (size_t n = 0; n < tx.vin.size(); ++n)
    {
      rv.p.MGs[n].II.resize(1);
      rv.p.MGs[n].II[0] = rct::ki2rct(boost::get<txin_to_key>(tx.vin[n]).k_image);
    }
  }
  else
  {
    CHECK_AND_ASSERT_MES(false, false, "Unsupported rct tx type: " + boost::lexical_cast<std::string>(rv.type));
  }

  // outPk was already done by handle_incoming_tx

  return true;
}
//------------------------------------------------------------------.


bool Blockchain::check_advanced_tx_input(const txin_to_script &txin, tx_verification_context &tvc)
{

  if (txin.command_type == safex::command_t::token_stake)
  {
    if (txin.amount > 0 || txin.token_amount == 0)
      return false;
  }
  else if (txin.command_type == safex::command_t::token_unstake)
  {
    if (txin.token_amount == 0)
      return false;
  }
  else if (txin.command_type == safex::command_t::donate_network_fee)
  {
    if (txin.amount == 0 || txin.token_amount > 0)
      return false;
  }
  else if (txin.command_type == safex::command_t::create_account)
  {
    if (txin.amount != 0 || txin.token_amount == 0) //create account input references (spends some of token outputs), in total SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_FEE
      return false;
  }
  else if (txin.command_type == safex::command_t::edit_account)
  {
    if (txin.amount > 0 || txin.token_amount > 0)
      return false;
  }
  else if (txin.command_type == safex::command_t::create_offer)
  {
      if (txin.amount > 0 || txin.token_amount > 0)
          return false;
  }
  else if (txin.command_type == safex::command_t::edit_offer)
  {
      if (txin.amount > 0 || txin.token_amount > 0)
          return false;
  }
  else if (txin.command_type == safex::command_t::simple_purchase)
  {
      if (txin.amount == 0 || txin.token_amount > 0)
          return false;
  }
  else if (txin.command_type == safex::command_t::create_feedback)
  {
      if (txin.amount > 0 || txin.token_amount > 0)
          return false;
  }
  else if (txin.command_type == safex::command_t::create_price_peg)
  {
    if (txin.amount > 0 || txin.token_amount > 0)
      return false;
  }
  else if (txin.command_type == safex::command_t::update_price_peg)
  {
    if (txin.amount > 0 || txin.token_amount > 0)
      return false;
  }
  else
  {
    MERROR_VER("Unknown input command type");
    return false;
  }

  return true;
}
//------------------------------------------------------------------.
// This function validates transaction inputs and their keys.
// FIXME: consider moving functionality specific to one input into
//        check_tx_input() rather than here, and use this function simply
//        to iterate the inputs as necessary (splitting the task
//        using threads, etc.)
bool Blockchain::check_tx_inputs(transaction& tx, tx_verification_context &tvc, uint64_t* pmax_used_block_height)
{
  PERF_TIMER(check_tx_inputs);
  LOG_PRINT_L3("Blockchain::" << __func__);
  if(pmax_used_block_height)
    *pmax_used_block_height = 0;

  crypto::hash tx_prefix_hash = get_transaction_prefix_hash(tx);

  const uint8_t hf_version = m_hardfork->get_current_version();

  // from hard fork HF_VERSION_MIN_MIXIN_REQUIRED, we require mixin at least 2 unless one output cannot mix with 2 others
  // if one output cannot mix with 2 others, we accept at most 1 output that can mix
  if (hf_version >= HF_VERSION_MIN_MIXIN_REQUIRED)
  {
    size_t n_unmixable = 0, n_mixable = 0;
    size_t mixin = std::numeric_limits<size_t>::max();
    const size_t min_mixin = hf_version >= HF_VERSION_MIN_MIXIN_6 ? 6 : hf_version >= HF_VERSION_MIN_MIXIN_4 ? 4 : 2;
    for (const auto& txin : tx.vin)
    {
      const tx_out_type output_type = boost::apply_visitor(tx_output_type_visitor(), txin);
      //todo ATANA add txin_token_to_key input here before min mixin starts to be used
      if (txin.type() == typeid(txin_to_key))
      {
        const txin_to_key& in_to_key = boost::get<txin_to_key>(txin);
        if (in_to_key.amount == 0)
        {
          // always consider rct inputs mixable. Even if there's not enough rct
          // inputs on the chain to mix with, this is going to be the case for
          // just a few blocks right after the fork at most
          ++n_mixable;
        }
        else
        {
          uint64_t n_outputs = m_db->get_num_outputs(in_to_key.amount, output_type);
          MDEBUG("output size " << print_money(in_to_key.amount) << ": " << n_outputs << " available");
          // n_outputs includes the output we're considering
          if (n_outputs <= min_mixin)
            ++n_unmixable;
          else
            ++n_mixable;
        }
        if (in_to_key.key_offsets.size() - 1 < mixin)
          mixin = in_to_key.key_offsets.size() - 1;
      }
    }

    if (mixin < min_mixin)
    {
      if (n_unmixable == 0)
      {
        MERROR_VER("Tx " << get_transaction_hash(tx) << " has too low ring size (" << (mixin + 1) << "), and no unmixable inputs");
        tvc.m_low_mixin = true;
        return false;
      }
      if (n_mixable > 1)
      {
        MERROR_VER("Tx " << get_transaction_hash(tx) << " has too low ring size (" << (mixin + 1) << "), and more than one mixable input with unmixable inputs");
        tvc.m_low_mixin = true;
        return false;
      }
    }
  }

  //sorted ins
  crypto::key_image last_key_image = AUTO_VAL_INIT(last_key_image);
  for (size_t n = 0; n < tx.vin.size(); ++n)
  {
    const txin_v &txin = tx.vin[n];
    if (is_valid_transaction_input_type(txin, tx.version))
    {
      const crypto::key_image &k_image = *boost::apply_visitor(key_image_visitor(), txin);
      if ((last_key_image != boost::value_initialized<crypto::key_image>()) && (memcmp(&k_image, &last_key_image, sizeof(last_key_image)) >= 0))
      {
        MERROR_VER("transaction has unsorted inputs");
        tvc.m_verifivation_failed = true;
        return false;
      }
      last_key_image = k_image;
    }
  }

  auto it = m_check_txin_table.find(tx_prefix_hash);
  if(it == m_check_txin_table.end())
  {
    m_check_txin_table.emplace(tx_prefix_hash, std::unordered_map<crypto::key_image, bool>());
    it = m_check_txin_table.find(tx_prefix_hash);
    assert(it != m_check_txin_table.end());
  }

  std::vector<std::vector<rct::ctkey>> pubkeys(tx.vin.size());
  std::vector<uint64_t> results;
  results.resize(tx.vin.size(), 0);

  tools::threadpool& tpool = tools::threadpool::getInstance();
  tools::threadpool::waiter waiter;
  int threads = tpool.get_max_concurrency();
  size_t sig_index = 0;

  uint64_t already_migrated_tokens = m_db->height() ? m_db->get_block_already_migrated_tokens(m_db->height() - 1) : 0;  //whole number of tokens, without decimals
  CHECK_AND_ASSERT_MES((already_migrated_tokens <= TOKEN_TOTAL_SUPPLY), false, "wrong number of migrated tokens, please purge and rebuild database");
  MDEBUG("already_migrated_tokens: " << already_migrated_tokens);
  uint64_t newly_migrated_tokens = 0;

  for (const auto& txin : tx.vin)
  {

    // make sure output being spent is of allow input type (txin_to_key,txin_token_to_key) ...
    CHECK_AND_ASSERT_MES(is_valid_transaction_input_type(txin, tx.version), false, "wrong type id in tx input at Blockchain::check_tx_inputs");

    // make sure that the input amount is a while number
    if ((txin.type() == typeid(txin_token_to_key)) || (txin.type() == typeid(txin_token_migration)))
    {
      auto token_amount = boost::apply_visitor(token_amount_visitor(), txin);
      CHECK_AND_ASSERT_MES(tools::is_whole_token_amount(*token_amount), false, "token amount not a whole number");

      //Check for maximum of migrated tokens
      if (txin.type() == typeid(txin_token_migration))
      {
        newly_migrated_tokens += *token_amount/SAFEX_TOKEN; //don't keep decimals
        //note: we are duing calculations with whole number of tokens. Database keeps whole number of tokens
        CHECK_AND_ASSERT_MES((already_migrated_tokens+newly_migrated_tokens <= TOKEN_TOTAL_SUPPLY), false, "max number of migrated tokens exceeded");
      }
    }

    /* Check advaced command intput validity */
    if ((txin.type() == typeid(txin_to_script)) && !check_advanced_tx_input(boost::get<txin_to_script>(txin), tvc))
    {
      MERROR_VER("Error in advanced input");
      tvc.m_safex_invalid_input = true;
      return false;
    }


    // make sure tx output has key offset(s) (is signed to be used)
    CHECK_AND_ASSERT_MES(is_valid_txin_key_offsets(txin), false, "empty in_to_key.key_offsets in transaction with id " << get_transaction_hash(tx));

    const crypto::key_image &k_image = *boost::apply_visitor(key_image_visitor(), txin);  //key image of currently checked input

    if (txin.type() == typeid(txin_to_script))
    {
        const txin_to_script& in_to_script = boost::get<txin_to_script>(txin);
        if(safex::is_safex_key_image_verification_needed(in_to_script.command_type)){
            if (have_tx_keyimg_as_spent(k_image))
            {
              MERROR_VER("Key image already spent in blockchain: " << epee::string_tools::pod_to_hex(k_image));
              tvc.m_double_spend = true;
              return false;
            }
        }
    } else {
        if (have_tx_keyimg_as_spent(k_image))
        {
            MERROR_VER("Key image already spent in blockchain: " << epee::string_tools::pod_to_hex(k_image));
            tvc.m_double_spend = true;
            return false;
        }
    }


    // basically, make sure number of inputs == number of signatures
    CHECK_AND_ASSERT_MES(sig_index < tx.signatures.size(), false, "wrong transaction: not signature entry for input with index= " << sig_index);


#if defined(CACHE_VIN_RESULTS)
    auto itk = it->second.find(k_image);
    if(itk != it->second.end())
    {
      if(!itk->second)
      {
        MERROR_VER("Failed ring signature for tx " << get_transaction_hash(tx) << "  vin key with k_image: " << k_image << "  sig_index: " << sig_index);
        return false;
      }

      // txin has been verified already, skip
      sig_index++;
      continue;
    }
#endif


    // make sure that output being spent matches up correctly with the
    // signature spending it.
    if (!check_tx_input(tx.version, txin, tx_prefix_hash, tx.signatures[sig_index], pubkeys[sig_index], pmax_used_block_height))
    {
      it->second[k_image] = false;
      MERROR_VER("Failed to check ring signature for tx " << get_transaction_hash(tx) << "  vin key with k_image: " << k_image << "  sig_index: " << sig_index);
      if (pmax_used_block_height) // a default value of NULL is used when called from Blockchain::handle_block_to_main_chain()
      {
        MERROR_VER("  *pmax_used_block_height: " << *pmax_used_block_height);
      }

      return false;
    }

      if (threads > 1)
      {
        // ND: Speedup
        // 1. Thread ring signature verification if possible.
        if (txin.type() == typeid(txin_token_migration)) {
          tpool.submit(&waiter, boost::bind(&Blockchain::check_migration_signature, this, std::cref(tx_prefix_hash), std::cref(tx.signatures[sig_index][0]), std::ref(results[sig_index])));
        }
        else if ((txin.type() == typeid(txin_to_script)) && (boost::get<txin_to_script>(txin).command_type == safex::command_t::edit_account)) {
          std::unique_ptr<safex::edit_account> cmd = safex::safex_command_serializer::parse_safex_command<safex::edit_account>(boost::get<txin_to_script>(txin).script);
          crypto::public_key account_pkey{};
          get_safex_account_public_key(cmd->get_username(), account_pkey);
          tpool.submit(&waiter, boost::bind(&Blockchain::check_safex_account_signature, this, std::cref(tx_prefix_hash), std::cref(account_pkey),
                                            std::cref(tx.signatures[sig_index][0]), std::ref(results[sig_index]))
          );
        }
        else if ((txin.type() == typeid(txin_to_script)) && (boost::get<txin_to_script>(txin).command_type == safex::command_t::create_offer)) {
            std::unique_ptr<safex::create_offer> cmd = safex::safex_command_serializer::parse_safex_command<safex::create_offer>(boost::get<txin_to_script>(txin).script);
            crypto::public_key account_pkey{};
            get_safex_account_public_key(cmd->get_seller(), account_pkey);
            tpool.submit(&waiter, boost::bind(&Blockchain::check_safex_account_signature, this, std::cref(tx_prefix_hash), std::cref(account_pkey),
                                              std::cref(tx.signatures[sig_index][0]), std::ref(results[sig_index]))
            );
        }
        else if ((txin.type() == typeid(txin_to_script)) && (boost::get<txin_to_script>(txin).command_type == safex::command_t::edit_offer)) {
            std::unique_ptr<safex::edit_offer> cmd = safex::safex_command_serializer::parse_safex_command<safex::edit_offer>(boost::get<txin_to_script>(txin).script);
            crypto::public_key account_pkey{};
            get_safex_account_public_key(cmd->get_seller(), account_pkey);
            tpool.submit(&waiter, boost::bind(&Blockchain::check_safex_account_signature, this, std::cref(tx_prefix_hash), std::cref(account_pkey),
                                              std::cref(tx.signatures[sig_index][0]), std::ref(results[sig_index]))
            );
        }
        else if ((txin.type() == typeid(txin_to_script)) && (boost::get<txin_to_script>(txin).command_type == safex::command_t::create_price_peg)) {
          std::unique_ptr<safex::create_price_peg> cmd = safex::safex_command_serializer::parse_safex_command<safex::create_price_peg>(boost::get<txin_to_script>(txin).script);
          crypto::public_key account_pkey{};
          get_safex_account_public_key(cmd->get_creator(), account_pkey);
          tpool.submit(&waiter, boost::bind(&Blockchain::check_safex_account_signature, this, std::cref(tx_prefix_hash), std::cref(account_pkey),
                                            std::cref(tx.signatures[sig_index][0]), std::ref(results[sig_index]))
          );
        }
        else if ((txin.type() == typeid(txin_to_script)) && (boost::get<txin_to_script>(txin).command_type == safex::command_t::update_price_peg)) {
          std::unique_ptr<safex::update_price_peg> cmd = safex::safex_command_serializer::parse_safex_command<safex::update_price_peg>(boost::get<txin_to_script>(txin).script);
          crypto::public_key account_pkey{};
          safex::safex_price_peg sfx_price_peg;
          get_safex_price_peg(cmd->get_price_peg_id(),sfx_price_peg);
          get_safex_account_public_key(sfx_price_peg.creator, account_pkey);
          tpool.submit(&waiter, boost::bind(&Blockchain::check_safex_account_signature, this, std::cref(tx_prefix_hash), std::cref(account_pkey),
                                            std::cref(tx.signatures[sig_index][0]), std::ref(results[sig_index]))
          );
        }
        else {
          tpool.submit(&waiter, boost::bind(&Blockchain::check_ring_signature, this, std::cref(tx_prefix_hash), std::cref(k_image), std::cref(pubkeys[sig_index]), std::cref(tx.signatures[sig_index]), std::ref(results[sig_index])));
        }
      }
      else
      {
        if (txin.type() == typeid(txin_token_migration)) {
          check_migration_signature(tx_prefix_hash, tx.signatures[sig_index][0], results[sig_index]);
        } else if ((txin.type() == typeid(txin_to_script)) && (boost::get<txin_to_script>(txin).command_type == safex::command_t::edit_account)) {
            std::unique_ptr<safex::edit_account> cmd = safex::safex_command_serializer::parse_safex_command<safex::edit_account>(boost::get<txin_to_script>(txin).script);
            crypto::public_key account_pkey{};
            get_safex_account_public_key(cmd->get_username(), account_pkey);
            check_safex_account_signature(tx_prefix_hash,account_pkey,tx.signatures[sig_index][0],results[sig_index]);
        }
        else if ((txin.type() == typeid(txin_to_script)) && (boost::get<txin_to_script>(txin).command_type == safex::command_t::create_offer)) {
            std::unique_ptr<safex::create_offer> cmd = safex::safex_command_serializer::parse_safex_command<safex::create_offer>(boost::get<txin_to_script>(txin).script);
            crypto::public_key account_pkey{};
            get_safex_account_public_key(cmd->get_seller(), account_pkey);
            check_safex_account_signature( tx_prefix_hash, account_pkey,tx.signatures[sig_index][0], results[sig_index]);
        }
        else if ((txin.type() == typeid(txin_to_script)) && (boost::get<txin_to_script>(txin).command_type == safex::command_t::edit_offer)) {
            std::unique_ptr<safex::edit_offer> cmd = safex::safex_command_serializer::parse_safex_command<safex::edit_offer>(boost::get<txin_to_script>(txin).script);
            crypto::public_key account_pkey{};
            get_safex_account_public_key(cmd->get_seller(), account_pkey);
            check_safex_account_signature( tx_prefix_hash, account_pkey,tx.signatures[sig_index][0], results[sig_index]);
        }
        else if ((txin.type() == typeid(txin_to_script)) && (boost::get<txin_to_script>(txin).command_type == safex::command_t::create_price_peg)) {
          std::unique_ptr<safex::create_price_peg> cmd = safex::safex_command_serializer::parse_safex_command<safex::create_price_peg>(boost::get<txin_to_script>(txin).script);
          crypto::public_key account_pkey{};
          get_safex_account_public_key(cmd->get_creator(), account_pkey);
          check_safex_account_signature( tx_prefix_hash, account_pkey,tx.signatures[sig_index][0], results[sig_index]);
        }
        else if ((txin.type() == typeid(txin_to_script)) && (boost::get<txin_to_script>(txin).command_type == safex::command_t::update_price_peg)) {
          std::unique_ptr<safex::update_price_peg> cmd = safex::safex_command_serializer::parse_safex_command<safex::update_price_peg>(boost::get<txin_to_script>(txin).script);
          crypto::public_key account_pkey{};
          safex::safex_price_peg sfx_price_peg;
          get_safex_price_peg(cmd->get_price_peg_id(),sfx_price_peg);
          get_safex_account_public_key(sfx_price_peg.creator, account_pkey);
          check_safex_account_signature( tx_prefix_hash, account_pkey,tx.signatures[sig_index][0], results[sig_index]);
        }
        else {
          check_ring_signature(tx_prefix_hash, k_image, pubkeys[sig_index], tx.signatures[sig_index], results[sig_index]);
        }

        if (!results[sig_index])
        {
          it->second[k_image] = false;
          MERROR_VER("Failed to check ring signature for tx " << get_transaction_hash(tx) << "  vin key with k_image: " << k_image << "  sig_index: " << sig_index);

          if (pmax_used_block_height)  // a default value of NULL is used when called from Blockchain::handle_block_to_main_chain()
          {
            MERROR_VER("*pmax_used_block_height: " << *pmax_used_block_height);
          }

          return false;
        }
        it->second[k_image] = true;
      }

    sig_index++;
  }

    if (threads > 1)
    {
       waiter.wait();
      // save results to table, passed or otherwise
      bool failed = false;
      for (size_t i = 0; i < tx.vin.size(); i++)
      {
        const auto k_image_opt = boost::apply_visitor(key_image_visitor(), tx.vin[i]);  //key image boost optional of currently checked input
        CHECK_AND_ASSERT_MES(k_image_opt, false, "key image is not available");

        it->second[*k_image_opt] = results[i];
        if(!failed && !results[i])
          failed = true;
      }

      if (failed)
      {
        MERROR_VER("Failed to check ring signatures!");
        return false;
      }
    }

  if(!check_safex_tx(tx,tvc)){
      tvc.m_verifivation_failed = true;
      tvc.m_safex_verification_failed = true;
      return false;
  }

  return true;
}

//------------------------------------------------------------------
void Blockchain::check_ring_signature(const crypto::hash &tx_prefix_hash, const crypto::key_image &key_image, const std::vector<rct::ctkey> &pubkeys, const std::vector<crypto::signature>& sig, uint64_t &result)
{
  std::vector<const crypto::public_key *> p_output_keys;
  for (auto &key : pubkeys)
  {
    // rct::key and crypto::public_key have the same structure, avoid object ctor/memcpy
    p_output_keys.push_back(&(const crypto::public_key&)key.dest);
  }

  result = crypto::check_ring_signature(tx_prefix_hash, key_image, p_output_keys, sig.data()) ? 1 : 0;
}
//------------------------------------------------------------------
void Blockchain::check_migration_signature(const crypto::hash &tx_prefix_hash,
                                           const crypto::signature &signature, uint64_t &result)
{
    crypto::public_key sender_public_key;
    get_migration_verification_public_key(m_nettype, sender_public_key);
    result = crypto::check_signature(tx_prefix_hash, sender_public_key, signature) ? 1 : 0;
}
//------------------------------------------------------------------
void Blockchain::check_safex_account_signature(const crypto::hash &tx_prefix_hash, const crypto::public_key &sender_safex_account_key,
                                           const crypto::signature &signature, uint64_t &result)
{

  result = safex::check_safex_account_signature(tx_prefix_hash, sender_safex_account_key, signature) ? 1 : 0;
}


//------------------------------------------------------------------
static uint64_t get_fee_quantization_mask()
{
  static uint64_t mask = 0;
  if (mask == 0)
  {
    mask = 1;
    for (size_t n = PER_KB_FEE_QUANTIZATION_DECIMALS; n < CRYPTONOTE_DISPLAY_DECIMAL_POINT; ++n)
      mask *= 10;
  }
  return mask;
}

//------------------------------------------------------------------
uint64_t Blockchain::get_dynamic_per_kb_fee(uint64_t block_reward, size_t median_block_size, uint8_t version)
{
  const uint64_t min_block_size = get_min_block_size(version);
  const uint64_t fee_per_kb_base = DYNAMIC_FEE_PER_KB_BASE_FEE;

  if (median_block_size < min_block_size)
    median_block_size = min_block_size;

  uint64_t unscaled_fee_per_kb = (fee_per_kb_base * min_block_size / median_block_size);
  uint64_t hi, lo = mul128(unscaled_fee_per_kb, block_reward, &hi);
  static_assert(DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD % 1000000 == 0, "DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD must be divisible by 1000000");
  static_assert(DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD / 1000000 <= std::numeric_limits<uint32_t>::max(), "DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD is too large");

  // divide in two steps, since the divisor must be 32 bits, but DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD isn't
  div128_32(hi, lo, DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD / 1000000, &hi, &lo);
  div128_32(hi, lo, 1000000, &hi, &lo);
  assert(hi == 0);

  // quantize fee up to 6 decimals
  uint64_t mask = get_fee_quantization_mask();
  uint64_t qlo = (lo + mask - 1) / mask * mask;
  MDEBUG("lo " << print_money(lo) << ", qlo " << print_money(qlo) << ", mask " << mask);

  return qlo;
}

//------------------------------------------------------------------
bool Blockchain::check_fee(size_t blob_size, uint64_t fee) const
{
  const uint8_t hf_version = get_current_hard_fork_version();

  uint64_t fee_per_kb;
  if (hf_version < HF_VERSION_DYNAMIC_FEE)
  {
    fee_per_kb = FEE_PER_KB;
  }
  else
  {
    uint64_t median = m_current_block_cumul_sz_limit / 2;
    uint64_t already_generated_coins = m_db->height() ? m_db->get_block_already_generated_coins(m_db->height() - 1) : 0;
    uint64_t base_reward;
    if (!get_block_reward(median, 1, already_generated_coins, base_reward, hf_version, m_db->height()))
      return false;
    fee_per_kb = get_dynamic_per_kb_fee(base_reward, median, hf_version);
  }
  MDEBUG("Using " << print_money(fee_per_kb) << "/kB fee");

  uint64_t needed_fee = blob_size / 1024;
  needed_fee += (blob_size % 1024) ? 1 : 0;
  needed_fee *= fee_per_kb;

  if (fee < needed_fee - needed_fee / 50) // keep a little 2% buffer on acceptance - no integer overflow
  {
    MERROR_VER("transaction fee is not enough: " << print_money(fee) << ", minimum fee: " << print_money(needed_fee));
    return false;
  }
  return true;
}

//------------------------------------------------------------------
uint64_t Blockchain::get_dynamic_per_kb_fee_estimate(uint64_t grace_blocks) const
{
  const uint8_t hf_version = get_current_hard_fork_version();

  if (hf_version < HF_VERSION_DYNAMIC_FEE)
    return FEE_PER_KB;

  if (grace_blocks >= CRYPTONOTE_REWARD_BLOCKS_WINDOW)
    grace_blocks = CRYPTONOTE_REWARD_BLOCKS_WINDOW - 1;

  const uint64_t min_block_size = get_min_block_size(hf_version);
  std::vector<size_t> sz;
  get_last_n_blocks_sizes(sz, CRYPTONOTE_REWARD_BLOCKS_WINDOW - grace_blocks);
  for (size_t i = 0; i < grace_blocks; ++i)
    sz.push_back(min_block_size);

  uint64_t median = epee::misc_utils::median(sz);
  if(median <= min_block_size)
    median = min_block_size;

  uint64_t already_generated_coins = m_db->height() ? m_db->get_block_already_generated_coins(m_db->height() - 1) : 0;
  uint64_t base_reward;
  if (!get_block_reward(median, 1, already_generated_coins, base_reward, hf_version, m_db->height()))
  {
    MERROR("Failed to determine block reward, using placeholder " << print_money(BLOCK_REWARD_OVERESTIMATE) << " as a high bound");
    base_reward = BLOCK_REWARD_OVERESTIMATE;
  }

  uint64_t fee = get_dynamic_per_kb_fee(base_reward, median, hf_version);
  MDEBUG("Estimating " << grace_blocks << "-block fee at " << print_money(fee) << "/kB");
  return fee;
}

//------------------------------------------------------------------
// This function checks to see if a tx is unlocked.  unlock_time is either
// a block index or a unix time.
bool Blockchain::is_tx_spendtime_unlocked(uint64_t unlock_time) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  if(unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER)
  {
    // ND: Instead of calling get_current_blockchain_height(), call m_db->height()
    //    directly as get_current_blockchain_height() locks the recursive mutex.
    if(m_db->height()-1 + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS >= unlock_time)
      return true;
    else
      return false;
  }
  else
  {
    //interpret as time
    uint64_t current_time = static_cast<uint64_t>(time(NULL));
    if (current_time + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS >= unlock_time)
      return true;
    else
      return false;
  }
  return false;
}
//------------------------------------------------------------------
// This function locates all outputs associated with a given input (mixins)
// and validates that they exist and are usable.  It also checks the ring
// signature for each input.
template <class T>
bool Blockchain::check_tx_input_generic(size_t tx_version, const T& txin, const crypto::hash& tx_prefix_hash, const std::vector<crypto::signature>& sig, std::vector<rct::ctkey> &output_keys, uint64_t* pmax_related_block_height)
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  // ND:
  // 1. Disable locking and make method private.
  //CRITICAL_REGION_LOCAL(m_blockchain_lock);

  struct outputs_visitor
  {
    std::vector<rct::ctkey >& m_output_keys;
    const Blockchain& m_bch;
    outputs_visitor(std::vector<rct::ctkey>& output_keys, const Blockchain& bch) :
      m_output_keys(output_keys), m_bch(bch)
    {
    }

  };

  output_keys.clear();

  uint64_t cash_amount = get_tx_input_cash_amount(txin);
  uint64_t token_amount = get_tx_input_token_amount(txin);

  // collect output keys
  Blockchain::outputs_generic_visitor vi(output_keys, *this);
  if (!scan_outputkeys_for_indexes(tx_version, txin, vi, tx_prefix_hash, pmax_related_block_height))
  {
    MERROR_VER("Failed to get output keys for tx with cash amount = " << print_money(cash_amount) << " token amount=" << token_amount << " and count indexes " << txin.key_offsets.size());
    return false;
  }

  if(txin.key_offsets.size() != output_keys.size())
  {
    MERROR_VER("Output keys for tx with amount= " << cash_amount<< " token amount=" << token_amount << " and count indexes " << txin.key_offsets.size() << " returned wrong keys count " << output_keys.size());
    return false;
  }

  CHECK_AND_ASSERT_MES(sig.size() == output_keys.size(), false, "internal error: tx signatures count=" << sig.size() << " mismatch with outputs keys count for inputs=" << output_keys.size());
    return true;
}

//------------------------------------------------------------------
// This function locates all outputs associated with a given input (mixins)
// and validates that they exist and are usable for advanced inputs
// with comamnds.  It also checks the ring
// signature for each input.
bool Blockchain::check_tx_input_script(size_t tx_version, const txin_to_script& txin, const crypto::hash& tx_prefix_hash,
                                       const std::vector<crypto::signature>& sig, std::vector<rct::ctkey> &output_keys,
                                       uint64_t* pmax_related_block_height)
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  //CRITICAL_REGION_LOCAL(m_blockchain_lock);

  output_keys.clear();


  uint64_t cash_amount = get_tx_input_cash_amount(txin);
  uint64_t token_amount = get_tx_input_token_amount(txin);

  // collect output keys
  Blockchain::outputs_generic_visitor vi(output_keys, *this);
  if (!scan_outputkeys_for_indexes(tx_version, txin, vi, tx_prefix_hash, pmax_related_block_height))
  {
    MERROR_VER("Failed to get advanced output keys for tx with cash amount = " << print_money(cash_amount) << " token amount=" << token_amount << " and count indexes " << txin.key_offsets.size());
    return false;
  }

  if(txin.key_offsets.size() != output_keys.size())
  {
    MERROR_VER("Advanced output keys for tx with amount= " << cash_amount<< " token amount=" << token_amount << " and count indexes " << txin.key_offsets.size() << " returned wrong keys count " << output_keys.size());
    return false;
  }

  CHECK_AND_ASSERT_MES(sig.size() == output_keys.size(), false, "internal error: tx signatures count=" << sig.size() << " mismatch with outputs keys count for inputs=" << output_keys.size());

  return true;
}
//------------------------------------------------------------------
// Call particular specialized function to check various input types
bool Blockchain::check_tx_input(size_t tx_version, const txin_v& txin, const crypto::hash& tx_prefix_hash, const std::vector<crypto::signature>& sig, std::vector<rct::ctkey> &output_keys, uint64_t* pmax_related_block_height)
{
  struct txin_visitor : public boost::static_visitor<bool> {
      size_t tx_version;
      const crypto::hash& tx_prefix_hash;
      const std::vector<crypto::signature>& sig;
      std::vector<rct::ctkey> &output_keys;
      uint64_t* pmax_related_block_height;
      Blockchain *const that;

      txin_visitor(Blockchain *const _that, size_t _tx_version, const crypto::hash& _tx_prefix_hash, const std::vector<crypto::signature>& _sig,
              std::vector<rct::ctkey> &_output_keys, uint64_t* _pmax_related_block_height):
            that(_that), tx_version(_tx_version), tx_prefix_hash(_tx_prefix_hash), sig(_sig), output_keys(_output_keys),
            pmax_related_block_height(_pmax_related_block_height)
      {}

      bool operator()(const cryptonote::txin_gen & _txin) const {return false;}
      bool operator()(const txin_to_key & _txin) const {return that->check_tx_input_generic<txin_to_key>(tx_version, _txin, tx_prefix_hash, sig, output_keys, pmax_related_block_height);}
      bool operator()(const txin_token_to_key & _txin) const {return that->check_tx_input_generic<txin_token_to_key>(tx_version, _txin, tx_prefix_hash, sig, output_keys, pmax_related_block_height);}
      bool operator()(const txin_token_migration & _txin) const {return that->check_tx_input_migration(tx_version, _txin, tx_prefix_hash, sig, output_keys, pmax_related_block_height);}
      bool operator()(const txin_to_script & _txin) const {return that->check_tx_input_script(tx_version, _txin, tx_prefix_hash, sig, output_keys, pmax_related_block_height);}
      bool operator()(const txin_to_scripthash & _txin) const {return false;}

  };

  return boost::apply_visitor(txin_visitor(this, tx_version, tx_prefix_hash, sig, output_keys, pmax_related_block_height), txin);
}
//------------------------------------------------------------------
// Verify migration transaction
bool Blockchain::check_tx_input_migration(size_t tx_version, const txin_token_migration &txin,
                                          const crypto::hash &tx_prefix_hash, const std::vector<crypto::signature> &sig,
                                          std::vector<rct::ctkey> &output_keys, uint64_t *pmax_related_block_height)
{
  //todo Igor If needed, expand. So far, so good
  CHECK_AND_ASSERT_MES(sig.size() == 1, false, "There should be only one signature");

  return true;
}
//------------------------------------------------------------------
//TODO: Is this intended to do something else?  Need to look into the todo there.
uint64_t Blockchain::get_adjusted_time() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  //TODO: add collecting median time
  return time(NULL);
}
//------------------------------------------------------------------
//TODO: revisit, has changed a bit on upstream
bool Blockchain::check_block_timestamp(std::vector<uint64_t>& timestamps, const block& b, uint64_t& median_ts) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  median_ts = epee::misc_utils::median(timestamps);
  size_t blockchain_timestamp_check_window;

  if (m_hardfork->get_current_version() < HF_VERSION_DIFFICULTY_V2) {
    blockchain_timestamp_check_window = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW;
  } else {
    blockchain_timestamp_check_window = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V2;
  }

  if(b.timestamp < median_ts)
  {
    MERROR_VER("Timestamp of block with id: " << get_block_hash(b) << ", " << b.timestamp << ", less than median of last " << blockchain_timestamp_check_window << " blocks, " << median_ts);
    return false;
  }

  return true;
}
//------------------------------------------------------------------
// This function grabs the timestamps from the most recent <n> blocks,
// where n = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW.  If there are not those many
// blocks in the blockchain, the timestap is assumed to be valid.  If there
// are, this function returns:
//   true if the block's timestamp is not less than the timestamp of the
//       median of the selected blocks
//   false otherwise
bool Blockchain::check_block_timestamp(const block& b, uint64_t& median_ts) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  uint64_t cryptonote_block_future_time_limit;
  size_t blockchain_timestamp_check_window;

  if (m_hardfork->get_current_version() < HF_VERSION_DIFFICULTY_V2) {
    cryptonote_block_future_time_limit = CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT;
    blockchain_timestamp_check_window = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW;
  } else {
    cryptonote_block_future_time_limit = CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V2;
    blockchain_timestamp_check_window = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V2;
  }

  if(b.timestamp > get_adjusted_time() + cryptonote_block_future_time_limit)
  {
    MERROR_VER("Timestamp of block with id: " << get_block_hash(b) << ", " << b.timestamp << ", bigger than adjusted time + " << (m_hardfork->get_current_version() < HF_VERSION_DIFFICULTY_V2 ? "2 hours" : "30 minutes"));
    return false;
  }

  // if not enough blocks, no proper median yet, return true
  if(m_db->height() < blockchain_timestamp_check_window)
  {
    return true;
  }

  std::vector<uint64_t> timestamps;
  auto h = m_db->height();

  // need most recent 60 blocks, get index of first of those
  size_t offset = h - blockchain_timestamp_check_window;
  for(;offset < h; ++offset)
  {
    timestamps.push_back(m_db->get_block_timestamp(offset));
  }

  return check_block_timestamp(timestamps, b, median_ts);
}
//------------------------------------------------------------------
void Blockchain::return_tx_to_pool(std::vector<transaction> &txs)
{
  uint8_t hf_version = get_current_hard_fork_version();
  for (auto& tx : txs)
  {
    cryptonote::tx_verification_context tvc = AUTO_VAL_INIT(tvc);
    // We assume that if they were in a block, the transactions are already
    // known to the network as a whole. However, if we had mined that block,
    // that might not be always true. Unlikely though, and always relaying
    // these again might cause a spike of traffic as many nodes re-relay
    // all the transactions in a popped block when a reorg happens.
    if (!m_tx_pool.add_tx(tx, tvc, true, true, false, hf_version))
    {
      MERROR("Failed to return taken transaction with hash: " << get_transaction_hash(tx) << " to tx_pool");
    }
  }
}
//------------------------------------------------------------------
bool Blockchain::flush_txes_from_pool(const std::list<crypto::hash> &txids)
{
  CRITICAL_REGION_LOCAL(m_tx_pool);

  bool res = true;
  for (const auto &txid: txids)
  {
    cryptonote::transaction tx;
    size_t blob_size;
    uint64_t fee;
    bool relayed, do_not_relay, double_spend_seen;
    MINFO("Removing txid " << txid << " from the pool");
    if(m_tx_pool.have_tx(txid) && !m_tx_pool.take_tx(txid, tx, blob_size, fee, relayed, do_not_relay, double_spend_seen))
    {
      MERROR("Failed to remove txid " << txid << " from the pool");
      res = false;
    }
  }
  return res;
}
//------------------------------------------------------------------
//      Needs to validate the block and acquire each transaction from the
//      transaction mem_pool, then pass the block and transactions to
//      m_db->add_block()
bool Blockchain::handle_block_to_main_chain(const block& bl, const crypto::hash& id, block_verification_context& bvc)
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  TIME_MEASURE_START(block_processing_time);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  TIME_MEASURE_START(t1);

  static bool seen_future_version = false;

  m_db->block_txn_start(true);
  if(bl.prev_id != get_tail_id())
  {
    MERROR_VER("Block with id: " << id << std::endl << "has wrong prev_id: " << bl.prev_id << std::endl << "expected: " << get_tail_id());
leave:
    m_db->block_txn_stop();
    return false;
  }

  // warn users if they're running an old version
  if (!seen_future_version && bl.major_version > m_hardfork->get_ideal_version())
  {
    seen_future_version = true;
    const el::Level level = el::Level::Warning;
    MCLOG_RED(level, "global", "**********************************************************************");
    MCLOG_RED(level, "global", "A block was seen on the network with a version higher than the last");
    MCLOG_RED(level, "global", "known one. This may be an old version of the daemon, and a software");
    MCLOG_RED(level, "global", "update may be required to sync further. Try running: update check");
    MCLOG_RED(level, "global", "**********************************************************************");
  }

  // this is a cheap test
  if (!m_hardfork->check(bl))
  {
    MERROR_VER("Block with id: " << id << std::endl << "has old version: " << (unsigned)bl.major_version << std::endl << "current: " << (unsigned)m_hardfork->get_current_version());
    bvc.m_verifivation_failed = true;
    goto leave;
  }

  TIME_MEASURE_FINISH(t1);
  TIME_MEASURE_START(t2);

  // make sure block timestamp is not less than the median timestamp
  // of a set number of the most recent blocks.
  if(!check_block_timestamp(bl))
  {
    MERROR_VER("Block with id: " << id << std::endl << "has invalid timestamp: " << bl.timestamp);
    bvc.m_verifivation_failed = true;
    goto leave;
  }

  TIME_MEASURE_FINISH(t2);
  //check proof of work
  TIME_MEASURE_START(target_calculating_time);

  // get the target difficulty for the block.
  // the calculation can overflow, among other failure cases,
  // so we need to check the return type.
  // FIXME: get_difficulty_for_next_block can also assert, look into
  // changing this to throwing exceptions instead so we can clean up.
  difficulty_type current_diffic = get_difficulty_for_next_block();
  CHECK_AND_ASSERT_MES(current_diffic, false, "!!!!!!!!! difficulty overhead !!!!!!!!!");

  TIME_MEASURE_FINISH(target_calculating_time);

  TIME_MEASURE_START(longhash_calculating_time);

  crypto::hash proof_of_work = null_hash;

  // Formerly the code below contained an if loop with the following condition
  // !m_checkpoints.is_in_checkpoint_zone(get_current_blockchain_height())
  // however, this caused the daemon to not bother checking PoW for blocks
  // before checkpoints, which is very dangerous behaviour. We moved the PoW
  // validation out of the next chunk of code to make sure that we correctly
  // check PoW now.
  // FIXME: height parameter is not used...should it be used or should it not
  // be a parameter?
  // validate proof_of_work versus difficulty target
  bool precomputed = false;
  bool fast_check = false;
#if defined(PER_BLOCK_CHECKPOINT)
  if (m_db->height() < m_blocks_hash_check.size())
  {
    auto hash = get_block_hash(bl);
    const auto &expected_hash = m_blocks_hash_check[m_db->height()];
    if (expected_hash != crypto::null_hash)
    {
      if (memcmp(&hash, &expected_hash, sizeof(hash)) != 0)
      {
        MERROR_VER("Block with id is INVALID: " << id);
        bvc.m_verifivation_failed = true;
        goto leave;
      }
      fast_check = true;
    }
    else
    {
      MCINFO("verify", "No pre-validated hash at height " << m_db->height() << ", verifying fully");
    }
  }
  else
#endif
  {
    auto it = m_blocks_longhash_table.find(id);
    if (it != m_blocks_longhash_table.end())
    {
      precomputed = true;
      proof_of_work = it->second;
    }
    else
      proof_of_work = get_block_longhash(this, bl, m_db->height(), 0);

    // validate proof_of_work versus difficulty target
    if(!check_hash(proof_of_work, current_diffic))
    {
      MERROR_VER("Block with id: " << id << std::endl << "does not have enough proof of work: " << proof_of_work << std::endl << "unexpected difficulty: " << current_diffic);
      bvc.m_verifivation_failed = true;
      goto leave;
    }
  }

  // If we're at a checkpoint, ensure that our hardcoded checkpoint hash
  // is correct.
  if(m_checkpoints.is_in_checkpoint_zone(get_current_blockchain_height()))
  {
    if(!m_checkpoints.check_block(get_current_blockchain_height(), id))
    {
      LOG_ERROR("CHECKPOINT VALIDATION FAILED");
      bvc.m_verifivation_failed = true;
      goto leave;
    }
  }

  TIME_MEASURE_FINISH(longhash_calculating_time);
  if (precomputed)
    longhash_calculating_time += m_fake_pow_calc_time;

  TIME_MEASURE_START(t3);

  // sanity check basic miner tx properties;
  if(!prevalidate_miner_transaction(bl, m_db->height()))
  {
    MERROR_VER("Block with id: " << id << " failed to pass prevalidation");
    bvc.m_verifivation_failed = true;
    goto leave;
  }

  size_t coinbase_blob_size = get_object_blobsize(bl.miner_tx);
  size_t cumulative_block_size = coinbase_blob_size;

  std::vector<transaction> txs;
  key_images_container keys;

  uint64_t fee_summary = 0;
  uint64_t t_checktx = 0;
  uint64_t t_exists = 0;
  uint64_t t_pool = 0;
  uint64_t t_dblspnd = 0;
  TIME_MEASURE_FINISH(t3);

// XXX old code adds miner tx here

  size_t tx_index = 0;
  // Iterate over the block's transaction hashes, grabbing each
  // from the tx_pool and validating them.  Each is then added
  // to txs.  Keys spent in each are added to <keys> by the double spend check.
  for (const crypto::hash& tx_id : bl.tx_hashes)
  {
    transaction tx;
    size_t blob_size = 0;
    uint64_t fee = 0;
    bool relayed = false, do_not_relay = false, double_spend_seen = false;
    TIME_MEASURE_START(aa);

// XXX old code does not check whether tx exists
    if (m_db->tx_exists(tx_id))
    {
      MERROR("Block with id: " << id << " attempting to add transaction already in blockchain with id: " << tx_id);
      bvc.m_verifivation_failed = true;
      return_tx_to_pool(txs);
      goto leave;
    }

    TIME_MEASURE_FINISH(aa);
    t_exists += aa;
    TIME_MEASURE_START(bb);

    // get transaction with hash <tx_id> from tx_pool
    if(!m_tx_pool.take_tx(tx_id, tx, blob_size, fee, relayed, do_not_relay, double_spend_seen))
    {
      MERROR_VER("Block with id: " << id  << " has at least one unknown transaction with id: " << tx_id);
      bvc.m_verifivation_failed = true;
      return_tx_to_pool(txs);
      goto leave;
    }

    TIME_MEASURE_FINISH(bb);
    t_pool += bb;
    // add the transaction to the temp list of transactions, so we can either
    // store the list of transactions all at once or return the ones we've
    // taken from the tx_pool back to it if the block fails verification.
    txs.push_back(tx);
    TIME_MEASURE_START(dd);

    // FIXME: the storage should not be responsible for validation.
    //        If it does any, it is merely a sanity check.
    //        Validation is the purview of the Blockchain class
    //        - TW
    //
    // ND: this is not needed, db->add_block() checks for duplicate k_images and fails accordingly.
    // if (!check_for_double_spend(tx, keys))
    // {
    //     LOG_PRINT_L0("Double spend detected in transaction (id: " << tx_id);
    //     bvc.m_verifivation_failed = true;
    //     break;
    // }

    TIME_MEASURE_FINISH(dd);
    t_dblspnd += dd;
    TIME_MEASURE_START(cc);

#if defined(PER_BLOCK_CHECKPOINT)
    if (!fast_check)
#endif
    {
      // validate that transaction inputs and the keys spending them are correct.
      tx_verification_context tvc;
      if(!check_tx_inputs(tx, tvc))
      {
        MERROR_VER("Block with id: " << id  << " has at least one transaction (id: " << tx_id << ") with wrong inputs.");

        //TODO: why is this done?  make sure that keeping invalid blocks makes sense.
        add_block_as_invalid(bl, id);
        MERROR_VER("Block with id " << id << " added as invalid because of wrong inputs in transactions");
        bvc.m_verifivation_failed = true;
        return_tx_to_pool(txs);
        goto leave;
      }
    }
#if defined(PER_BLOCK_CHECKPOINT)
    else
    {
      // ND: if fast_check is enabled for blocks, there is no need to check
      // the transaction inputs, but do some sanity checks anyway.
      if (tx_index >= m_blocks_txs_check.size() || memcmp(&m_blocks_txs_check[tx_index++], &tx_id, sizeof(tx_id)) != 0)
      {
        MERROR_VER("Block with id: " << id << " has at least one transaction (id: " << tx_id << ") with wrong inputs.");
        //TODO: why is this done?  make sure that keeping invalid blocks makes sense.
        add_block_as_invalid(bl, id);
        MERROR_VER("Block with id " << id << " added as invalid because of wrong inputs in transactions");
        bvc.m_verifivation_failed = true;
        return_tx_to_pool(txs);
        goto leave;
      }
    }
#endif
    TIME_MEASURE_FINISH(cc);
    t_checktx += cc;
    fee_summary += fee;
    cumulative_block_size += blob_size;
  }

  m_blocks_txs_check.clear();

  TIME_MEASURE_START(vmt);
  uint64_t base_reward = 0;
  uint64_t already_generated_coins = m_db->height() ? m_db->get_block_already_generated_coins(m_db->height() - 1) : 0;
  if(!validate_miner_transaction(bl, cumulative_block_size, fee_summary, base_reward, already_generated_coins, bvc.m_partial_block_reward, m_hardfork->get_current_version()))
  {
    MERROR_VER("Block with id: " << id << " has incorrect miner transaction");
    bvc.m_verifivation_failed = true;
    return_tx_to_pool(txs);
    goto leave;
  }

  TIME_MEASURE_FINISH(vmt);
  size_t block_size;
  difficulty_type cumulative_difficulty;

  // populate various metadata about the block to be stored alongside it.
  block_size = cumulative_block_size;
  cumulative_difficulty = current_diffic;
  // In the "tail" state when the minimum subsidy (implemented in get_block_reward) is in effect, the number of
  // coins will eventually exceed MONEY_SUPPLY and overflow a uint64. To prevent overflow, cap already_generated_coins
  // at MONEY_SUPPLY. already_generated_coins is only used to compute the block subsidy and MONEY_SUPPLY yields a
  // subsidy of 0 under the base formula and therefore the minimum subsidy >0 in the tail state.
  //todo ATANA calculate inflation into this formula
  already_generated_coins = base_reward < (MONEY_SUPPLY-already_generated_coins) ? already_generated_coins + base_reward : MONEY_SUPPLY;
  if(m_db->height())
    cumulative_difficulty += m_db->get_block_cumulative_difficulty(m_db->height() - 1);

  TIME_MEASURE_FINISH(block_processing_time);
  if(precomputed)
    block_processing_time += m_fake_pow_calc_time;

  m_db->block_txn_stop();
  TIME_MEASURE_START(addblock);
  uint64_t new_height = 0;

  if (!bvc.m_verifivation_failed)
  {
    try
    {
      uint64_t already_migrated_tokens = m_db->height() ? m_db->get_block_already_migrated_tokens(m_db->height() - 1) : 0; //whole number of tokens, without decimals
      already_migrated_tokens += count_new_migration_tokens(txs);
      new_height = m_db->add_block(bl, block_size, cumulative_difficulty, already_generated_coins, already_migrated_tokens, txs);
    }
    catch (const KEY_IMAGE_EXISTS& e)
    {
      LOG_ERROR("Error adding block with hash: " << id << " to blockchain, what = " << e.what());
      m_batch_success = false;
      bvc.m_verifivation_failed = true;
      return_tx_to_pool(txs);
      return false;
    }
    catch (const SAFEX_TX_CONFLICT& e)
    {
        LOG_ERROR("Error adding block with hash: " << id << " to blockchain, what = " << e.what());
        m_batch_success = false;
        bvc.m_verifivation_failed = true;
//        auto it = find_if(txs.begin(),txs.end(),[e](transaction& tx){ return tx.hash == e.tx_hash; });
//        txs.erase(it);
        return_tx_to_pool(txs);
        return false;
    }
    catch (const std::exception& e)
    {
      //TODO: figure out the best way to deal with this failure
      LOG_ERROR("Error adding block with hash: " << id << " to blockchain, what = " << e.what());
      m_batch_success = false;
      bvc.m_verifivation_failed = true;
      return_tx_to_pool(txs);
      return false;
    }
  }
  else
  {
    LOG_ERROR("Blocks that failed verification should not reach here");
  }

  TIME_MEASURE_FINISH(addblock);

  // do this after updating the hard fork state since the size limit may change due to fork
  update_next_cumulative_size_limit();

  MINFO("+++++ BLOCK SUCCESSFULLY ADDED" << std::endl << "id:\t" << id << std::endl << "PoW:\t" << proof_of_work << std::endl << "HEIGHT " << new_height-1 << ", difficulty:\t" << current_diffic << std::endl << "block reward: " << print_money(fee_summary + base_reward) << "(" << print_money(base_reward) << " + " << print_money(fee_summary) << "), coinbase_blob_size: " << coinbase_blob_size << ", cumulative size: " << cumulative_block_size << ", " << block_processing_time << "(" << target_calculating_time << "/" << longhash_calculating_time << ")ms");
  if(m_show_time_stats)
  {
    MINFO("Height: " << new_height << " blob: " << coinbase_blob_size << " cumm: "
        << cumulative_block_size << " p/t: " << block_processing_time << " ("
        << target_calculating_time << "/" << longhash_calculating_time << "/"
        << t1 << "/" << t2 << "/" << t3 << "/" << t_exists << "/" << t_pool
        << "/" << t_checktx << "/" << t_dblspnd << "/" << vmt << "/" << addblock << ")ms");
  }

  bvc.m_added_to_main_chain = true;
  ++m_sync_counter;

  // appears to be a NOP *and* is called elsewhere.  wat?
  m_tx_pool.on_blockchain_inc(new_height, id);

  return true;
}
//------------------------------------------------------------------
bool Blockchain::update_next_cumulative_size_limit()
{
  uint64_t full_reward_zone = get_min_block_size(get_current_hard_fork_version());

  LOG_PRINT_L3("Blockchain::" << __func__);
  std::vector<size_t> sz;
  get_last_n_blocks_sizes(sz, CRYPTONOTE_REWARD_BLOCKS_WINDOW);

  uint64_t median = epee::misc_utils::median(sz);
  m_current_block_cumul_sz_median = median;
  if(median <= full_reward_zone)
    median = full_reward_zone;

  m_current_block_cumul_sz_limit = median*2;
  return true;
}
//------------------------------------------------------------------
bool Blockchain::add_new_block(const block& bl_, block_verification_context& bvc)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  //copy block here to let modify block.target
  block bl = bl_;
  crypto::hash id = get_block_hash(bl);
  CRITICAL_REGION_LOCAL(m_tx_pool);//to avoid deadlock lets lock tx_pool for whole add/reorganize process
  CRITICAL_REGION_LOCAL1(m_blockchain_lock);
  m_db->block_txn_start(true);
  if(have_block(id))
  {
    LOG_PRINT_L3("block with id = " << id << " already exists");
    bvc.m_already_exists = true;
    m_db->block_txn_stop();
    m_blocks_txs_check.clear();
    return false;
  }

  //check that block refers to chain tail
  if(!(bl.prev_id == get_tail_id()))
  {
    //chain switching or wrong block
    bvc.m_added_to_main_chain = false;
    m_db->block_txn_stop();
    bool r = handle_alternative_block(bl, id, bvc);
    m_blocks_txs_check.clear();
    return r;
    //never relay alternative blocks
  }

  m_db->block_txn_stop();
  return handle_block_to_main_chain(bl, id, bvc);
}
//------------------------------------------------------------------
//TODO: Refactor, consider returning a failure height and letting
//      caller decide course of action.
void Blockchain::check_against_checkpoints(const checkpoints& points, bool enforce)
{
  const auto& pts = points.get_points();
  bool stop_batch;

  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  stop_batch = m_db->batch_start();
  for (const auto& pt : pts)
  {
    // if the checkpoint is for a block we don't have yet, move on
    if (pt.first >= m_db->height())
    {
      continue;
    }

    if (!points.check_block(pt.first, m_db->get_block_hash_from_height(pt.first)))
    {
      // if asked to enforce checkpoints, roll back to a couple of blocks before the checkpoint
      if (enforce)
      {
        LOG_ERROR("Local blockchain failed to pass a checkpoint, rolling back!");
        std::list<block> empty;
        rollback_blockchain_switching(empty, pt.first - 2);
      }
      else
      {
        LOG_ERROR("WARNING: local blockchain failed to pass a MoneroPulse checkpoint, and you could be on a fork. You should either sync up from scratch, OR download a fresh blockchain bootstrap, OR enable checkpoint enforcing with the --enforce-dns-checkpointing command-line option");
      }
    }
  }
  if (stop_batch)
    m_db->batch_stop();
}
//------------------------------------------------------------------
// returns false if any of the checkpoints loading returns false.
// That should happen only if a checkpoint is added that conflicts
// with an existing checkpoint.
bool Blockchain::update_checkpoints(const std::string& file_path, bool check_dns)
{
  if (!m_checkpoints.load_checkpoints_from_json(file_path))
  {
      return false;
  }

  // if we're checking both dns and json, load checkpoints from dns.
  // if we're not hard-enforcing dns checkpoints, handle accordingly
  if (m_enforce_dns_checkpoints && check_dns && !m_offline)
  {
    if (!m_checkpoints.load_checkpoints_from_dns())
    {
      return false;
    }
  }
  else if (check_dns && !m_offline)
  {
    checkpoints dns_points;
    dns_points.load_checkpoints_from_dns();
    if (m_checkpoints.check_for_conflicts(dns_points))
    {
      check_against_checkpoints(dns_points, false);
    }
    else
    {
      MERROR("One or more checkpoints fetched from DNS conflicted with existing checkpoints!");
    }
  }

  check_against_checkpoints(m_checkpoints, true);

  return true;
}
//------------------------------------------------------------------
void Blockchain::set_enforce_dns_checkpoints(bool enforce_checkpoints)
{
  m_enforce_dns_checkpoints = enforce_checkpoints;
}

//------------------------------------------------------------------
void Blockchain::block_longhash_worker(uint64_t height, const std::vector<block> &blocks, std::unordered_map<crypto::hash, crypto::hash> &map) const
{
  TIME_MEASURE_START(t);
  slow_hash_allocate_state();

  for (const auto & block : blocks)
  {
    if (m_cancel)
       break;
    crypto::hash id = get_block_hash(block);
    crypto::hash pow = get_block_longhash(this, block, height++, 0);
    map.emplace(id, pow);
  }

  slow_hash_free_state();
  TIME_MEASURE_FINISH(t);
}

//------------------------------------------------------------------
bool Blockchain::cleanup_handle_incoming_blocks(bool force_sync)
{
  bool success = false;

  MTRACE("Blockchain::" << __func__);
  CRITICAL_REGION_BEGIN(m_blockchain_lock);
  TIME_MEASURE_START(t1);

  try
  {
    if (m_batch_success)
        m_db->batch_stop();
    else
        m_db->batch_abort();
    success = true;
  }
  catch (const std::exception &e)
  {
    MERROR("Exception in cleanup_handle_incoming_blocks: " << e.what());
  }

  if (success && m_sync_counter > 0)
  {
    if (force_sync)
    {
      if(m_db_sync_mode != db_nosync)
        store_blockchain();
      m_sync_counter = 0;
    }
    else if (m_db_blocks_per_sync && m_sync_counter >= m_db_blocks_per_sync)
    {
      if(m_db_sync_mode == db_async)
      {
        m_sync_counter = 0;
        m_async_service.dispatch(boost::bind(&Blockchain::store_blockchain, this));
      }
      else if(m_db_sync_mode == db_sync)
      {
        store_blockchain();
      }
      else // db_nosync
      {
        // DO NOTHING, not required to call sync.
      }
    }
  }

  TIME_MEASURE_FINISH(t1);
  m_blocks_longhash_table.clear();
  m_scan_table.clear();
  m_scan_table_adv.clear();
  m_blocks_txs_check.clear();
  m_check_txin_table.clear();

  // when we're well clear of the precomputed hashes, free the memory
  if (!m_blocks_hash_check.empty() && m_db->height() > m_blocks_hash_check.size() + 4096)
  {
    MINFO("Dumping block hashes, we're now 4k past " << m_blocks_hash_check.size());
    m_blocks_hash_check.clear();
    m_blocks_hash_check.shrink_to_fit();
  }

  CRITICAL_REGION_END();
  m_tx_pool.unlock();

  return success;
}

//------------------------------------------------------------------
void Blockchain::output_scan_worker(const uint64_t amount, const tx_out_type output_type, const std::vector<uint64_t> &offsets, std::vector<output_data_t> &outputs) const
{
  try
  {
    m_db->get_amount_output_key(amount, offsets, outputs, output_type, true);
  }
  catch (const std::exception& e)
  {
    MERROR_VER("EXCEPTION: " << e.what());
  }
  catch (...)
  {

  }
}
//------------------------------------------------------------------
void Blockchain::output_advanced_scan_worker(const tx_out_type output_type, const std::vector<uint64_t> &output_ids, std::vector<output_advanced_data_t> &outputs) const
{
  try
  {
    m_db->get_advanced_output_key(output_ids, outputs, output_type, true);
  }
  catch (const std::exception& e)
  {
    MERROR_VER("EXCEPTION: " << e.what());
  }
  catch (...)
  {

  }
}

uint64_t Blockchain::prevalidate_block_hashes(uint64_t height, const std::list<crypto::hash> &hashes)
{
  // new: . . . . . X X X X X . . . . . .
  // pre: A A A A B B B B C C C C D D D D

  // easy case: height >= hashes
  if (height >= m_blocks_hash_of_hashes.size() * HASH_OF_HASHES_STEP)
    return hashes.size();

  // if we're getting old blocks, we might have jettisoned the hashes already
  if (m_blocks_hash_check.empty())
    return hashes.size();

  // find hashes encompassing those block
  size_t first_index = height / HASH_OF_HASHES_STEP;
  size_t last_index = (height + hashes.size() - 1) / HASH_OF_HASHES_STEP;
  MDEBUG("Blocks " << height << " - " << (height + hashes.size() - 1) << " start at " << first_index << " and end at " << last_index);

  // case of not enough to calculate even a single hash
  if (first_index == last_index && hashes.size() < HASH_OF_HASHES_STEP && (height + hashes.size()) % HASH_OF_HASHES_STEP)
    return hashes.size();

  // build hashes vector to hash hashes together
  std::vector<crypto::hash> data;
  data.reserve(hashes.size() + HASH_OF_HASHES_STEP - 1); // may be a bit too much

  // we expect height to be either equal or a bit below db height
  bool disconnected = (height > m_db->height());
  size_t pop;
  if (disconnected && height % HASH_OF_HASHES_STEP)
  {
    ++first_index;
    pop = HASH_OF_HASHES_STEP - height % HASH_OF_HASHES_STEP;
  }
  else
  {
    // we might need some already in the chain for the first part of the first hash
    for (uint64_t h = first_index * HASH_OF_HASHES_STEP; h < height; ++h)
    {
      data.push_back(m_db->get_block_hash_from_height(h));
    }
    pop = 0;
  }

  // push the data to check
  for (const auto &h: hashes)
  {
    if (pop)
      --pop;
    else
      data.push_back(h);
  }

  // hash and check
  uint64_t usable = first_index * HASH_OF_HASHES_STEP - height; // may start negative, but unsigned under/overflow is not UB
  for (size_t n = first_index; n <= last_index; ++n)
  {
    if (n < m_blocks_hash_of_hashes.size())
    {
      // if the last index isn't fully filled, we can't tell if valid
      if (data.size() < (n - first_index) * HASH_OF_HASHES_STEP + HASH_OF_HASHES_STEP)
        break;

      crypto::hash hash;
      cn_fast_hash(data.data() + (n - first_index) * HASH_OF_HASHES_STEP, HASH_OF_HASHES_STEP * sizeof(crypto::hash), hash);
      bool valid = hash == m_blocks_hash_of_hashes[n];

      // add to the known hashes array
      if (!valid)
      {
        MDEBUG("invalid hash for blocks " << n * HASH_OF_HASHES_STEP << " - " << (n * HASH_OF_HASHES_STEP + HASH_OF_HASHES_STEP - 1));
        break;
      }

      size_t end = n * HASH_OF_HASHES_STEP + HASH_OF_HASHES_STEP;
      for (size_t i = n * HASH_OF_HASHES_STEP; i < end; ++i)
      {
        CHECK_AND_ASSERT_MES(m_blocks_hash_check[i] == crypto::null_hash || m_blocks_hash_check[i] == data[i - first_index * HASH_OF_HASHES_STEP],
            0, "Consistency failure in m_blocks_hash_check construction");
        m_blocks_hash_check[i] = data[i - first_index * HASH_OF_HASHES_STEP];
      }
      usable += HASH_OF_HASHES_STEP;
    }
    else
    {
      // if after the end of the precomputed blocks, accept anything
      usable += HASH_OF_HASHES_STEP;
      if (usable > hashes.size())
        usable = hashes.size();
    }
  }
  MDEBUG("usable: " << usable << " / " << hashes.size());
  CHECK_AND_ASSERT_MES(usable < std::numeric_limits<uint64_t>::max() / 2, 0, "usable is negative");
  return usable;
}

//------------------------------------------------------------------
// ND: Speedups:
// 1. Thread long_hash computations if possible (m_max_prepare_blocks_threads = nthreads, default = 4)
// 2. Group all amounts (from txs) and related absolute offsets and form a table of tx_prefix_hash
//    vs [k_image, output_keys] (m_scan_table). This is faster because it takes advantage of bulk queries
//    and is threaded if possible. The table (m_scan_table) will be used later when querying output
//    keys.
bool Blockchain::prepare_handle_incoming_blocks(const std::list<block_complete_entry> &blocks_entry)
{
  MTRACE("Blockchain::" << __func__);
  TIME_MEASURE_START(prepare);
  bool stop_batch;
  uint64_t bytes = 0;

  // Order of locking must be:
  //  m_incoming_tx_lock (optional)
  //  m_tx_pool lock
  //  blockchain lock
  //
  //  Something which takes the blockchain lock may never take the txpool lock
  //  if it has not provably taken the txpool lock earlier
  //
  //  The txpool lock is now taken in prepare_handle_incoming_blocks
  //  and released in cleanup_handle_incoming_blocks. This avoids issues
  //  when something uses the pool, which now uses the blockchain and
  //  needs a batch, since a batch could otherwise be active while the
  //  txpool and blockchain locks were not held

  m_tx_pool.lock();
  CRITICAL_REGION_LOCAL1(m_blockchain_lock);

  if(blocks_entry.size() == 0)
    return false;

  for (const auto &entry : blocks_entry)
  {
    bytes += entry.block.size();
    for (const auto &tx_blob : entry.txs)
    {
      bytes += tx_blob.size();
    }
  }
  while (!(stop_batch = m_db->batch_start(blocks_entry.size(), bytes))) {
    m_blockchain_lock.unlock();
    m_tx_pool.unlock();
    epee::misc_utils::sleep_no_w(1000);
    m_tx_pool.lock();
    m_blockchain_lock.lock();
  }
  m_batch_success = true;

  if ((m_db->height() + blocks_entry.size()) < m_blocks_hash_check.size())
    return true;

  bool blocks_exist = false;
  tools::threadpool& tpool = tools::threadpool::getInstance();
  unsigned int threads = tpool.get_max_concurrency();

  if (blocks_entry.size() > 1 && threads > 1 && m_max_prepare_blocks_threads > 1)
  {
    // limit threads, default limit = 4
    if(threads > m_max_prepare_blocks_threads)
      threads = m_max_prepare_blocks_threads;

    uint64_t height = m_db->height();
    unsigned int batches = blocks_entry.size() / threads;
    unsigned int extra = blocks_entry.size() % threads;
    MDEBUG("block_batches: " << batches);
    std::vector<std::unordered_map<crypto::hash, crypto::hash>> maps(threads);
    std::vector < std::vector < block >> blocks(threads);
    auto it = blocks_entry.begin();

    for (unsigned int i = 0; i < threads; i++)
    {
      for (unsigned int j = 0; j < batches; j++)
      {
        block block;

        if (!parse_and_validate_block_from_blob(it->block, block))
        {
          std::advance(it, 1);
          continue;
        }

        // check first block and skip all blocks if its not chained properly
        if (i == 0 && j == 0)
        {
          crypto::hash tophash = m_db->top_block_hash();
          if (block.prev_id != tophash)
          {
            MDEBUG("Skipping prepare blocks. New blocks don't belong to chain.");
            return true;
          }
        }
        if (have_block(get_block_hash(block)))
        {
          blocks_exist = true;
          break;
        }

        blocks[i].push_back(block);
        std::advance(it, 1);
      }

      if (blocks_exist)
        break;

      if (i < extra)
      {
        block block;

        if (!parse_and_validate_block_from_blob(it->block, block))
        {
          std::advance(it, 1);
          continue;
        }

        if (have_block(get_block_hash(block)))
        {
          blocks_exist = true;
          break;
        }

        blocks[i].push_back(block);
        std::advance(it, 1);
      }
    }

    if (!blocks_exist)
    {
      m_blocks_longhash_table.clear();
      uint64_t thread_height = height;
      tools::threadpool::waiter waiter;
      m_prepare_height = height;
      m_prepare_nblocks = blocks_entry.size();
      m_prepare_blocks = &blocks;
      for (uint64_t i = 0; i < threads; i++)
      {
        tpool.submit(&waiter, boost::bind(&Blockchain::block_longhash_worker, this, thread_height, std::cref(blocks[i]), std::ref(maps[i])));
        thread_height += blocks[i].size();
      }

      waiter.wait();
      m_prepare_height = 0;

      if (m_cancel)
         return false;

      for (const auto & map : maps)
      {
        m_blocks_longhash_table.insert(map.begin(), map.end());
      }
    }
  }

  if (m_cancel)
    return false;

  if (blocks_exist)
  {
    MDEBUG("Skipping prepare blocks. Blocks exist.");
    return true;
  }

  m_fake_scan_time = 0;
  m_fake_pow_calc_time = 0;

  m_scan_table.clear();
  m_scan_table_adv.clear();
  m_check_txin_table.clear();

  TIME_MEASURE_FINISH(prepare);
  m_fake_pow_calc_time = prepare / blocks_entry.size();

  if (blocks_entry.size() > 1 && threads > 1 && m_show_time_stats)
    MDEBUG("Prepare blocks took: " << prepare << " ms");

  TIME_MEASURE_START(scantable);

  // [input] stores all unique amounts found
  std::vector <std::pair<tx_out_type, uint64_t>> amounts;
  // [input] stores all absolute_offsets for each amount
  std::map<std::pair<tx_out_type, uint64_t>, std::vector<uint64_t>> offset_map;
  // [output] stores all output_data_t for each absolute_offset
  std::map<std::pair<tx_out_type, uint64_t>, std::vector<output_data_t>> tx_map;

  std::set<tx_out_type> types;

  // [input] store all found  advanced output types and vector of their output ids
  std::map<tx_out_type, std::vector<uint64_t>> advanced_output_ids_map;
  // [output] stores all output_advanced_data_t for each tx_out_type
  std::map<tx_out_type, std::vector<output_advanced_data_t>> tx_advanced_map;

#define SCAN_TABLE_QUIT(m) \
        do { \
            MERROR_VER(m) ;\
            m_scan_table.clear(); \
            m_scan_table_adv.clear(); \
            return false; \
        } while(0); \

  // generate sorted tables for all amounts and absolute offsets
  for (const auto &entry : blocks_entry)
  {
    if (m_cancel)
      return false;

    for (const auto &tx_blob : entry.txs)
    {
      crypto::hash tx_hash = null_hash;
      crypto::hash tx_prefix_hash = null_hash;
      transaction tx;

      if (!parse_and_validate_tx_from_blob(tx_blob, tx, tx_hash, tx_prefix_hash))
        SCAN_TABLE_QUIT("Could not parse tx from incoming blocks.");

      auto its = m_scan_table.find(tx_prefix_hash);
      if (its != m_scan_table.end())
        SCAN_TABLE_QUIT("Duplicate tx found from incoming blocks.");

      m_scan_table.emplace(tx_prefix_hash, std::unordered_map<crypto::key_image, std::vector<output_data_t>>());
      its = m_scan_table.find(tx_prefix_hash);
      assert(its != m_scan_table.end());

      auto its_advanced = m_scan_table_adv.find(tx_prefix_hash);
      if (its_advanced != m_scan_table_adv.end())
        SCAN_TABLE_QUIT("Duplicate advanced tx found from incoming blocks.");

      m_scan_table_adv.emplace(tx_prefix_hash, std::unordered_map<crypto::key_image, std::vector<output_advanced_data_t>>());
      its_advanced = m_scan_table_adv.find(tx_prefix_hash);
      assert(its_advanced != m_scan_table_adv.end());


      // get all amounts from tx.vin(s)
      for (const auto &txin : tx.vin)
      {
        const crypto::key_image &k_image = *boost::apply_visitor(key_image_visitor(), txin);

        // check for duplicate
        auto it = its->second.find(k_image);
        if (it != its->second.end())
          SCAN_TABLE_QUIT("Duplicate key_image found from incoming blocks.");

        auto it_advanced = its_advanced->second.find(k_image);
        if (it_advanced != its_advanced->second.end())
          SCAN_TABLE_QUIT("Duplicate advanced key_image found from incoming blocks.");

        const tx_out_type output_type = boost::apply_visitor(tx_output_type_visitor(), txin);
        if (output_type == tx_out_type::out_cash || output_type == tx_out_type::out_token)
        {
          const uint64_t amount = *boost::apply_visitor(amount_visitor(), txin);
          amounts.push_back(std::pair<tx_out_type, uint64_t>{output_type, amount});
        }
        else
        {
          types.insert(output_type);

        }
      }

      // sort and remove duplicate amounts from amounts list
      std::sort(amounts.begin(), amounts.end());
      auto last = std::unique(amounts.begin(), amounts.end());
      amounts.erase(last, amounts.end());

      // add amount to the offset_map and tx_map
      for (const std::pair<tx_out_type, uint64_t> &amount : amounts)
      {
        if (offset_map.find(amount) == offset_map.end())
          offset_map.emplace(amount, std::vector<uint64_t>());

        if (tx_map.find(amount) == tx_map.end())
          tx_map.emplace(amount, std::vector<output_data_t>());
      }

      for(auto type: types)
      {
        if(tx_advanced_map.find(type)== tx_advanced_map.end())
          tx_advanced_map.emplace(type, std::vector<output_advanced_data_t>());
      }

      // add new absolute_offsets to offset_map
      for (const auto &txin : tx.vin)
      {
        const tx_out_type output_presumed_type = boost::apply_visitor(tx_output_type_visitor(), txin);

        if ((txin.type() == typeid(const txin_to_key)) || (txin.type() == typeid(const txin_token_to_key))
            || (txin.type() == typeid(const txin_to_script) && (output_presumed_type == tx_out_type::out_cash || output_presumed_type == tx_out_type::out_token))
                )
        {

          // no need to check for duplicate here.
          const std::vector<uint64_t> &key_offsets = *boost::apply_visitor(key_offset_visitor(), txin);
          const uint64_t amount = *boost::apply_visitor(amount_visitor(), txin);


          auto absolute_offsets = relative_output_offsets_to_absolute(key_offsets);
          for (const auto &offset : absolute_offsets)
            offset_map[std::pair<tx_out_type, uint64_t>{output_presumed_type, amount}].push_back(offset);
        }
        else if (txin.type() == typeid(const txin_to_script))
        {
          const std::vector<uint64_t> &output_ids = *boost::apply_visitor(key_offset_visitor(), txin);

          for (uint64_t output_id: output_ids)
            advanced_output_ids_map[output_presumed_type].push_back(output_id);

        }
      }
    }
  }

  // sort and remove duplicate absolute_offsets in offset_map
  for (auto &offsets : offset_map)
  {
    std::sort(offsets.second.begin(), offsets.second.end());
    auto last = std::unique(offsets.second.begin(), offsets.second.end());
    offsets.second.erase(last, offsets.second.end());
  }

  threads = tpool.get_max_concurrency();
  if (!m_db->can_thread_bulk_indices())
    threads = 1;

  if (threads > 1)
  {
    tools::threadpool::waiter waiter;

    for (size_t i = 0; i < amounts.size(); i++)
    {
      std::pair<tx_out_type, uint64_t> amount = amounts[i];
      if (amount.first == tx_out_type::out_bitcoin_migration) {
        //todo ATANA check output validity here, verify signature
      }
      else
      {
        tpool.submit(&waiter, boost::bind(&Blockchain::output_scan_worker, this, amount.second, amount.first, std::cref(offset_map[amount]), std::ref(tx_map[amount])));
      }
    }

    for (auto &adv_out : advanced_output_ids_map)
    {
        tpool.submit(&waiter, boost::bind(&Blockchain::output_advanced_scan_worker, this, adv_out.first, std::cref(adv_out.second), std::ref(tx_advanced_map[adv_out.first])));
    }
    waiter.wait();
  }
  else
  {
    for (size_t i = 0; i < amounts.size(); i++)
    {
      std::pair<tx_out_type, uint64_t> amount =  amounts[i];
      if (amount.first == tx_out_type::out_bitcoin_migration)
      {
        //todo ATANA check bitcoin output validity here, verify signature
      }
      else
      {
        output_scan_worker(amount.second /*value*/, amount.first /*cash or token*/, offset_map[amount], tx_map[amount]);
      }
    }

    for (auto &adv_out : advanced_output_ids_map)
    {
      output_advanced_scan_worker(adv_out.first, adv_out.second, tx_advanced_map[adv_out.first]);
    }
  }

  int total_txs = 0;

  // now generate a table for each tx_prefix and k_image hashes
  for (const auto &entry : blocks_entry)
  {
    if (m_cancel)
      return false;

    for (const auto &tx_blob : entry.txs)
    {
      crypto::hash tx_hash = null_hash;
      crypto::hash tx_prefix_hash = null_hash;
      transaction tx;

      if (!parse_and_validate_tx_from_blob(tx_blob, tx, tx_hash, tx_prefix_hash))
        SCAN_TABLE_QUIT("Could not parse tx from incoming blocks.");

      ++total_txs;
      auto its = m_scan_table.find(tx_prefix_hash);
      if (its == m_scan_table.end())
        SCAN_TABLE_QUIT("Tx not found on scan table from incoming blocks.");

      auto its_advanced = m_scan_table_adv.find(tx_prefix_hash);
      if (its_advanced == m_scan_table_adv.end())
        SCAN_TABLE_QUIT("Tx not found on advanced scan table from incoming blocks.");

      for (const auto &txin : tx.vin)
      {
        const tx_out_type output_presumed_type = boost::apply_visitor(tx_output_type_visitor(), txin);

        if ((txin.type() == typeid(const txin_to_key)) || (txin.type() == typeid(const txin_token_to_key))
            || (txin.type() == typeid(const txin_to_script) && (output_presumed_type == tx_out_type::out_cash || output_presumed_type == tx_out_type::out_token))
            )
        {
          const std::vector<uint64_t> &key_offsets = *boost::apply_visitor(key_offset_visitor(), txin);
          const uint64_t output_value_amount = *boost::apply_visitor(amount_visitor(), txin);

          auto needed_offsets = relative_output_offsets_to_absolute(key_offsets);

          std::vector<output_data_t> outputs;
          for (const uint64_t & offset_needed : needed_offsets)
          {
            size_t pos = 0;
            bool found = false;

            //todo ATANA double check/retest
            std::pair<tx_out_type, uint64_t> amount{output_presumed_type, output_value_amount};
            for (const uint64_t &offset_found : offset_map[amount])
            {
              if (offset_needed == offset_found)
              {
                found = true;
                break;
              }

              ++pos;
            }

            if (found && pos < tx_map[amount].size())
              outputs.push_back(tx_map[amount].at(pos));
            else
              break;
          }

          const crypto::key_image &k_image = *boost::apply_visitor(key_image_visitor(), txin);
          its->second.emplace(k_image, outputs);

        }
        else if (txin.type() == typeid(const txin_to_script))
        {
          const std::vector<uint64_t> &needed_output_ids = *boost::apply_visitor(key_offset_visitor(), txin);


          std::vector<output_advanced_data_t> advanced_outputs;
          for (const uint64_t & needed_output_id : needed_output_ids)
          {
            size_t pos = 0;
            bool found = false;

            for (const output_advanced_data_t &output_found : tx_advanced_map[output_presumed_type])
            {
              if (needed_output_id == output_found.output_id)
              {
                found = true;
                break;
              }

              ++pos;
            }

            if (found && pos < tx_advanced_map[output_presumed_type].size())
              advanced_outputs.push_back(tx_advanced_map[output_presumed_type].at(pos));
            else
              break;
          }

          const crypto::key_image &k_image = *boost::apply_visitor(key_image_visitor(), txin);
          its_advanced->second.emplace(k_image, advanced_outputs);

        }
        else if (txin.type() == typeid(txin_token_migration)) {
          const txin_token_migration &in_token_migration = boost::get < txin_token_migration > (txin);
          std::vector<output_data_t> outputs;

          output_data_t output = AUTO_VAL_INIT(output);
          output.commitment = rct::zeroCommit(in_token_migration.token_amount);
          outputs.push_back(output);
          its->second.emplace(in_token_migration.k_image, outputs);
        }
      }
    }
  }

  TIME_MEASURE_FINISH(scantable);
  if (total_txs > 0)
  {
    m_fake_scan_time = scantable / total_txs;
    if(m_show_time_stats)
      MDEBUG("Prepare scantable took: " << scantable << " ms");
  }

  return true;
}

void Blockchain::add_txpool_tx(transaction &tx, const txpool_tx_meta_t &meta)
{
  m_db->add_txpool_tx(tx, meta);
}

void Blockchain::update_txpool_tx(const crypto::hash &txid, const txpool_tx_meta_t &meta)
{
  m_db->update_txpool_tx(txid, meta);
}

void Blockchain::remove_txpool_tx(const crypto::hash &txid)
{
  m_db->remove_txpool_tx(txid);
}

uint64_t Blockchain::get_txpool_tx_count(bool include_unrelayed_txes) const
{
  return m_db->get_txpool_tx_count(include_unrelayed_txes);
}

bool Blockchain::get_txpool_tx_meta(const crypto::hash& txid, txpool_tx_meta_t &meta) const
{
  return m_db->get_txpool_tx_meta(txid, meta);
}

bool Blockchain::get_txpool_tx_blob(const crypto::hash& txid, cryptonote::blobdata &bd) const
{
  return m_db->get_txpool_tx_blob(txid, bd);
}

cryptonote::blobdata Blockchain::get_txpool_tx_blob(const crypto::hash& txid) const
{
  return m_db->get_txpool_tx_blob(txid);
}

bool Blockchain::for_all_txpool_txes(std::function<bool(const crypto::hash&, const txpool_tx_meta_t&, const cryptonote::blobdata*)> f, bool include_blob, bool include_unrelayed_txes) const
{
  return m_db->for_all_txpool_txes(f, include_blob, include_unrelayed_txes);
}

void Blockchain::set_user_options(uint64_t maxthreads, uint64_t blocks_per_sync, blockchain_db_sync_mode sync_mode, bool fast_sync)
{
  if (sync_mode == db_defaultsync)
  {
    m_db_default_sync = true;
    sync_mode = db_async;
  }
  m_db_sync_mode = sync_mode;
  m_fast_sync = fast_sync;
  m_db_blocks_per_sync = blocks_per_sync;
  m_max_prepare_blocks_threads = maxthreads;
}

void Blockchain::safesyncmode(const bool onoff)
{
  /* all of this is no-op'd if the user set a specific
   * --db-sync-mode at startup.
   */
  if (m_db_default_sync)
  {
    m_db->safesyncmode(onoff);
    m_db_sync_mode = onoff ? db_nosync : db_async;
  }
}

HardFork::State Blockchain::get_hard_fork_state() const
{
  return m_hardfork->get_state();
}

bool Blockchain::get_hard_fork_voting_info(uint8_t version, uint32_t &window, uint32_t &votes, uint32_t &threshold, uint64_t &earliest_height, uint8_t &voting) const
{
  return m_hardfork->get_voting_info(version, window, votes, threshold, earliest_height, voting);
}

uint64_t Blockchain::get_difficulty_target() const
{
  return DIFFICULTY_TARGET;
}

std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>> Blockchain:: get_output_histogram(const std::vector<uint64_t> &amounts, bool unlocked, uint64_t recent_cutoff, const tx_out_type output_type) const
{
  return m_db->get_output_histogram(amounts, unlocked, recent_cutoff, output_type);
}

std::list<std::pair<Blockchain::block_extended_info,uint64_t>> Blockchain::get_alternative_chains() const
{
  std::list<std::pair<Blockchain::block_extended_info,uint64_t>> chains;

  for (const auto &i: m_alternative_chains)
  {
    const crypto::hash &top = i.first;
    bool found = false;
    for (const auto &j: m_alternative_chains)
    {
      if (j.second.bl.prev_id == top)
      {
        found = true;
        break;
      }
    }
    if (!found)
    {
      uint64_t length = 1;
      auto h = i.second.bl.prev_id;
      blocks_ext_by_hash::const_iterator prev;
      while ((prev = m_alternative_chains.find(h)) != m_alternative_chains.end())
      {
        h = prev->second.bl.prev_id;
        ++length;
      }
      chains.push_back(std::make_pair(i.second, length));
    }
  }
  return chains;
}

void Blockchain::cancel()
{
  m_cancel = true;
}

#if defined(PER_BLOCK_CHECKPOINT)
static const char expected_block_hashes_hash[] = "d03984da2c9181c7bf36220e5e887d3182a270aff3782649cb6ba68280287b23";
void Blockchain::load_compiled_in_block_hashes()
{
  const bool testnet = m_nettype == TESTNET;
  const bool stagenet = m_nettype == STAGENET;
  if (m_fast_sync && get_blocks_dat_start(testnet, stagenet) != nullptr && get_blocks_dat_size(testnet, stagenet) > 0)
  {
    MINFO("Loading precomputed blocks (" << get_blocks_dat_size(testnet, stagenet) << " bytes)");

    if (m_nettype == MAINNET)
    {
      // first check hash
      crypto::hash hash;
      if (!tools::sha256sum(get_blocks_dat_start(testnet, stagenet), get_blocks_dat_size(testnet, stagenet), hash))
      {
        MERROR("Failed to hash precomputed blocks data");
        return;
      }
      MINFO("precomputed blocks hash: " << hash << ", expected " << expected_block_hashes_hash);
      cryptonote::blobdata expected_hash_data;
      if (!epee::string_tools::parse_hexstr_to_binbuff(std::string(expected_block_hashes_hash), expected_hash_data) || expected_hash_data.size() != sizeof(crypto::hash))
      {
        MERROR("Failed to parse expected block hashes hash");
        return;
      }
      const crypto::hash expected_hash = *reinterpret_cast<const crypto::hash*>(expected_hash_data.data());
      if (hash != expected_hash)
      {
        MERROR("Block hash data does not match expected hash");
        return;
      }
    }

    if (get_blocks_dat_size(testnet, stagenet) > 4)
    {
      const unsigned char *p = get_blocks_dat_start(testnet, stagenet);
      const uint32_t nblocks = *p | ((*(p+1))<<8) | ((*(p+2))<<16) | ((*(p+3))<<24);
      if (nblocks > (std::numeric_limits<uint32_t>::max() - 4) / sizeof(hash))
      {
        MERROR("Block hash data is too large");
        return;
      }
      const size_t size_needed = 4 + nblocks * sizeof(crypto::hash);
      if(nblocks > 0 && nblocks > (m_db->height() + HASH_OF_HASHES_STEP - 1) / HASH_OF_HASHES_STEP && get_blocks_dat_size(testnet, stagenet) >= size_needed)
      {
        p += sizeof(uint32_t);
        m_blocks_hash_of_hashes.reserve(nblocks);
        for (uint32_t i = 0; i < nblocks; i++)
        {
          crypto::hash hash;
          memcpy(hash.data, p, sizeof(hash.data));
          p += sizeof(hash.data);
          m_blocks_hash_of_hashes.push_back(hash);
        }
        m_blocks_hash_check.resize(m_blocks_hash_of_hashes.size() * HASH_OF_HASHES_STEP, crypto::null_hash);
        MINFO(nblocks << " block hashes loaded");

        // FIXME: clear tx_pool because the process might have been
        // terminated and caused it to store txs kept by blocks.
        // The core will not call check_tx_inputs(..) for these
        // transactions in this case. Consequently, the sanity check
        // for tx hashes will fail in handle_block_to_main_chain(..)
        CRITICAL_REGION_LOCAL(m_tx_pool);

        std::list<transaction> txs;
        m_tx_pool.get_transactions(txs);

        size_t blob_size;
        uint64_t fee;
        bool relayed, do_not_relay, double_spend_seen;
        transaction pool_tx;
        for(const transaction &tx : txs)
        {
          crypto::hash tx_hash = get_transaction_hash(tx);
          m_tx_pool.take_tx(tx_hash, pool_tx, blob_size, fee, relayed, do_not_relay, double_spend_seen);
        }
      }
    }
  }
}
#endif

bool Blockchain::is_within_compiled_block_hash_area(uint64_t height) const
{
#if defined(PER_BLOCK_CHECKPOINT)
  return height < m_blocks_hash_of_hashes.size() * HASH_OF_HASHES_STEP;
#else
  return false;
#endif
}

void Blockchain::lock()
{
  m_blockchain_lock.lock();
}

void Blockchain::unlock()
{
  m_blockchain_lock.unlock();
}

bool Blockchain::for_all_key_images(std::function<bool(const crypto::key_image&)> f) const
{
  return m_db->for_all_key_images(f);
}

bool Blockchain::for_blocks_range(const uint64_t& h1, const uint64_t& h2, std::function<bool(uint64_t, const crypto::hash&, const block&)> f) const
{
  return m_db->for_blocks_range(h1, h2, f);
}

bool Blockchain::for_all_transactions(std::function<bool(const crypto::hash&, const cryptonote::transaction&)> f) const
{
  return m_db->for_all_transactions(f);
}

bool Blockchain::for_all_outputs(std::function<bool(uint64_t amount, const crypto::hash &tx_hash, uint64_t height, size_t tx_idx)> f, const tx_out_type output_type) const
{
  return m_db->for_all_outputs(f, output_type);;
}

bool Blockchain::for_all_outputs(uint64_t amount, std::function<bool(uint64_t height)> f, const tx_out_type output_type) const
{
  return m_db->for_all_outputs(amount, f, output_type);;
}

namespace cryptonote {
template bool Blockchain::get_transactions(const std::vector<crypto::hash>&, std::list<transaction>&, std::list<crypto::hash>&) const;
}

bool Blockchain::is_valid_txin_key_offsets(const txin_v& txin) const
{
  struct key_offsets_visitor : public boost::static_visitor<bool> {
      bool operator()(const txin_to_key & _txin) const { return _txin.key_offsets.size() > 0; }
      bool operator()(const txin_token_to_key & _txin) const  { return _txin.key_offsets.size() > 0; }
      bool operator()(const txin_token_migration & _txin) const  { return true; } //non applicable
      bool operator()(const txin_to_script & _txin) const  { return true; } //non applicable
      bool operator()(const txin_to_scripthash & _txin) const  { return true; } //non applicable
      bool operator()(const txin_gen & _txin) const { return true; } //non applicable

  };

  return boost::apply_visitor(key_offsets_visitor(), txin);
}

/* Returns whole number of tokens without decimals */
uint64_t Blockchain::count_new_migration_tokens(const std::vector<transaction>& txs) const
{
  uint64_t ret = 0;

  for (const auto &tx: txs)
    for (const auto &txin : tx.vin)
    {
      if (txin.type() == typeid(txin_token_migration))
      {
        const txin_token_migration &in_token_migration = boost::get<txin_token_migration>(txin);
        ret += in_token_migration.token_amount / SAFEX_TOKEN;
      }
    }

  return ret;
}

uint64_t Blockchain::get_current_staked_token_sum() const
{
  return m_db->get_current_staked_token_sum();
}

uint64_t Blockchain::get_staked_token_sum_for_interval(const uint64_t &interval) const
{
  return m_db->get_staked_token_sum_for_interval(interval);
}

uint64_t Blockchain::get_network_fee_sum_for_interval(const uint64_t& interval) const
{
  return m_db->get_network_fee_sum_for_interval(interval);
}


/* Returns token stake interest */
uint64_t Blockchain::calculate_staked_token_interest(const uint64_t token_amount, const uint64_t start_block, const uint64_t end_block) const
{
  uint64_t ret = 0;


  return ret;
}

uint64_t Blockchain::calculate_staked_token_interest_for_output(const txin_to_script &txin, const uint64_t unlock_height) const
{
    return m_db->calculate_staked_token_interest_for_output(txin, unlock_height);
}

std::map<uint64_t, uint64_t> Blockchain::get_interest_map(uint64_t begin_interval, uint64_t end_interval)
{
  safex::map_interval_interest interest_map;
  if (!m_db->get_interval_interest_map(begin_interval, end_interval, interest_map)) {
    MERROR("Could not get interval map");
    return interest_map;
  }

  return interest_map;
}


bool Blockchain::get_safex_account_public_key(const safex::account_username &username, crypto::public_key &pkey) const
{

  try {
    bool result = m_db->get_account_key(username, pkey);
    return result;
  }
  catch (std::exception &ex) {
    //MERROR("Error fetching account public key: "+std::string(ex.what()));
    return false;
  }
}

bool Blockchain::get_safex_account_data(const safex::account_username &username, std::vector<uint8_t> &data) const
{

  try {
    bool result = m_db->get_account_data(username, data);
    return result;
  }
  catch (std::exception &ex) {
    MERROR("Error fetching account data: "+std::string(ex.what()));
    return false;
  }
}

bool Blockchain::get_safex_offer_seller(const crypto::hash &offerID, std::string &seller) const
{
    try {
        bool result = m_db->get_offer_seller(offerID, seller);
        return result;
    }
    catch (std::exception &ex) {
        MERROR("Error fetching offer seller username: "+std::string(ex.what()));
        return false;
    }
}

bool Blockchain::get_safex_offer(const crypto::hash &offerID, safex::safex_offer &offer) const
{
    try {
        bool result = m_db->get_offer(offerID, offer);
        return result;
    }
    catch (std::exception &ex) {
        MERROR("Error fetching offer: "+std::string(ex.what()));
        return false;
    }
}

bool Blockchain::get_safex_offer_price(const crypto::hash &offerID, uint64_t &price) const
{
    try {
        bool result = m_db->get_offer_price(offerID, price);
        return result;
    }
    catch (std::exception &ex) {
        MERROR("Error fetching offer price: "+std::string(ex.what()));
        return false;
    }
}

bool Blockchain::get_safex_offer_quantity(const crypto::hash &offerID, uint64_t &quantity) const
{
    try {
        bool result = m_db->get_offer_quantity(offerID, quantity);
        return result;
    }
    catch (std::exception &ex) {
        MERROR("Error fetching offer quantity: "+std::string(ex.what()));
        return false;
    }
}

bool Blockchain::get_safex_offer_active_status(const crypto::hash &offerID, bool &active) const
{
    try {
        bool result = m_db->get_offer_active_status(offerID, active);
        return result;
    }
    catch (std::exception &ex) {
        MERROR("Error fetching offer active status: "+std::string(ex.what()));
        return false;
    }
}

bool Blockchain::get_safex_offer_rating(const crypto::hash &offerID, uint64_t &rating) const
{
    try {
        bool result = m_db->get_offer_stars_given(offerID, rating);
        return result;
    }
    catch (std::exception &ex) {
        MERROR("Error fetching offer active status: "+std::string(ex.what()));
        return false;
    }
}

bool Blockchain::get_safex_accounts( std::vector<std::pair<std::string,std::string>> &safex_accounts) const
{
    LOG_PRINT_L3("Blockchain::" << __func__);

    return m_db->get_safex_accounts(safex_accounts);
}

bool Blockchain::get_table_sizes( std::vector<uint64_t> &table_sizes) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  return m_db->get_table_sizes(table_sizes);
}

bool Blockchain::get_safex_offer_height( crypto::hash &offer_id, uint64_t &height) const
{
    LOG_PRINT_L3("Blockchain::" << __func__);

    return m_db->get_safex_offer_height(offer_id, height);
}

bool Blockchain::get_safex_offers( std::vector<safex::safex_offer> &safex_offers) const
{
    LOG_PRINT_L3("Blockchain::" << __func__);

    return m_db->get_safex_offers(safex_offers);
}

bool Blockchain::get_safex_feedbacks(std::vector<safex::safex_feedback>& safex_feedbacks, const crypto::hash& offer_id) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  return m_db->get_safex_feedbacks(safex_feedbacks, offer_id);
}

bool Blockchain::get_safex_price_pegs( std::vector<safex::safex_price_peg> &safex_price_pegs, const std::string& currency) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  return m_db->get_safex_price_pegs(safex_price_pegs, currency);
}

bool Blockchain::get_safex_price_peg( const crypto::hash& price_peg_id, safex::safex_price_peg& sfx_price_peg) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  return m_db->get_safex_price_peg(price_peg_id,sfx_price_peg);
}

std::vector<crypto::public_key> Blockchain::is_safex_purchase_right_address(const crypto::secret_key& seller_secret_view_key, const crypto::public_key& public_seller_spend_key, const cryptonote::transaction& tx) {

    crypto::public_key pkey;
    if (!crypto::secret_key_to_public_key(seller_secret_view_key, pkey)) {
        return {};
    }

    hw::device &hwdev = hw::get_device("default");

    boost::unique_lock<hw::device> hwdev_lock (hwdev);
    hw::reset_mode rst(hwdev);
    hwdev_lock.unlock();


    std::vector<crypto::public_key> seller_outputs{};

    std::vector<tx_extra_field> tx_extra_fields;
    if(!parse_tx_extra(tx.extra, tx_extra_fields))
    {
        return seller_outputs;
    }
    size_t pk_index = 0;
    tx_extra_pub_key pub_key_field;
    if(!find_tx_extra_field_by_type(tx_extra_fields, pub_key_field, pk_index++))
    {
        if (pk_index > 1)
            return seller_outputs;
       return seller_outputs;
    }

    crypto::public_key tx_pub_key = pub_key_field.pub_key;
    crypto::key_derivation derivation;
    hwdev_lock.lock();
    hwdev.set_mode(hw::device::TRANSACTION_PARSE);
    if (!hwdev.generate_key_derivation(tx_pub_key, seller_secret_view_key, derivation))
    {
        MWARNING("Failed to generate key derivation from tx pubkey, skipping");
        static_assert(sizeof(derivation) == sizeof(rct::key), "Mismatched sizes of key_derivation and rct::key");
        memcpy(&derivation, rct::identity().bytes, sizeof(derivation));
    }

    // additional tx pubkeys and derivations for multi-destination transfers involving one or more subaddresses
    std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(tx);
    std::vector<crypto::key_derivation> additional_derivations;
    for (size_t i = 0; i < additional_tx_pub_keys.size(); ++i)
    {
        additional_derivations.push_back({});
        if (!hwdev.generate_key_derivation(additional_tx_pub_keys[i], seller_secret_view_key, additional_derivations.back()))
        {
            MWARNING("Failed to generate key derivation from tx pubkey, skipping");
            additional_derivations.pop_back();
        }
    }
    hwdev_lock.unlock();



    for (size_t i = 0; i < tx.vout.size(); ++i)
    {

        auto o = tx.vout[i];
        boost::optional<cryptonote::subaddress_receive_info> received;

        hwdev_lock.lock();
        hwdev.set_mode(hw::device::TRANSACTION_PARSE);
        if (!cryptonote::is_valid_transaction_output_type(o.target))
        {
            hwdev_lock.unlock();
            continue;
        }

        const crypto::public_key &out_key = *boost::apply_visitor(destination_public_key_visitor(), o.target);

        std::unordered_map<crypto::public_key, cryptonote::subaddress_index> m_subaddresses;
        cryptonote::subaddress_index sub_index{};
        m_subaddresses[public_seller_spend_key] = sub_index;

        received = is_out_to_acc_precomp(m_subaddresses, out_key, derivation, additional_derivations, i, hwdev);

        if(received)
        {
            seller_outputs.push_back(out_key);
        }
        hwdev_lock.unlock();
    }

    return seller_outputs;
}

bool Blockchain::are_safex_tokens_unlocked(const std::vector<txin_v> &tx_vin) {

  //We search the inputs for tokens
  for (const txin_v &txin: tx_vin)
  {
    if (txin.type() == typeid(txin_token_to_key))
    {
      const txin_token_to_key &in = boost::get<txin_token_to_key>(txin);
      if(in.token_amount != SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_FEE)
        continue;
      const std::vector<uint64_t> absolute = cryptonote::relative_output_offsets_to_absolute(in.key_offsets);

      // Now we search the offsets and find their txs
      for (auto index: absolute) {
        tx_out_index toi = this->m_db->get_output_tx_and_index(in.token_amount, index, tx_out_type::out_token);
        auto output_token_fee = this->m_db->get_output_key(in.token_amount, index, tx_out_type::out_token);
        cryptonote::transaction tx = m_db->get_tx(toi.first);
        //Now we search for script input
        if(is_create_safex_account_token_fee(tx.vout,output_token_fee.pubkey) &&
           output_token_fee.height + safex::get_safex_minumum_account_create_token_lock_period(m_nettype) > m_db->height())
          return false;
      }
    } else if ((txin.type() == typeid(txin_to_script)) && (boost::get<txin_to_script>(txin).command_type == safex::command_t::create_account))
        {
            const txin_to_script &in = boost::get<txin_to_script>(txin);
            if(in.token_amount != SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_FEE)
                continue;
            const std::vector<uint64_t> absolute = cryptonote::relative_output_offsets_to_absolute(in.key_offsets);

            // Now we search the offsets and find their txs
            for (auto index: absolute) {
                tx_out_index toi = this->m_db->get_output_tx_and_index(in.token_amount, index, tx_out_type::out_token);
                auto output_token_fee = this->m_db->get_output_key(in.token_amount, index, tx_out_type::out_token);
                cryptonote::transaction tx = m_db->get_tx(toi.first);
                //Now we search for script input
                if(is_create_safex_account_token_fee(tx.vout,output_token_fee.pubkey) &&
                    output_token_fee.height + safex::get_safex_minumum_account_create_token_lock_period(m_nettype) > m_db->height())
                    return false;
            }
        }

  }
  return true;
}

uint8_t Blockchain::get_maximum_tx_version_supported(uint8_t hf_version) const
{

    switch (m_nettype) {
    case cryptonote::network_type::FAKECHAIN:
    case cryptonote::network_type::TESTNET:
        return MAX_SUPPORTED_TX_VERSION;
    case cryptonote::network_type::STAGENET:
        return hf_version < HF_VERSION_ALLOW_TX_VERSION_2 ? MIN_SUPPORTED_TX_VERSION : MAX_SUPPORTED_TX_VERSION;
    default:
        return hf_version < HF_VERSION_ALLOW_TX_VERSION_2 ? MIN_SUPPORTED_TX_VERSION : MAX_SUPPORTED_TX_VERSION;
    }

    return hf_version < HF_VERSION_ALLOW_TX_VERSION_2 ? MIN_SUPPORTED_TX_VERSION : MAX_SUPPORTED_TX_VERSION;
}

