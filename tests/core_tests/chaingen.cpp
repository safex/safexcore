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

#include <vector>
#include <iostream>
#include <sstream>

#include "include_base_utils.h"

#include "console_handler.h"

#include "p2p/net_node.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/miner.h"

#include "chaingen.h"
#include "device/device.hpp"

#include "safex/command.h"

using namespace std;

using namespace epee;
using namespace crypto;
using namespace cryptonote;


void test_generator::get_block_chain(std::vector<block_info>& blockchain, const crypto::hash& head, size_t n) const
{
  crypto::hash curr = head;
  while (null_hash != curr && blockchain.size() < n)
  {
    auto it = m_blocks_info.find(curr);
    if (m_blocks_info.end() == it)
    {
      throw std::runtime_error("block hash wasn't found");
    }

    blockchain.push_back(it->second);
    curr = it->second.prev_id;
  }

  std::reverse(blockchain.begin(), blockchain.end());
}

void test_generator::get_last_n_block_sizes(std::vector<size_t>& block_sizes, const crypto::hash& head, size_t n) const
{
  std::vector<block_info> blockchain;
  get_block_chain(blockchain, head, n);
  BOOST_FOREACH(auto& bi, blockchain)
  {
    block_sizes.push_back(bi.block_size);
  }
}

uint64_t test_generator::get_already_generated_coins(const crypto::hash& blk_id) const
{
  auto it = m_blocks_info.find(blk_id);
  if (it == m_blocks_info.end())
    throw std::runtime_error("block hash wasn't found");

  return it->second.already_generated_coins;
}

uint64_t test_generator::get_already_generated_coins(const cryptonote::block& blk) const
{
  crypto::hash blk_hash;
  get_block_hash(blk, blk_hash);
  return get_already_generated_coins(blk_hash);
}

void test_generator::add_block(const cryptonote::block& blk, size_t tsx_size, std::vector<size_t>& block_sizes, uint64_t already_generated_coins, uint8_t hf_version, size_t height)
{
  const size_t block_size = tsx_size + get_object_blobsize(blk.miner_tx);
  uint64_t block_reward;
  get_block_reward(misc_utils::median(block_sizes), block_size, already_generated_coins, block_reward, hf_version, height);
  m_blocks_info[get_block_hash(blk)] = block_info(blk.prev_id, already_generated_coins + block_reward, block_size);
}

bool test_generator::construct_block(cryptonote::block& blk, uint64_t height, const crypto::hash& prev_id,
                                     const cryptonote::account_base& miner_acc, uint64_t timestamp, uint64_t already_generated_coins,
                                     std::vector<size_t>& block_sizes, const std::list<cryptonote::transaction>& tx_list)
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
    if (!construct_miner_tx(height, misc_utils::median(block_sizes), already_generated_coins, target_block_size, total_fee, miner_acc.get_keys().m_account_address, blk.miner_tx, blobdata(), 10))
      return false;

    size_t actual_block_size = txs_size + get_object_blobsize(blk.miner_tx);
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

  //blk.tree_root_hash = get_tx_tree_hash(blk);

  // Nonce search...
  blk.nonce = 0;
  while (!miner::find_nonce_for_given_block(NULL, blk, get_test_difficulty(), height))
    blk.timestamp++;

  const uint8_t hf_version = 1; //hardcode hf version for tests
  add_block(blk, txs_size, block_sizes, already_generated_coins, hf_version, height);

  return true;
}

bool test_generator::construct_block(cryptonote::block& blk, const cryptonote::account_base& miner_acc, uint64_t timestamp)
{
  std::vector<size_t> block_sizes;
  std::list<cryptonote::transaction> tx_list;
  return construct_block(blk, 0, null_hash, miner_acc, timestamp, 0, block_sizes, tx_list);
}

bool test_generator::construct_block(cryptonote::block& blk, const cryptonote::block& blk_prev,
                                     const cryptonote::account_base& miner_acc,
                                     const std::list<cryptonote::transaction>& tx_list/* = std::list<cryptonote::transaction>()*/)
{
  uint64_t height = boost::get<txin_gen>(blk_prev.miner_tx.vin.front()).height + 1;
  crypto::hash prev_id = get_block_hash(blk_prev);
  // Keep difficulty unchanged
  uint64_t timestamp = blk_prev.timestamp + DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN;
  uint64_t already_generated_coins = get_already_generated_coins(prev_id);
  std::vector<size_t> block_sizes;
  get_last_n_block_sizes(block_sizes, prev_id, CRYPTONOTE_REWARD_BLOCKS_WINDOW);

  return construct_block(blk, height, prev_id, miner_acc, timestamp, already_generated_coins, block_sizes, tx_list);
}

bool test_generator::construct_block_manually(block& blk, const block& prev_block, const account_base& miner_acc,
                                              int actual_params/* = bf_none*/, uint8_t major_ver/* = 0*/,
                                              uint8_t minor_ver/* = 0*/, uint64_t timestamp/* = 0*/,
                                              const crypto::hash& prev_id/* = crypto::hash()*/, const difficulty_type& diffic/* = 1*/,
                                              const transaction& miner_tx/* = transaction()*/,
                                              const std::vector<crypto::hash>& tx_hashes/* = std::vector<crypto::hash>()*/,
                                              size_t txs_sizes/* = 0*/, size_t max_outs/* = 0*/, uint8_t hf_version/* = 1*/)
{
  blk.major_version = actual_params & bf_major_ver ? major_ver : CURRENT_BLOCK_MAJOR_VERSION;
  blk.minor_version = actual_params & bf_minor_ver ? minor_ver : CURRENT_BLOCK_MINOR_VERSION;
  blk.timestamp     = actual_params & bf_timestamp ? timestamp : prev_block.timestamp + DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN; // Keep difficulty unchanged
  blk.prev_id       = actual_params & bf_prev_id   ? prev_id   : get_block_hash(prev_block);
  blk.tx_hashes     = actual_params & bf_tx_hashes ? tx_hashes : std::vector<crypto::hash>();
  max_outs          = actual_params & bf_max_outs ? max_outs : 9999;
  hf_version        = actual_params & bf_hf_version ? hf_version : 1;

  size_t height = get_block_height(prev_block) + 1;
  uint64_t already_generated_coins = get_already_generated_coins(prev_block);
  std::vector<size_t> block_sizes;
  get_last_n_block_sizes(block_sizes, get_block_hash(prev_block), CRYPTONOTE_REWARD_BLOCKS_WINDOW);
  if (actual_params & bf_miner_tx)
  {
    blk.miner_tx = miner_tx;
  }
  else
  {
    size_t current_block_size = txs_sizes + get_object_blobsize(blk.miner_tx);
    // TODO: This will work, until size of constructed block is less then CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE
    if (!construct_miner_tx(height, misc_utils::median(block_sizes), already_generated_coins, current_block_size, 0, miner_acc.get_keys().m_account_address, blk.miner_tx, blobdata(), max_outs, hf_version))
      return false;
  }

  //blk.tree_root_hash = get_tx_tree_hash(blk);

  difficulty_type a_diffic = actual_params & bf_diffic ? diffic : get_test_difficulty();
  fill_nonce(blk, a_diffic, height);

  add_block(blk, txs_sizes, block_sizes, already_generated_coins, hf_version, height);

  return true;
}

bool test_generator::construct_block_manually_tx(cryptonote::block& blk, const cryptonote::block& prev_block,
                                                 const cryptonote::account_base& miner_acc,
                                                 const std::vector<crypto::hash>& tx_hashes, size_t txs_size)
{
  return construct_block_manually(blk, prev_block, miner_acc, bf_tx_hashes, 0, 0, 0, crypto::hash(), 0, transaction(), tx_hashes, txs_size);
}


struct output_index {
    const cryptonote::txout_target_v out;
    uint64_t amount;
    uint64_t token_amount;
    size_t blk_height; // block height
    size_t tx_no; // index of transaction in block
    size_t out_no; // index of out in transaction
    size_t idx;
    size_t advanced_output_id{0};
    bool spent;
    const cryptonote::block *p_blk;
    const cryptonote::transaction *p_tx;
    cryptonote::tx_out_type out_type{cryptonote::tx_out_type::out_invalid};

    output_index(const cryptonote::txout_target_v &_out, uint64_t _a, uint64_t _t_a, size_t _h, size_t tno, size_t ono, const cryptonote::block *_pb, const cryptonote::transaction *_pt)
        : out(_out), amount(_a), token_amount(_t_a), blk_height(_h), tx_no(tno), out_no(ono), idx(0), spent(false), p_blk(_pb), p_tx(_pt) { }

    output_index(const output_index &other)
        : out(other.out), amount(other.amount), token_amount(other.token_amount), blk_height(other.blk_height), tx_no(other.tx_no), out_no(other.out_no), idx(other.idx),
        spent(other.spent), p_blk(other.p_blk), p_tx(other.p_tx), advanced_output_id{other.advanced_output_id}, out_type{other.out_type} {  }

    const std::string toString() const {
        std::stringstream ss;

        ss << "output_index{blk_height=" << blk_height
           << " tx_no=" << tx_no
           << " out_no=" << out_no
           << " amount=" << amount
           << " token_amount=" << token_amount
           << " idx=" << idx
           << " spent=" << spent
           << " out_type=" << static_cast<int>(out_type)
           << "}";

        return ss.str();
    }

    output_index& operator=(const output_index& other)
    {
      new(this) output_index(other);
      return *this;
    }
};

typedef std::map<uint64_t, std::vector<size_t> > map_output_t;
typedef std::map<uint64_t, std::vector<output_index> > map_output_idx_t;
typedef pair<uint64_t, size_t>  outloc_t;

namespace
{
  uint64_t get_inputs_amount(const vector<tx_source_entry> &s)
  {
    uint64_t r = 0;
    BOOST_FOREACH(const tx_source_entry &e, s)
    {
      r += e.amount;
    }

    return r;
  }

  uint64_t get_inputs_token_amount(const vector<tx_source_entry> &s)
  {
    uint64_t r = 0;
    BOOST_FOREACH(const tx_source_entry &e, s)
          {
            r += e.token_amount;
          }

    return r;
  }
}

bool init_output_indices(map_output_idx_t& outs, std::map<uint64_t, std::vector<size_t> >& outs_mine, const std::vector<cryptonote::block>& blockchain, const map_hash2tx_t& mtx,
                         const cryptonote::account_base& from, cryptonote::tx_out_type out_type = cryptonote::tx_out_type::out_cash, const crypto::public_key& safex_account_pkey = {}) {

    int output_id_counter = 0;
    int block_height = 0;
    BOOST_FOREACH (const block& blk, blockchain) {
        vector<const transaction*> vtx;
        vtx.push_back(&blk.miner_tx);

        BOOST_FOREACH(const crypto::hash &h, blk.tx_hashes) {
            const map_hash2tx_t::const_iterator cit = mtx.find(h);
            if (mtx.end() == cit)
                throw std::runtime_error("block contains an unknown tx hash");

            vtx.push_back(cit->second);
        }


        //vtx.insert(vtx.end(), blk.);
        // TODO: add all other txes
        for (size_t i = 0; i < vtx.size(); i++)
        {
          const transaction &tx = *vtx[i];

          for (size_t j = 0; j < tx.vout.size(); ++j)
          {
            output_id_counter+=1;
            const tx_out &out = tx.vout[j];
            const crypto::public_key &out_key = *boost::apply_visitor(cryptonote::destination_public_key_visitor(), out.target);

            if ((out_type == cryptonote::tx_out_type::out_token) || (out_type == cryptonote::tx_out_type::out_staked_token)
                || (out_type == cryptonote::tx_out_type::out_safex_account) || (out_type == cryptonote::tx_out_type::out_safex_account_update))
            {
              if (out.target.type() == typeid(cryptonote::txout_token_to_key))
              {
                output_index oi(out.target, out.amount, out.token_amount, boost::get<txin_gen>(*blk.miner_tx.vin.begin()).height, i, j, &blk, vtx[i]);
                outs[out.token_amount].push_back(oi);
                size_t tx_global_idx = outs[out.token_amount].size() - 1;
                outs[out.token_amount][tx_global_idx].idx = tx_global_idx;
                // Is out to me?
                if (is_out_to_acc(from.get_keys(), out_key, get_tx_pub_key_from_extra(tx), get_additional_tx_pub_keys_from_extra(tx), j))
                {
                  outs_mine[out.token_amount].push_back(tx_global_idx);
                }
              }
              else if (out.target.type() == typeid(cryptonote::txout_to_script))
              {
                const txout_to_script &temp = boost::get<txout_to_script>(out.target);
                if ((temp.output_type == static_cast<uint8_t>(tx_out_type::out_staked_token))
                  || (temp.output_type == static_cast<uint8_t>(tx_out_type::out_safex_account)))
                {
                  //cast tx_out_type and use it as imaginary amount for advanced outputs
                  output_index oi(out.target, out.amount, out.token_amount, boost::get<txin_gen>(*blk.miner_tx.vin.begin()).height, i, j, &blk, vtx[i]);
                  outs[static_cast<uint64_t>(temp.output_type)].push_back(oi);
                  size_t tx_global_idx = outs[static_cast<uint64_t>(temp.output_type)].size() - 1;
                  outs[static_cast<uint64_t>(temp.output_type)][tx_global_idx].idx = tx_global_idx;
                  outs[static_cast<uint64_t>(temp.output_type)][tx_global_idx].advanced_output_id = output_id_counter-1;
                  outs[static_cast<uint64_t>(temp.output_type)][tx_global_idx].blk_height = block_height;
                  outs[static_cast<uint64_t>(temp.output_type)][tx_global_idx].out_type = static_cast<cryptonote::tx_out_type>(temp.output_type);

                  // Is out to me?
                  if (is_safex_out_to_acc(safex_account_pkey, out_key)) {
                    outs_mine[static_cast<uint64_t>(temp.output_type)].push_back(tx_global_idx);
                  }
                  else if (is_out_to_acc(from.get_keys(), out_key, get_tx_pub_key_from_extra(tx), get_additional_tx_pub_keys_from_extra(tx), j))
                  {
                    outs_mine[static_cast<uint64_t>(temp.output_type)].push_back(tx_global_idx);
                  }
                }
              }

            }
            else if ((out_type == cryptonote::tx_out_type::out_cash) || (out_type == cryptonote::tx_out_type::out_network_fee))
            {
              if (out.target.type() == typeid(cryptonote::txout_to_key))
              { // out_to_key
                output_index oi(out.target, out.amount, out.token_amount, boost::get<txin_gen>(*blk.miner_tx.vin.begin()).height, i, j, &blk, vtx[i]);
                outs[out.amount].push_back(oi);
                size_t tx_global_idx = outs[out.amount].size() - 1;
                outs[out.amount][tx_global_idx].idx = tx_global_idx;
                // Is out to me?
                if (is_out_to_acc(from.get_keys(), out_key, get_tx_pub_key_from_extra(tx), get_additional_tx_pub_keys_from_extra(tx), j))
                {
                  outs_mine[out.amount].push_back(tx_global_idx);
                }
              }

            }


            }
        }
        block_height++;
    }

    return true;
}

bool init_spent_output_indices(map_output_idx_t& outs, map_output_t& outs_mine, const std::vector<cryptonote::block>& blockchain, const map_hash2tx_t& mtx, const cryptonote::account_base& from)
{

    BOOST_FOREACH (const map_output_t::value_type &o, outs_mine) {
        for (size_t i = 0; i < o.second.size(); ++i) {
            output_index &oi = outs[o.first][o.second[i]];

            // construct key image for this output
            crypto::key_image img;
            keypair in_ephemeral;
            const crypto::public_key &out_key = *boost::apply_visitor(destination_public_key_visitor(), oi.out);
            std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;
            subaddresses[from.get_keys().m_account_address.m_spend_public_key] = {0,0};
            if (oi.out_type == tx_out_type::out_safex_account) continue; //key image check not relevant
            generate_key_image_helper(from.get_keys(), subaddresses, out_key, get_tx_pub_key_from_extra(*oi.p_tx), get_additional_tx_pub_keys_from_extra(*oi.p_tx), oi.out_no, in_ephemeral, img, hw::get_device(("default")));

            // lookup for this key image in the events vector
            BOOST_FOREACH(auto& tx_pair, mtx) {
                const transaction& tx = *tx_pair.second;
                BOOST_FOREACH(const txin_v &in, tx.vin)
                {
                  auto k_image_opt = boost::apply_visitor(key_image_visitor(), in);
                  if (!k_image_opt)
                    continue;
                  const crypto::key_image &k_image = *k_image_opt;
                  if (k_image == img)
                  {
                    oi.spent = true;
                  }
                }
            }
        }
    }

    return true;
}

bool create_network_token_lock_interest_map(const std::vector<test_event_entry> &events, const block &blk_head, safex::map_interval_interest &interest_map)
{

    std::vector<cryptonote::block> blockchain;
    map_hash2tx_t mtx;
    if (!find_block_chain(events, blockchain, mtx, get_block_hash(blk_head)))
        return false;

    int block_height_counter = 0;
    int current_interval = 0;
    uint64_t interval_collected_fee = 0;
    uint64_t currently_locked_tokens = 0;

    BOOST_FOREACH (const block &blk, blockchain)
                {
                    vector<const transaction *> vtx;
                    vtx.push_back(&blk.miner_tx);

                    BOOST_FOREACH(const crypto::hash &h, blk.tx_hashes)
                                {
                                    const map_hash2tx_t::const_iterator cit = mtx.find(h);
                                    if (mtx.end() == cit)
                                        throw std::runtime_error("block contains an unknown tx hash");

                                    vtx.push_back(cit->second);
                                }

                    for (size_t i = 0; i < vtx.size(); i++)
                    {
                        const transaction &tx = *vtx[i];

                        for (size_t j = 0; j < tx.vin.size(); ++j)
                        {
                            const txin_v &txin = tx.vin[j];
                            if (txin.type() == typeid(txin_to_script)) {
                                const txin_to_script &in = boost::get<txin_to_script>(txin);
                                if (in.command_type == safex::command_t::token_unstake) {
                                    currently_locked_tokens -= in.token_amount;
                                }
                                else if (in.command_type == safex::command_t::distribute_network_fee) {
                                    //nothing to do??
                                }
                            }





                        }

                        for (size_t j = 0; j < tx.vout.size(); ++j) {
                            const tx_out &out = tx.vout[j];

                            if (out.target.type() == typeid(cryptonote::txout_to_script)) {
                                const txout_to_script &temp = boost::get<txout_to_script>(out.target);
                                if (temp.output_type == static_cast<uint8_t>(tx_out_type::out_staked_token)) {
                                    currently_locked_tokens += out.token_amount;
                                } else if (temp.output_type == static_cast<uint8_t>(tx_out_type::out_network_fee)) {
                                    interval_collected_fee += out.amount;
                                }
                            }
                        }



                    }
                    block_height_counter++;
                    current_interval = safex::calculate_interval_for_height(block_height_counter,
                                                                            cryptonote::network_type::FAKECHAIN);

                    if (safex::is_interval_last_block(block_height_counter, cryptonote::network_type::FAKECHAIN)) {
                        uint64_t whole_token_amount = currently_locked_tokens/SAFEX_TOKEN;
                        uint64_t interest_per_token = interval_collected_fee>0? interval_collected_fee/whole_token_amount:0;
                        interest_map[current_interval] = interest_per_token;
                        if (interest_per_token>0) std::cout << "For interval "<<current_interval<<" locked tokens:"<<whole_token_amount<<" interval_collected_fee:"<<interval_collected_fee<<" interest per token:"<<interest_per_token<<std::endl;
                        interval_collected_fee = 0;
                    }

                }
    return true;

}


bool fill_output_entries(std::vector<output_index>& out_indices, size_t sender_out, size_t nmix, size_t& real_entry_idx, std::vector<tx_source_entry::output_entry>& output_entries)
{
  if (out_indices.size() <= nmix)
    return false;

  bool sender_out_found = false;
  size_t rest = nmix;
  for (size_t i = 0; i < out_indices.size() && (0 < rest || !sender_out_found); ++i)
  {
    const output_index& oi = out_indices[i];
    if (oi.spent)
      continue;

    bool append = false;
    if (i == sender_out)
    {
      append = true;
      sender_out_found = true;
      real_entry_idx = output_entries.size();
    }
    else if (0 < rest)
    {
      --rest;
      append = true;
    }

    if (append)
    {
      const crypto::public_key &key = *boost::apply_visitor(destination_public_key_visitor(), oi.out);
      output_entries.push_back(tx_source_entry::output_entry(oi.idx, rct::ctkey({rct::pk2rct(key), rct::identity()})));
    }
  }

  return 0 == rest && sender_out_found;
}

bool fill_output_entries_advanced(std::vector<output_index>& out_indices, size_t sender_out, size_t nmix, size_t& real_entry_idx, std::vector<tx_source_entry::output_entry>& output_entries)
{
  if (out_indices.size() <= nmix)
    return false;

  bool sender_out_found = false;
  size_t rest = nmix;
  for (size_t i = 0; i < out_indices.size() && (0 < rest || !sender_out_found); ++i)
  {
    const output_index& oi = out_indices[i];
    if (oi.spent)
      continue;

    bool append = false;
    if (i == sender_out)
    {
      append = true;
      sender_out_found = true;
      real_entry_idx = output_entries.size();
    }
    else if (0 < rest)
    {
      --rest;
      append = true;
    }

    if (append)
    {
      if (oi.out_type == tx_out_type::out_safex_account) {
        crypto::public_key key{};
        if (!safex::parse_safex_account_key(oi.out, key)) {
          return false;
        }
        output_entries.push_back(tx_source_entry::output_entry(oi.advanced_output_id, rct::ctkey({rct::pk2rct(key), rct::identity()})));

      }
      else
      {
        const crypto::public_key &key = *boost::apply_visitor(destination_public_key_visitor(), oi.out);
        output_entries.push_back(tx_source_entry::output_entry(oi.advanced_output_id, rct::ctkey({rct::pk2rct(key), rct::identity()})));
      }
    }
  }

  return 0 == rest && sender_out_found;
}

bool fill_tx_sources(std::vector<tx_source_entry>& sources, const std::vector<test_event_entry>& events,
                     const block& blk_head, const cryptonote::account_base& from, uint64_t value_amount, size_t nmix,
                     cryptonote::tx_out_type out_type = cryptonote::tx_out_type::out_cash,
                             const crypto::public_key& safex_account_pkey = {})
{
    map_output_idx_t outs;
    map_output_t outs_mine;

    std::vector<cryptonote::block> blockchain;
    map_hash2tx_t mtx;
    if (!find_block_chain(events, blockchain, mtx, get_block_hash(blk_head)))
        return false;

    if (!init_output_indices(outs, outs_mine, blockchain, mtx, from, out_type, safex_account_pkey))
        return false;

    if (!init_spent_output_indices(outs, outs_mine, blockchain, mtx, from))
        return false;

    // Iterate in reverse is more efficiency
    uint64_t sources_cash_amount = 0;
    uint64_t sources_token_amount = 0;
    bool sources_found = false;
    BOOST_REVERSE_FOREACH(const map_output_t::value_type o, outs_mine)
    {
        for (size_t i = 0; i < o.second.size() && !sources_found; ++i)
        {
            size_t sender_out = o.second[i];
            const output_index &oi = outs[o.first][sender_out];
            if ((oi.spent) || (oi.token_amount > 0 && (out_type == cryptonote::tx_out_type::out_cash || out_type == cryptonote::tx_out_type::out_network_fee)) ||
                (oi.amount > 0 && (out_type == cryptonote::tx_out_type::out_token || out_type == cryptonote::tx_out_type::out_staked_token)))
              continue;

            if (out_type == cryptonote::tx_out_type::out_safex_account_update && oi.out_type != cryptonote::tx_out_type::out_safex_account)
                continue;



            cryptonote::tx_source_entry ts = AUTO_VAL_INIT(ts);
            if (out_type == cryptonote::tx_out_type::out_cash)
            {
              ts.amount = oi.amount;
              ts.referenced_output_type = cryptonote::tx_out_type::out_cash;
            }
            else if (out_type == cryptonote::tx_out_type::out_token)
            {
              ts.token_amount = oi.token_amount;
              ts.referenced_output_type = cryptonote::tx_out_type::out_token;
            }
            else if (out_type == cryptonote::tx_out_type::out_staked_token)
            {
              ts.token_amount = oi.token_amount;
              ts.referenced_output_type = cryptonote::tx_out_type::out_token;
              ts.command_type = safex::command_t::token_stake;
            }
            else if (out_type == cryptonote::tx_out_type::out_network_fee)
            {
              ts.amount = oi.amount;
              ts.referenced_output_type = cryptonote::tx_out_type::out_cash;
              ts.command_type = safex::command_t::donate_network_fee;
            }
            else if (out_type == cryptonote::tx_out_type::out_safex_account)
            {
              ts.token_amount = oi.token_amount;
              ts.referenced_output_type = cryptonote::tx_out_type::out_token;
              ts.command_type = safex::command_t::create_account;
            }
            else if (out_type == cryptonote::tx_out_type::out_safex_account_update)
            {
              ts.referenced_output_type = cryptonote::tx_out_type::out_safex_account;
              ts.command_type = safex::command_t::edit_account;
            }
            else
            {
              throw std::runtime_error("unknown referenced output type");
            }

            ts.real_output_in_tx_index = oi.out_no;
            ts.real_out_tx_key = get_tx_pub_key_from_extra(*oi.p_tx); // incoming tx public key
            size_t realOutput;

            switch (out_type) {
              case cryptonote::tx_out_type::out_safex_account_update:
                {
                  if (!fill_output_entries_advanced(outs[static_cast<uint64_t>(ts.referenced_output_type)], sender_out, nmix, realOutput, ts.outputs))
                    continue;

                  sources_found = true;
                }
              break;

              case cryptonote::tx_out_type::out_cash:
              case cryptonote::tx_out_type::out_token:
              case cryptonote::tx_out_type::out_network_fee:
              case cryptonote::tx_out_type::out_staked_token:
              case cryptonote::tx_out_type::out_safex_account:
              default:
                {
                if (!fill_output_entries(outs[o.first], sender_out, nmix, realOutput, ts.outputs))
                  continue;
                }
                break;
            }

            ts.real_output = realOutput;

            sources.push_back(ts);

            if ((out_type == cryptonote::tx_out_type::out_cash) ||
                (out_type == cryptonote::tx_out_type::out_network_fee))
            {
              sources_cash_amount += ts.amount;
              sources_found = value_amount <= sources_cash_amount;
            }
            else if ((out_type == cryptonote::tx_out_type::out_token)
                     || (out_type == cryptonote::tx_out_type::out_staked_token)
                     || (out_type == cryptonote::tx_out_type::out_safex_account))
            {
              sources_token_amount += ts.token_amount;
              sources_found = value_amount <= sources_token_amount;
            }


        }

        if (sources_found)
            break;
    }

    return sources_found;
}

uint64_t calculate_token_holder_interest_for_output(uint64_t lock_start_height, uint64_t lock_end_height, safex::map_interval_interest &interest_map, uint64_t token_amount)
{
  std::cout << "Calculating interest, lock_start_height:" << lock_start_height << " end height:" << lock_end_height << std::endl;

  uint64_t interest = 0;
  uint64_t starting_interval = safex::calculate_interval_for_height(lock_start_height, network_type::FAKECHAIN) + 1;
  uint64_t end_interval = safex::calculate_interval_for_height(lock_end_height, network_type::FAKECHAIN) - 1;
  for (uint64_t interval = starting_interval; interval <= end_interval; interval++)
  {
    interest += interest_map[interval] * (token_amount / SAFEX_TOKEN);
    if (interest_map[interval] > 0) std::cout << "Interest in interval "<<interval<<" per token "<< interest_map[interval]<<" is " << interest_map[interval] * (token_amount / SAFEX_TOKEN) << std::endl;
  }

  return interest;
}

bool fill_unstake_token_sources(std::vector<tx_source_entry> &sources, const std::vector<test_event_entry> &events, const block &blk_head,
                                const cryptonote::account_base &from, uint64_t value_amount, size_t nmix, cryptonote::tx_out_type out_type = cryptonote::tx_out_type::out_staked_token)
{
  map_output_idx_t outs;
  map_output_t outs_mine;

  std::vector<cryptonote::block> blockchain;

  map_hash2tx_t mtx;
  if (!find_block_chain(events, blockchain, mtx, get_block_hash(blk_head))) return false;

  uint64_t current_height = blockchain.size();

  if (!init_output_indices(outs, outs_mine, blockchain, mtx, from, out_type)) return false;

  if (!init_spent_output_indices(outs, outs_mine, blockchain, mtx, from)) return false;

    //insert fee calculation here
  safex::map_interval_interest interest_map;
  if (!create_network_token_lock_interest_map(events, blk_head, interest_map)) return false;

  // Iterate in reverse is more efficiency
  uint64_t sources_locked_token_amount = 0;
  bool sources_found = false;
  BOOST_REVERSE_FOREACH(const map_output_t::value_type o, outs_mine)
        {
          for (size_t i = 0; i < o.second.size() && !sources_found; ++i)
          {
            size_t sender_out = o.second[i];
            const output_index &oi = outs[o.first][sender_out];
            if ((oi.spent) || (oi.token_amount > 0 && out_type == cryptonote::tx_out_type::out_cash)
                || (oi.amount > 0 && (out_type == cryptonote::tx_out_type::out_token || out_type == cryptonote::tx_out_type::out_staked_token))
                || (oi.out.type() != typeid(txout_to_script)))
              continue;


            const cryptonote::txout_to_script &out = boost::get<txout_to_script>(oi.out);

            if (out.output_type != static_cast<uint8_t >(cryptonote::tx_out_type::out_staked_token))
              continue;

            cryptonote::tx_source_entry ts = AUTO_VAL_INIT(ts);
            ts.token_amount = oi.token_amount;
            ts.referenced_output_type = cryptonote::tx_out_type::out_staked_token;
            ts.command_type = safex::command_t::token_unstake;
            ts.real_output_in_tx_index = oi.out_no;
            ts.real_out_tx_key = get_tx_pub_key_from_extra(*oi.p_tx); // incoming tx public key
            size_t realOutput;
            if (!fill_output_entries_advanced(outs[o.first], sender_out, nmix, realOutput, ts.outputs))
              continue;
            ts.real_output = realOutput;

            sources_locked_token_amount = ts.token_amount;
            sources_found = value_amount == sources_locked_token_amount;

            if (sources_found)
            {
              cryptonote::tx_source_entry ts_interest = AUTO_VAL_INIT(ts_interest);
              ts_interest.referenced_output_type = cryptonote::tx_out_type::out_network_fee;
              ts_interest.command_type = safex::command_t::distribute_network_fee;
              ts_interest.amount = calculate_token_holder_interest_for_output(oi.blk_height, current_height, interest_map, oi.token_amount);
              ts_interest.real_output_in_tx_index = oi.out_no; //reference same token output
              //******************************************************************************************************/
              //todo atana check if this is safe, if we can use same public key for interest, as ring size is only 1
              //******************************************************************************************************/
              ts_interest.real_out_tx_key = get_tx_pub_key_from_extra(*oi.p_tx); // here just for completion, does not actually used for check
              //ts_interest.real_out_tx_key = AUTO_VAL_INIT(ts_interest.real_out_tx_key); //not used
              ts_interest.outputs = ts.outputs;
              ts_interest.real_output = realOutput;


              sources.push_back(ts);
              if (ts_interest.amount > 0)
                sources.push_back(ts_interest);
            }


          }

          if (sources_found)
            break;
        }

  return sources_found;
}


bool fill_migration_tx_sources(std::vector<tx_source_entry>& sources, const std::vector<test_event_entry>& events,
                     const block& blk_head, const cryptonote::account_base& from, uint64_t token_amount, uint64_t cash_airdrop_amount,
                     const crypto::hash &bitcoin_transaction_hash)
{
  map_output_idx_t outs;
  map_output_t outs_mine;

  std::vector<cryptonote::block> blockchain;
  map_hash2tx_t mtx;
  if (!find_block_chain(events, blockchain, mtx, get_block_hash(blk_head)))
    return false;

  if (!init_output_indices(outs, outs_mine, blockchain, mtx, from))
    return false;

  if (!init_spent_output_indices(outs, outs_mine, blockchain, mtx, from))
    return false;

  // Iterate in reverse is more efficiency to get cash for migration transaction
  uint64_t sources_cash_amount = 0;
  bool sources_found = false;
  BOOST_REVERSE_FOREACH(const map_output_t::value_type o, outs_mine)
        {
          for (size_t i = 0; i < o.second.size() && !sources_found; ++i)
          {
            size_t sender_out = o.second[i];
            const output_index& oi = outs[o.first][sender_out];
            if (oi.spent)
              continue;

            cryptonote::tx_source_entry ts = AUTO_VAL_INIT(ts);
            ts.amount = oi.amount;
            ts.real_output_in_tx_index = oi.out_no;
            ts.real_out_tx_key = get_tx_pub_key_from_extra(*oi.p_tx); // incoming tx public key
            size_t realOutput;
            if (!fill_output_entries(outs[o.first], sender_out, 0 /*nmix*/, realOutput, ts.outputs))
              continue;

            ts.real_output = realOutput;

            sources.push_back(ts);

            sources_cash_amount += ts.amount;
            sources_found = cash_airdrop_amount <= sources_cash_amount;
          }

          if (sources_found)
            break;
        }

  //add one migration input
  sources.resize(sources.size() + 1);
  cryptonote::tx_source_entry &src = sources.back();
  src = boost::value_initialized<cryptonote::tx_source_entry>();
  //Only migration account could sign txin_token_migration
  auto output = cryptonote::generate_migration_bitcoin_transaction_output(from.get_keys(), bitcoin_transaction_hash, token_amount);
  src.outputs.push_back(output);
  src.token_amount = token_amount;
  src.referenced_output_type = cryptonote::tx_out_type::out_bitcoin_migration;


  return sources_found;
}


bool fill_tx_destination(tx_destination_entry &de, const cryptonote::account_base &to, uint64_t amount) {
    de.addr = to.get_keys().m_account_address;
    de.amount = amount;
    de.output_type = cryptonote::tx_out_type::out_cash;
    return true;
}

bool fill_token_tx_destination(tx_destination_entry &de, const cryptonote::account_base &to, uint64_t token_amount) {
  de.addr = to.get_keys().m_account_address;
  de.token_amount = token_amount;
  de.token_transaction = true;
  de.output_type = cryptonote::tx_out_type::out_token;
  return true;
}


void fill_tx_sources_and_destinations(const std::vector<test_event_entry>& events, const block& blk_head,
                                      const cryptonote::account_base& from, const cryptonote::account_base& to,
                                      uint64_t amount, uint64_t fee, size_t nmix, std::vector<tx_source_entry>& sources,
                                      std::vector<tx_destination_entry>& destinations)
{
  sources.clear();
  destinations.clear();

  if (!fill_tx_sources(sources, events, blk_head, from, amount + fee, nmix))
    throw std::runtime_error("couldn't fill transaction sources");

  tx_destination_entry de;
  if (!fill_tx_destination(de, to, amount))
    throw std::runtime_error("couldn't fill transaction destination");
  destinations.push_back(de);

  tx_destination_entry de_change;
  uint64_t cache_back = get_inputs_amount(sources) - (amount + fee);
  if (0 < cache_back)
  {
    if (!fill_tx_destination(de_change, from, cache_back))
      throw std::runtime_error("couldn't fill transaction cache back destination");
    destinations.push_back(de_change);
  }
}

void fill_migration_tx_sources_and_destinations(const std::vector<test_event_entry>& events, const block& blk_head,
                                      const cryptonote::account_base& from, const cryptonote::account_base& to,
                                      uint64_t token_amount, uint64_t fee, std::vector<tx_source_entry>& sources,
                                      std::vector<tx_destination_entry>& destinations, const crypto::hash &bitcoin_transaction_hash)
{
  sources.clear();
  destinations.clear();

  const uint64_t cash_airdrop_amount = cryptonote::get_airdrop_cash(token_amount);

  if (!fill_migration_tx_sources(sources, events, blk_head, from, token_amount, cash_airdrop_amount + fee, bitcoin_transaction_hash))
    throw std::runtime_error("couldn't fill transaction sources");

  tx_destination_entry de_cash = AUTO_VAL_INIT(de_cash);
  if (!fill_tx_destination(de_cash, to, cash_airdrop_amount))
    throw std::runtime_error("couldn't fill transaction destination");
  destinations.push_back(de_cash);

  tx_destination_entry de_change = AUTO_VAL_INIT(de_change);
  uint64_t cache_back = get_inputs_amount(sources) - (cash_airdrop_amount + fee);
  if (0 < cache_back)
  {
    if (!fill_tx_destination(de_change, from, cache_back))
      throw std::runtime_error("couldn't fill transaction cache back destination");
    destinations.push_back(de_change);
  }

  tx_destination_entry de_token = AUTO_VAL_INIT(de_token);
  if (!fill_token_tx_destination(de_token, to, token_amount))
    throw std::runtime_error("couldn't fill transaction destination");
  destinations.push_back(de_token);

}

void fill_token_tx_sources_and_destinations(const std::vector<test_event_entry>& events, const block& blk_head,
                                      const cryptonote::account_base& from, const cryptonote::account_base& to,
                                      uint64_t token_amount, uint64_t fee, size_t nmix, std::vector<tx_source_entry>& sources,
                                      std::vector<tx_destination_entry>& destinations)
{
  sources.clear();
  destinations.clear();

  //fill cache sources for fee
  if (!fill_tx_sources(sources, events, blk_head, from, fee, nmix, cryptonote::tx_out_type::out_cash))
    throw std::runtime_error("couldn't fill transaction sources");

  //token source
  if (!fill_tx_sources(sources, events, blk_head, from, token_amount, nmix, cryptonote::tx_out_type::out_token))
    throw std::runtime_error("couldn't fill token transaction sources");

  //token destination
  tx_destination_entry de = AUTO_VAL_INIT(de);
  if (!fill_token_tx_destination(de, to, token_amount))
    throw std::runtime_error("couldn't fill token transaction destination");
  destinations.push_back(de);

  //destination token change
  tx_destination_entry de_token_change  = AUTO_VAL_INIT(de_token_change);
  uint64_t token_back = get_inputs_token_amount(sources) - token_amount;
  if (0 < token_back)
  {
    if (!fill_token_tx_destination(de_token_change, from, token_back))
      throw std::runtime_error("couldn't fill transaction token back destination");
    destinations.push_back(de_token_change);
  }

  //sender change for fee
  tx_destination_entry de_change  = AUTO_VAL_INIT(de);
  uint64_t cache_back = get_inputs_amount(sources) - fee;
  if (0 < cache_back)
  {
    if (!fill_tx_destination(de_change, from, cache_back))
      throw std::runtime_error("couldn't fill transaction cache back destination");
    destinations.push_back(de_change);
  }
}

tx_destination_entry create_tx_destination(const cryptonote::account_base &to, uint64_t amount)
{
  return tx_destination_entry{amount, to.get_keys().m_account_address, false, tx_out_type::out_cash};
}

tx_destination_entry create_token_tx_destination(const cryptonote::account_base &to, uint64_t token_amount)
{
  return tx_destination_entry{token_amount, to.get_keys().m_account_address, false, tx_out_type::out_token};
}

tx_destination_entry create_locked_token_tx_destination(const cryptonote::account_base &to, uint64_t token_amount)
{
  return tx_destination_entry{token_amount, to.get_keys().m_account_address, false, tx_out_type::out_staked_token};
}

tx_destination_entry create_network_fee_tx_destination(uint64_t cash_amount)
{
  account_public_address dummy = AUTO_VAL_INIT(dummy);
  return tx_destination_entry{cash_amount, dummy, false, tx_out_type::out_network_fee};
}

tx_destination_entry create_interest_destination(const cryptonote::account_base &to, uint64_t cash_amount)
{
  return tx_destination_entry{cash_amount, to.get_keys().m_account_address, false, tx_out_type::out_cash};
}

tx_destination_entry create_safex_account_destination(const cryptonote::account_base &to, const std::string &username, const crypto::public_key &pkey,
                                                      const std::vector<uint8_t> &account_data)
{
  safex::create_account_data acc_output_data{username, pkey, account_data};
  blobdata blobdata = cryptonote::t_serializable_object_to_blob(acc_output_data);
  return tx_destination_entry{0, to.get_keys().m_account_address, false, tx_out_type::out_safex_account, blobdata};
}

tx_destination_entry create_edit_account_destination(const cryptonote::account_base &to, const std::string &username, const std::vector<uint8_t> &account_data)
{
  safex::edit_account_data acc_output_data{username, account_data};
  blobdata blobdata = cryptonote::t_serializable_object_to_blob(acc_output_data);
  return tx_destination_entry{0, to.get_keys().m_account_address, false, tx_out_type::out_safex_account_update, blobdata};
}


void fill_token_stake_tx_sources_and_destinations(const std::vector<test_event_entry> &events, const block &blk_head,
                                                  const cryptonote::account_base &from, const cryptonote::account_base &to, uint64_t token_amount, uint64_t fee, size_t nmix, std::vector<tx_source_entry> &sources,
                                                  std::vector<tx_destination_entry> &destinations)
{
  sources.clear();
  destinations.clear();

  //fill cache sources for fee
  if (!fill_tx_sources(sources, events, blk_head, from, fee, nmix, cryptonote::tx_out_type::out_cash))
    throw std::runtime_error("couldn't fill transaction sources");

  //token source
  if (!fill_tx_sources(sources, events, blk_head, from, token_amount, nmix, cryptonote::tx_out_type::out_staked_token))
    throw std::runtime_error("couldn't fill token transaction sources for tokens to lock");

  //locked token destination
  tx_destination_entry de = create_locked_token_tx_destination(to, token_amount);
  destinations.push_back(de);

  //destination token change

  uint64_t token_back = get_inputs_token_amount(sources) - token_amount;
  if (0 < token_back)
  {
    tx_destination_entry de_token_change = create_token_tx_destination(from, token_back);
    destinations.push_back(de_token_change);
  }

  //sender change for fee

  uint64_t cache_back = get_inputs_amount(sources) - fee;
  if (0 < cache_back)
  {
    tx_destination_entry de_change = create_tx_destination(from, cache_back);
    destinations.push_back(de_change);
  }
}


void fill_token_unstake_tx_sources_and_destinations(const std::vector<test_event_entry> &events, const block &blk_head, const cryptonote::account_base &from, const cryptonote::account_base &to,
                                                    uint64_t token_amount, uint64_t fee, size_t nmix, std::vector<tx_source_entry> &sources,
                                                    std::vector<tx_destination_entry> &destinations)
{
  sources.clear();
  destinations.clear();

  //fill cache sources for fee
  if (!fill_tx_sources(sources, events, blk_head, from, fee, nmix, cryptonote::tx_out_type::out_cash))
    throw std::runtime_error("couldn't fill transaction sources");

  //locked token source
  if (!fill_unstake_token_sources(sources, events, blk_head, from, token_amount, nmix))
    throw std::runtime_error("couldn't fill token transaction sources for tokens to unlock");


  //locked token destination, there is no token change, all tokens are unlocked
  tx_destination_entry de_token = create_token_tx_destination(to, token_amount);
  destinations.push_back(de_token);

  // Interest destination is added in construct_advanced_tx_with_tx_key, review if this is optimal
  tx_destination_entry de_interest = AUTO_VAL_INIT(de_interest);
  for (tx_source_entry &source: sources) {
    if (source.command_type == safex::command_t::distribute_network_fee) {
      de_interest = create_interest_destination(to, source.amount);
    }
  }



  //sender change for fee
  uint64_t cache_back = get_inputs_amount(sources) - fee - de_interest.amount;
  if (0 < cache_back)
  {
    tx_destination_entry de_change = create_tx_destination(from, cache_back);
    destinations.push_back(de_change);
  }
}

void fill_donation_tx_sources_and_destinations(const std::vector<test_event_entry>& events, const block& blk_head,
        const cryptonote::account_base &from, uint64_t cash_amount, uint64_t fee, size_t nmix,
        std::vector<tx_source_entry> &sources, std::vector<tx_destination_entry> &destinations)
{
  sources.clear();
  destinations.clear();

  //fill cache sources for fee
  if (!fill_tx_sources(sources, events, blk_head, from, fee+cash_amount, nmix, cryptonote::tx_out_type::out_network_fee))
    throw std::runtime_error("couldn't fill transaction sources");

  //fee donation, txout_to_script
  tx_destination_entry de_donation_fee = create_network_fee_tx_destination(cash_amount);
  destinations.push_back(de_donation_fee);

  //sender change for fee

  uint64_t cache_back = get_inputs_amount(sources) - fee - cash_amount;
  if (0 < cache_back)
  {
    tx_destination_entry de_change = create_tx_destination(from, cache_back);
    destinations.push_back(de_change);
  }
}

void fill_create_account_sources_and_destinations(const std::vector<test_event_entry>& events, const block& blk_head,
                                                  const cryptonote::account_base &from, uint64_t token_amount,
                                                  uint64_t fee, size_t nmix, const std::string &username, const crypto::public_key &pkey,
                                                  const std::vector<uint8_t> &account_data, std::vector<tx_source_entry> &sources,
                                                  std::vector<tx_destination_entry> &destinations)
{
  sources.clear();
  destinations.clear();

  const cryptonote::account_base &to = from;

  //token amount is amount of tokens we want to lock for a period for creating account

  //fill cache sources for fee
  if (!fill_tx_sources(sources, events, blk_head,  from, fee, nmix, cryptonote::tx_out_type::out_cash))
    throw std::runtime_error("couldn't fill transaction sources");

  //safex account command source
  if (!fill_tx_sources(sources, events, blk_head,  from, token_amount, nmix, cryptonote::tx_out_type::out_safex_account))
    throw std::runtime_error("couldn't fill token transaction sources for create account");

  //update source with new account data
  for (auto &ts: sources) {
    if (ts.command_type == safex::command_t::create_account) {
      safex::create_account_data account{username, pkey, account_data};
      ts.command_safex_data = t_serializable_object_to_blob(account);
    }

  }

  //destinations

  //locked token destination
  tx_destination_entry de_token = create_token_tx_destination(to, token_amount);
  destinations.push_back(de_token);

  //destination token change
  uint64_t token_back = get_inputs_token_amount(sources) - token_amount;
  if (0 < token_back)
  {
    tx_destination_entry de_token_change = create_token_tx_destination(from, token_back);
    destinations.push_back(de_token_change);
  }

  //sender change for fee
  uint64_t cache_back = get_inputs_amount(sources) - fee;
  if (0 < cache_back)
  {
    tx_destination_entry de_change = create_tx_destination(from, cache_back);
    destinations.push_back(de_change);
  }

  //account
  tx_destination_entry de_account = create_safex_account_destination(from, username, pkey, account_data);
  destinations.push_back(de_account);
}

void fill_edit_account_tx_sources_and_destinations(const std::vector<test_event_entry>& events, const block& blk_head,
                                        const cryptonote::account_base &from, uint64_t token_amount,
                                        uint64_t fee, size_t nmix, const std::string &username, const std::vector<uint8_t> &new_account_data, std::vector<tx_source_entry> &sources,
                                        std::vector<tx_destination_entry> &destinations, const crypto::public_key& safex_account_pkey = {})
{
  sources.clear();
  destinations.clear();

  const cryptonote::account_base &to = from;

  //fill cache sources for fee
  if (!fill_tx_sources(sources, events, blk_head, from, fee, nmix, cryptonote::tx_out_type::out_cash))
    throw std::runtime_error("couldn't fill transaction sources");

  if (!fill_tx_sources(sources, events, blk_head, from, 0, nmix, cryptonote::tx_out_type::out_safex_account_update, safex_account_pkey))
    throw std::runtime_error("couldn't fill token transaction sources for edit account");

  //update source with new account data
  for (auto &ts: sources) {
    if (ts.command_type == safex::command_t::edit_account) {
      safex::edit_account_data editaccount{username, new_account_data};
      ts.command_safex_data = t_serializable_object_to_blob(editaccount);
    }
  }

  //destinations

  //sender change for fee
  uint64_t cache_back = get_inputs_amount(sources) - fee;
  if (0 < cache_back)
  {
    tx_destination_entry de_change = create_tx_destination(from, cache_back);
    destinations.push_back(de_change);
  }

  //new_account
  tx_destination_entry de_account = create_edit_account_destination(from, username, new_account_data);
  destinations.push_back(de_account);

}


void fill_nonce(cryptonote::block& blk, const difficulty_type& diffic, uint64_t height)
{
  blk.nonce = 0;
  while (!miner::find_nonce_for_given_block(NULL, blk, diffic, height))
    blk.timestamp++;
}

bool construct_miner_tx_manually(size_t height, uint64_t already_generated_coins,
                                 const account_public_address& miner_address, transaction& tx, uint64_t fee,
                                 keypair* p_txkey/* = 0*/)
{
  keypair txkey;
  txkey = keypair::generate(hw::get_device("default"));
  add_tx_pub_key_to_extra(tx, txkey.pub);

  if (0 != p_txkey)
    *p_txkey = txkey;

  txin_gen in;
  in.height = height;
  tx.vin.push_back(in);

  // This will work, until size of constructed block is less then CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE
  uint64_t block_reward;
  if (!get_block_reward(0, 0, already_generated_coins, block_reward, 1, height))
  {
    LOG_PRINT_L0("Block is too big");
    return false;
  }
  block_reward += fee;

  crypto::key_derivation derivation;
  crypto::public_key out_eph_public_key;
  crypto::generate_key_derivation(miner_address.m_view_public_key, txkey.sec, derivation);
  crypto::derive_public_key(derivation, 0, miner_address.m_spend_public_key, out_eph_public_key);

  tx_out out;
  out.amount = block_reward;
  out.target = txout_to_key(out_eph_public_key);
  tx.vout.push_back(out);

  tx.version = 1;
  tx.unlock_time = height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;

  return true;
}

bool construct_tx_to_key(const std::vector<test_event_entry>& events, cryptonote::transaction& tx, const block& blk_head,
                         const cryptonote::account_base& from, const cryptonote::account_base& to, uint64_t amount,
                         uint64_t fee, size_t nmix)
{
  vector<tx_source_entry> sources;
  vector<tx_destination_entry> destinations;
  fill_tx_sources_and_destinations(events, blk_head, from, to, amount, fee, nmix, sources, destinations);

  return construct_tx(from.get_keys(), sources, destinations, from.get_keys().m_account_address, std::vector<uint8_t>(), tx, 0);
}

bool construct_migration_tx_to_key(const std::vector<test_event_entry>& events, cryptonote::transaction& tx, const block& blk_head,
                         const cryptonote::account_base& from, const cryptonote::account_base& to, uint64_t token_amount,
                         uint64_t fee, const crypto::hash& bitcoin_hash)
{
  vector<tx_source_entry> sources;
  vector<tx_destination_entry> destinations;
  fill_migration_tx_sources_and_destinations(events, blk_head, from, to, token_amount, fee, sources, destinations, bitcoin_hash);

  std::vector<uint8_t> extra;
  add_bitcoin_hash_to_extra(extra, bitcoin_hash);

  return construct_tx(from.get_keys(), sources, destinations, from.get_keys().m_account_address, extra, tx, 0);
}

bool construct_token_tx_to_key(const std::vector<test_event_entry>& events, cryptonote::transaction& tx, const block& blk_head,
                         const cryptonote::account_base& from, const cryptonote::account_base& to, uint64_t token_amount,
                         uint64_t fee, size_t nmix)
{
  vector<tx_source_entry> sources;
  vector<tx_destination_entry> destinations;
  fill_token_tx_sources_and_destinations(events, blk_head, from, to, token_amount, fee, nmix, sources, destinations);

  return construct_tx(from.get_keys(), sources, destinations, from.get_keys().m_account_address, std::vector<uint8_t>(), tx, 0);
}

transaction construct_tx_with_fee(std::vector<test_event_entry>& events, const block& blk_head,
                                  const account_base& acc_from, const account_base& acc_to, uint64_t amount, uint64_t fee)
{
  transaction tx;
  construct_tx_to_key(events, tx, blk_head, acc_from, acc_to, amount, fee, 0);
  events.push_back(tx);
  return tx;
}

bool construct_token_stake_tx(const std::vector<test_event_entry> &events, cryptonote::transaction &tx, const block &blk_head,
                              const cryptonote::account_base &user_account, uint64_t token_amount, uint64_t fee, size_t nmix)
{
  std::vector<tx_source_entry> sources;
  std::vector<tx_destination_entry> destinations;
  fill_token_stake_tx_sources_and_destinations(events, blk_head, user_account, user_account, token_amount, fee, nmix, sources, destinations);

  return construct_tx(user_account.get_keys(), sources, destinations, user_account.get_keys().m_account_address, std::vector<uint8_t>(), tx, 0);
}

bool construct_token_unstake_tx(const std::vector<test_event_entry> &events, cryptonote::transaction &tx, const block &blk_head,
                                const cryptonote::account_base &from, uint64_t token_amount, uint64_t fee, size_t nmix)
{
  std::vector<tx_source_entry> sources;
  std::vector<tx_destination_entry> destinations;
  fill_token_unstake_tx_sources_and_destinations(events, blk_head, from, from, token_amount, fee, nmix, sources, destinations);

  return construct_tx(from.get_keys(), sources, destinations, from.get_keys().m_account_address, std::vector<uint8_t>(), tx, 0);
}

bool construct_fee_donation_transaction(const std::vector<test_event_entry>& events, cryptonote::transaction &tx, const block& blk_head,
        const cryptonote::account_base &from, uint64_t cash_amount, uint64_t fee, size_t nmix)
{
  std::vector<tx_source_entry> sources;
  std::vector<tx_destination_entry> destinations;

  fill_donation_tx_sources_and_destinations(events, blk_head, from, cash_amount, fee, nmix, sources, destinations);

  return construct_tx(from.get_keys(), sources, destinations, from.get_keys().m_account_address, std::vector<uint8_t>(), tx, 0);
}

bool construct_create_account_transaction(const std::vector<test_event_entry>& events,  cryptonote::transaction &tx, const cryptonote::block& blk_head,
                                          const cryptonote::account_base &from, uint64_t fee,
                                          size_t nmix, const std::string &username, const crypto::public_key &pkey, const std::vector<uint8_t> &account_data, uint64_t unlock_time, const safex::safex_account_keys &sfx_acc_keys)
{
  std::vector<tx_source_entry> sources;
  std::vector<tx_destination_entry> destinations;
  fill_create_account_sources_and_destinations(events, blk_head, from, SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_FEE, fee, nmix, username, pkey, account_data, sources, destinations);

  return construct_tx(from.get_keys(), sources, destinations, from.get_keys().m_account_address, std::vector<uint8_t>(), tx , unlock_time, sfx_acc_keys);
}

bool construct_edit_account_transaction(const std::vector<test_event_entry>& events,  cryptonote::transaction &tx, const cryptonote::block& blk_head,
                                          const cryptonote::account_base &from, uint64_t fee,
                                          size_t nmix, const std::string &username, const std::vector<uint8_t> &new_account_data, const safex::safex_account_keys &sfx_acc_keys)
{
  std::vector<tx_source_entry> sources;
  std::vector<tx_destination_entry> destinations;
  fill_edit_account_tx_sources_and_destinations(events, blk_head, from, 0, fee, nmix, username, new_account_data, sources, destinations, sfx_acc_keys.get_public_key());

  return construct_tx(from.get_keys(), sources, destinations, from.get_keys().m_account_address, std::vector<uint8_t>(), tx, 0, sfx_acc_keys);
}


uint64_t get_balance(const cryptonote::account_base& addr, const std::vector<cryptonote::block>& blockchain, const map_hash2tx_t& mtx) {
    uint64_t res = 0;
    std::map<uint64_t, std::vector<output_index> > outs;
    std::map<uint64_t, std::vector<size_t> > outs_mine;

    map_hash2tx_t confirmed_txs;
    get_confirmed_txs(blockchain, mtx, confirmed_txs);

    if (!init_output_indices(outs, outs_mine, blockchain, confirmed_txs, addr))
        return false;

    if (!init_spent_output_indices(outs, outs_mine, blockchain, confirmed_txs, addr))
        return false;

    BOOST_FOREACH (const map_output_t::value_type &o, outs_mine) {
        for (size_t i = 0; i < o.second.size(); ++i) {
            if (outs[o.first][o.second[i]].spent)
                continue;

            res += outs[o.first][o.second[i]].amount;
        }
    }

    return res;
}

uint64_t get_token_balance(const cryptonote::account_base& addr, const std::vector<cryptonote::block>& blockchain, const map_hash2tx_t& mtx) {
  uint64_t res = 0;
  std::map<uint64_t, std::vector<output_index> > token_outs;
  std::map<uint64_t, std::vector<size_t> > token_outs_mine;
  std::map<uint64_t, std::vector<output_index> > locked_token_outs;
  std::map<uint64_t, std::vector<output_index> > locked_token_outs_mine;

  map_hash2tx_t confirmed_txs;
  get_confirmed_txs(blockchain, mtx, confirmed_txs);

  if (!init_output_indices(token_outs, token_outs_mine, blockchain, confirmed_txs, addr, cryptonote::tx_out_type::out_token))
    return false;

  if (!init_spent_output_indices(token_outs, token_outs_mine, blockchain, confirmed_txs, addr))
    return false;

  BOOST_FOREACH (const map_output_t::value_type &o, token_outs_mine)
        {
          if (o.first == static_cast<uint8_t>(tx_out_type::out_staked_token)) continue;
          for (size_t i = 0; i < o.second.size(); ++i)
          {
            if (token_outs[o.first][o.second[i]].spent)
              continue;

            res += token_outs[o.first][o.second[i]].token_amount;
          }
        }

  return res;
}

uint64_t get_locked_token_balance(const cryptonote::account_base& addr, const std::vector<cryptonote::block>& blockchain, const map_hash2tx_t& mtx) {
  uint64_t res = 0;
  std::map<uint64_t, std::vector<output_index> > locked_token_outs;
  std::map<uint64_t, std::vector<size_t> > locked_token_outs_mine;

  map_hash2tx_t confirmed_txs;
  get_confirmed_txs(blockchain, mtx, confirmed_txs);

  if (!init_output_indices(locked_token_outs, locked_token_outs_mine, blockchain, confirmed_txs, addr, cryptonote::tx_out_type::out_staked_token))
    return false;

  if (!init_spent_output_indices(locked_token_outs, locked_token_outs_mine, blockchain, confirmed_txs, addr))
    return false;

  BOOST_FOREACH (const map_output_t::value_type &o, locked_token_outs_mine)
        {
          if (o.first != static_cast<uint8_t>(tx_out_type::out_staked_token)) continue;
          for (size_t i = 0; i < o.second.size(); ++i)
          {
            if (locked_token_outs[o.first][o.second[i]].spent)
              continue;

            res += locked_token_outs[o.first][o.second[i]].token_amount;
          }
        }

  return res;
}

void get_confirmed_txs(const std::vector<cryptonote::block>& blockchain, const map_hash2tx_t& mtx, map_hash2tx_t& confirmed_txs)
{
  std::unordered_set<crypto::hash> confirmed_hashes;
  BOOST_FOREACH(const block& blk, blockchain)
  {
    BOOST_FOREACH(const crypto::hash& tx_hash, blk.tx_hashes)
    {
      confirmed_hashes.insert(tx_hash);
    }
  }

  BOOST_FOREACH(const auto& tx_pair, mtx)
  {
    if (0 != confirmed_hashes.count(tx_pair.first))
    {
      confirmed_txs.insert(tx_pair);
    }
  }
}

bool find_block_chain(const std::vector<test_event_entry>& events, std::vector<cryptonote::block>& blockchain, map_hash2tx_t& mtx, const crypto::hash& head) {
    std::unordered_map<crypto::hash, const block*> block_index;
    BOOST_FOREACH(const test_event_entry& ev, events)
    {
        if (typeid(block) == ev.type())
        {
            const block* blk = &boost::get<block>(ev);
            block_index[get_block_hash(*blk)] = blk;
        }
        else if (typeid(transaction) == ev.type())
        {
            const transaction& tx = boost::get<transaction>(ev);
            mtx[get_transaction_hash(tx)] = &tx;
        }
    }

    bool b_success = false;
    crypto::hash id = head;
    for (auto it = block_index.find(id); block_index.end() != it; it = block_index.find(id))
    {
        blockchain.push_back(*it->second);
        id = it->second->prev_id;
        if (null_hash == id)
        {
            b_success = true;
            break;
        }
    }
    reverse(blockchain.begin(), blockchain.end());

    return b_success;
}


void test_chain_unit_base::register_callback(const std::string& cb_name, verify_callback cb)
{
  m_callbacks[cb_name] = cb;
}
bool test_chain_unit_base::verify(const std::string& cb_name, cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  auto cb_it = m_callbacks.find(cb_name);
  if(cb_it == m_callbacks.end())
  {
    LOG_ERROR("Failed to find callback " << cb_name);
    return false;
  }
  return cb_it->second(c, ev_index, events);
}



crypto::hash get_hash_from_string(const std::string hashstr) {
  //parse bitcoin transaction hash
  cryptonote::blobdata expected_bitcoin_hash_data;
  if (!epee::string_tools::parse_hexstr_to_binbuff(std::string(hashstr), expected_bitcoin_hash_data) || expected_bitcoin_hash_data.size() != sizeof(crypto::hash))
  {
    std::cerr << "failed to parse bitcoin transaction hash" << endl;
    return boost::value_initialized<crypto::hash>();
  }
  const crypto::hash bitcoin_transaction_hash = *reinterpret_cast<const crypto::hash*>(expected_bitcoin_hash_data.data());
  return bitcoin_transaction_hash;
}
