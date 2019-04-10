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

using namespace cryptonote;
using epee::string_tools::pod_to_hex;

#define ASSERT_HASH_EQ(a, b) ASSERT_EQ(pod_to_hex(a), pod_to_hex(b))

namespace
{  // anonymous namespace

  const int NUMBER_OF_BLOCKS = 22;
  const uint64_t default_miner_fee = ((uint64_t) 500000000);
  const std::string bitcoin_tx_hashes_str[6] = {"3b7ac2a66eded32dcdc61f0fec7e9ddb30ccb3c6f5f06c0743c786e979130c5f", "3c904e67190d2d8c5cc93147c1a3ead133c61fc3fa578915e9bf95544705e63c",
                                                "2d825e690c4cb904556285b74a6ce565f16ba9d2f09784a7e5be5f7cdb05ae1d", "89352ec1749c872146eabddd56cd0d1492a3be6d2f9df98f6fbbc0d560120182",
                                                "80220aec436a2298bae6b35c920017d36646cda874a0516e121e658a888d2b55", "361074a34cf1723c7f797f2764b4c34a8e1584475c28503867778ca90bebbc0a"};


// if the return type (blobdata for now) of block_to_blob ever changes
// from std::string, this might break.
  bool compare_blocks(const block &a, const block &b)
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
      get_block_longhash(bl, h, height);

      if (check_hash(h, diffic))
      {
        bl.invalidate_hashes();
        return true;
      }
    }
    bl.invalidate_hashes();
    return false;
  }

  struct output_index
  {
    const cryptonote::txout_target_v out;
    uint64_t amount;
    uint64_t token_amount;
    size_t blk_height; // block height
    size_t tx_no; // index of transaction in block
    size_t out_no; // index of out in transaction
    size_t idx;
    bool spent;
    const cryptonote::block *p_blk;
    const cryptonote::transaction *p_tx;

    output_index(const cryptonote::txout_target_v &_out, uint64_t _a, uint64_t _t_a, size_t _h, size_t tno, size_t ono, const cryptonote::block *_pb, const cryptonote::transaction *_pt)
            : out(_out), amount(_a), token_amount(_t_a), blk_height(_h), tx_no(tno), out_no(ono), idx(0), spent(false), p_blk(_pb), p_tx(_pt)
    {}

    output_index(const output_index &other)
            : out(other.out), amount(other.amount), token_amount(other.token_amount), blk_height(other.blk_height), tx_no(other.tx_no), out_no(other.out_no), idx(other.idx), spent(other.spent), p_blk(other.p_blk), p_tx(other.p_tx)
    {}

    const std::string toString() const
    {
      std::stringstream ss;

      ss << "output_index{blk_height=" << blk_height
         << " tx_no=" << tx_no
         << " out_no=" << out_no
         << " amount=" << amount
         << " token_amount=" << token_amount
         << " idx=" << idx
         << " spent=" << spent
         << "}";

      return ss.str();
    }

    output_index &operator=(const output_index &other)
    {
      new(this) output_index(other);
      return *this;
    }
  };

  typedef std::unordered_map<crypto::hash, cryptonote::transaction> map_hash2tx_t;
  typedef std::map<uint64_t, std::vector<size_t> > map_output_t;
  typedef std::map<uint64_t, std::vector<output_index> > map_output_idx_t;


  template<typename T>
  class SafexBlockchainDBTest : public testing::Test
  {
    protected:
      SafexBlockchainDBTest() : m_db(new T()), m_hardfork(*m_db, 1, 0)
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
            construct_migration_tx_to_key(tx, m_miner_acc, m_users_acc[0], m_test_tokens[0], default_miner_fee, get_hash_from_string(bitcoin_tx_hashes_str[0]));
            m_txmap[get_transaction_hash(tx)] = tx;
          }
          else if (i == 2)
          {
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();                                                           \
            construct_token_tx_to_key(tx, m_users_acc[0], m_users_acc[1], 200 * SAFEX_TOKEN, default_miner_fee, 0);
            m_txmap[get_transaction_hash(tx)] = tx;

            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx2 = tx_list.back();                                                           \
            construct_tx_to_key(tx2, m_miner_acc, m_users_acc[1], 10 * SAFEX_CASH_COIN, default_miner_fee, 0);
            m_txmap[get_transaction_hash(tx2)] = tx2;
          }
          else if (i == 3)
          {
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();                                                           \
            construct_token_tx_to_key(tx, m_users_acc[0], m_users_acc[1], 100 * SAFEX_TOKEN, default_miner_fee, 0);
            m_txmap[get_transaction_hash(tx)] = tx;
          }
          else if (i == 10)
          {
            //create token lock transaction, user 0 locks 100 safex token
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();                                                           \
            construct_token_lock_transaction(tx, m_users_acc[0], m_users_acc[0], 100 * SAFEX_TOKEN, default_miner_fee, 0);
//            std::cout << "tx 10 hash: " << epee::string_tools::pod_to_hex(get_transaction_hash(tx)) << std::endl;
            m_txmap[get_transaction_hash(tx)] = tx;
          }
          else if (i == 11)
          {
            //create other token lock transaction
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();                                                           \
            construct_token_lock_transaction(tx, m_users_acc[0], m_users_acc[0], 400 * SAFEX_TOKEN, default_miner_fee, 0);
            m_txmap[get_transaction_hash(tx)] = tx;

            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx2 = tx_list.back();                                                           \
            construct_token_lock_transaction(tx2, m_users_acc[1], m_users_acc[1], 100 * SAFEX_TOKEN, default_miner_fee, 0);
            m_txmap[get_transaction_hash(tx2)] = tx2;

          }
          else if (i == 13)
          {
            //add network fee
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();                                                           \
            construct_fee_donation_transaction(tx, m_miner_acc, 2 * SAFEX_CASH_COIN, default_miner_fee, 0);
            std::cout << "tx 13 hash: " << epee::string_tools::pod_to_hex(get_transaction_hash(tx)) << std::endl;
            m_txmap[get_transaction_hash(tx)] = tx;
          }
          else if (i == 15)
          {
            //add more network fee
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();                                                           \
            construct_fee_donation_transaction(tx, m_miner_acc, 12.5 * SAFEX_CASH_COIN, default_miner_fee, 0);
            std::cout << "tx 15 hash: " << epee::string_tools::pod_to_hex(get_transaction_hash(tx)) << std::endl;
            m_txmap[get_transaction_hash(tx)] = tx;
          }
          else if (i == 17)
          {
            //token unlock transaction
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();
            construct_token_unlock_transaction(tx, m_users_acc[1], m_users_acc[1], 100 * SAFEX_TOKEN, default_miner_fee, 0); //unlock 100
            m_txmap[get_transaction_hash(tx)] = tx;
          }
          else if (i == 19)
          {
            //token lock transaction
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();
            construct_token_lock_transaction(tx, m_users_acc[1], m_users_acc[1], 200 * SAFEX_TOKEN, default_miner_fee, 0);
            m_txmap[get_transaction_hash(tx)] = tx;
          }
          else if (i == 20)
          {
            //token unlock transaction
            tx_list.resize(tx_list.size() + 1);
            cryptonote::transaction &tx = tx_list.back();
            construct_token_unlock_transaction(tx, m_users_acc[0], m_users_acc[0], 400 * SAFEX_TOKEN, default_miner_fee, 0); //unlock 400
            m_txmap[get_transaction_hash(tx)] = tx;
          }


          construct_block(blk, i, prev_hash, m_miner_acc, 0, m_test_sizes[i], tx_list);

          m_txs.push_back(std::vector<cryptonote::transaction>{tx_list.begin(), tx_list.end()});
          m_blocks.push_back(blk);
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

      tx_destination_entry create_network_fee_tx_destination(uint64_t cash_amount)
      {
        account_public_address dummy = AUTO_VAL_INIT(dummy);
        return tx_destination_entry{cash_amount, dummy, false, tx_out_type::out_network_fee};
      }

      tx_destination_entry create_locked_token_tx_destination(const cryptonote::account_base &to, uint64_t token_amount)
      {
        return tx_destination_entry{token_amount, to.get_keys().m_account_address, false, tx_out_type::out_locked_token};
      }

      bool init_output_indices(map_output_idx_t &outs, std::map<uint64_t, std::vector<size_t> > &outs_mine, const std::vector<cryptonote::block> &blockchain,
                               const cryptonote::account_base &from, cryptonote::tx_out_type out_type = cryptonote::tx_out_type::out_cash)
      {

        BOOST_FOREACH (const block &blk, blockchain)
              {
                std::vector<const transaction *> vtx;
                vtx.push_back(&blk.miner_tx);

                BOOST_FOREACH(const crypto::hash &h, blk.tx_hashes)
                      {
                        const map_hash2tx_t::const_iterator cit = m_txmap.find(h);
                        if (m_txmap.end() == cit)
                          throw std::runtime_error("block contains an unknown tx hash");

                        vtx.push_back(&cit->second);
                      }


                // TODO: add all other txes
                for (size_t i = 0; i < vtx.size(); i++)
                {
                  const transaction &tx = *vtx[i];

                  for (size_t j = 0; j < tx.vout.size(); ++j)
                  {
                    const tx_out &out = tx.vout[j];
                    const crypto::public_key &out_key = *boost::apply_visitor(cryptonote::destination_public_key_visitor(), out.target);

                    if ((out_type == cryptonote::tx_out_type::out_token) || (out_type == cryptonote::tx_out_type::out_locked_token))
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
                        if (temp.output_type == static_cast<uint8_t>(tx_out_type::out_locked_token))
                        {
                          //cast tx_out_type and use it as imaginary amount for advanced outputs
                          output_index oi(out.target, out.amount, out.token_amount, boost::get<txin_gen>(*blk.miner_tx.vin.begin()).height, i, j, &blk, vtx[i]);
                          outs[static_cast<uint64_t>(tx_out_type::out_locked_token)].push_back(oi);
                          size_t tx_global_idx = outs[static_cast<uint64_t>(tx_out_type::out_locked_token)].size() - 1;
                          outs[static_cast<uint64_t>(tx_out_type::out_locked_token)][tx_global_idx].idx = tx_global_idx;
                          // Is out to me?
                          if (is_out_to_acc(from.get_keys(), out_key, get_tx_pub_key_from_extra(tx), get_additional_tx_pub_keys_from_extra(tx), j))
                          {
                            outs_mine[static_cast<uint64_t>(tx_out_type::out_locked_token)].push_back(tx_global_idx);
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
              }


        return true;
      }


      bool init_spent_output_indices(map_output_idx_t &outs, map_output_t &outs_mine, const std::vector<cryptonote::block> &blockchain,
                                     const cryptonote::account_base &from)
      {

        BOOST_FOREACH (const map_output_t::value_type &o, outs_mine)
              {
                for (size_t i = 0; i < o.second.size(); ++i) //go through my output indexes, o.first = amount, o.second="indexes of my outputs"
                {
                  output_index &oi = outs[o.first][o.second[i]]; //full data about the utxo


                  // construct key image for this output
                  crypto::key_image img;
                  keypair in_ephemeral;
                  const crypto::public_key &out_key = *boost::apply_visitor(destination_public_key_visitor(), oi.out);
                  std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;
                  subaddresses[from.get_keys().m_account_address.m_spend_public_key] = {0, 0};
                  generate_key_image_helper(from.get_keys(), subaddresses, out_key, get_tx_pub_key_from_extra(*oi.p_tx), get_additional_tx_pub_keys_from_extra(*oi.p_tx), oi.out_no, in_ephemeral, img, hw::get_device(("default")));

                  // lookup for this key image in the events vector
                  BOOST_FOREACH(auto &tx_pair, m_txmap)
                        {
                          const transaction &tx = tx_pair.second;
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


      bool fill_output_entries(std::vector<output_index> &out_indices, size_t sender_out, size_t nmix, size_t &real_entry_idx, std::vector<tx_source_entry::output_entry> &output_entries)
      {
        if (out_indices.size() <= nmix)
          return false;

        bool sender_out_found = false;
        size_t rest = nmix;
        for (size_t i = 0; i < out_indices.size() && (0 < rest || !sender_out_found); ++i)
        {
          const output_index &oi = out_indices[i];
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

      bool fill_tx_sources(std::vector<tx_source_entry> &sources, const cryptonote::account_base &from, uint64_t value_amount, size_t nmix,
                           cryptonote::tx_out_type out_type = cryptonote::tx_out_type::out_cash)
      {
        map_output_idx_t outs;
        map_output_t outs_mine;
        if (!init_output_indices(outs, outs_mine, m_blocks, from, out_type))
          return false;

        if (!init_spent_output_indices(outs, outs_mine, m_blocks, from))
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
                      (oi.amount > 0 && (out_type == cryptonote::tx_out_type::out_token || out_type == cryptonote::tx_out_type::out_locked_token)))
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
                  else if (out_type == cryptonote::tx_out_type::out_locked_token)
                  {
                    ts.token_amount = oi.token_amount;
                    ts.referenced_output_type = cryptonote::tx_out_type::out_token;
                    ts.command_type = safex::command_t::token_lock;
                  }
                  else if (out_type == cryptonote::tx_out_type::out_network_fee)
                  {
                    ts.amount = oi.amount;
                    ts.referenced_output_type = cryptonote::tx_out_type::out_cash;
                    ts.command_type = safex::command_t::donate_network_fee;
                  }
                  else
                  {
                    throw std::runtime_error("unknown referenced output type");
                  }
                  ts.real_output_in_tx_index = oi.out_no;
                  ts.real_out_tx_key = get_tx_pub_key_from_extra(*oi.p_tx); // incoming tx public key
                  size_t realOutput;
                  if (!fill_output_entries(outs[o.first], sender_out, nmix, realOutput, ts.outputs))
                    continue;

                  ts.real_output = realOutput;

                  sources.push_back(ts);

                  if ((out_type == cryptonote::tx_out_type::out_cash) ||
                          (out_type == cryptonote::tx_out_type::out_network_fee))
                  {
                    sources_cash_amount += ts.amount;
                    sources_found = value_amount <= sources_cash_amount;
                  }
                  else if ((out_type == cryptonote::tx_out_type::out_token) ||
                           (out_type == cryptonote::tx_out_type::out_locked_token))
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

      bool fill_unlock_token_sources(std::vector<tx_source_entry> &sources, const cryptonote::account_base &from, uint64_t value_amount, size_t nmix,
                                     cryptonote::tx_out_type out_type = cryptonote::tx_out_type::out_locked_token)
      {
        map_output_idx_t outs;
        map_output_t outs_mine;
        if (!init_output_indices(outs, outs_mine, m_blocks, from, cryptonote::tx_out_type::out_locked_token))
          return false;

        if (!init_spent_output_indices(outs, outs_mine, m_blocks, from))
          return false;

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
                      || (oi.amount > 0 && (out_type == cryptonote::tx_out_type::out_token || out_type == cryptonote::tx_out_type::out_locked_token))
                      || (oi.out.type() != typeid(txout_to_script)))
                    continue;


                  const cryptonote::txout_to_script &out = boost::get<txout_to_script>(oi.out);

                  if (out.output_type != static_cast<uint8_t >(cryptonote::tx_out_type::out_locked_token))
                    continue;

                  cryptonote::tx_source_entry ts = AUTO_VAL_INIT(ts);
                  ts.token_amount = oi.token_amount;
                  ts.referenced_output_type = cryptonote::tx_out_type::out_locked_token;
                  ts.command_type = safex::command_t::token_unlock;

                  ts.real_output_in_tx_index = oi.out_no;
                  ts.real_out_tx_key = get_tx_pub_key_from_extra(*oi.p_tx); // incoming tx public key
                  size_t realOutput;
                  if (!fill_output_entries(outs[o.first], sender_out, nmix, realOutput, ts.outputs))
                    continue;

                  ts.real_output = realOutput;

                  sources_locked_token_amount = ts.token_amount;
                  sources_found = value_amount == sources_locked_token_amount;

                  if (sources_found) sources.push_back(ts);


                }

                if (sources_found)
                  break;
              }

        return sources_found;
      }

      bool fill_migration_tx_sources(std::vector<tx_source_entry> &sources, const cryptonote::account_base &from,
                                     uint64_t token_amount, uint64_t cash_airdrop_amount, const crypto::hash &bitcoin_transaction_hash)
      {
        map_output_idx_t outs;
        map_output_t outs_mine;

        if (!init_output_indices(outs, outs_mine, m_blocks, from))
          return false;

        if (!init_spent_output_indices(outs, outs_mine, m_blocks, from))
          return false;

        // Iterate in reverse is more efficiency to get cash for migration transaction
        uint64_t sources_cash_amount = 0;
        bool sources_found = false;
        BOOST_REVERSE_FOREACH(const map_output_t::value_type o, outs_mine)
              {
                for (size_t i = 0; i < o.second.size() && !sources_found; ++i)
                {
                  size_t sender_out = o.second[i];
                  const output_index &oi = outs[o.first][sender_out];
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

      uint64_t get_inputs_amount(const std::vector<tx_source_entry> &s)
      {
        uint64_t r = 0;
        BOOST_FOREACH(const tx_source_entry &e, s)
              {
                r += e.amount;
              }

        return r;
      }

      uint64_t get_inputs_token_amount(const std::vector<tx_source_entry> &s)
      {
        uint64_t r = 0;
        BOOST_FOREACH(const tx_source_entry &e, s)
              {
                r += e.token_amount;
              }

        return r;
      }


      void fill_tx_sources_and_destinations(const cryptonote::account_base &from, const cryptonote::account_base &to,
                                            uint64_t amount, uint64_t fee, size_t nmix, std::vector<tx_source_entry> &sources,
                                            std::vector<tx_destination_entry> &destinations)
      {
        sources.clear();
        destinations.clear();

        if (!fill_tx_sources(sources, from, amount + fee, nmix))
          throw std::runtime_error("couldn't fill transaction sources");

        tx_destination_entry de = create_tx_destination(to, amount);
        destinations.push_back(de);

        uint64_t cache_back = get_inputs_amount(sources) - (amount + fee);
        if (0 < cache_back)
        {
          tx_destination_entry de_change = create_tx_destination(from, cache_back);
          destinations.push_back(de_change);
        }
      }

      void fill_token_tx_sources_and_destinations(const cryptonote::account_base &from, const cryptonote::account_base &to,
                                                  uint64_t token_amount, uint64_t fee, size_t nmix, std::vector<tx_source_entry> &sources,
                                                  std::vector<tx_destination_entry> &destinations)
      {
        sources.clear();
        destinations.clear();

        //fill cache sources for fee
        if (!fill_tx_sources(sources, from, fee, nmix, cryptonote::tx_out_type::out_cash))
          throw std::runtime_error("couldn't fill transaction sources");

        //token source
        if (!fill_tx_sources(sources, from, token_amount, nmix, cryptonote::tx_out_type::out_token))
          throw std::runtime_error("couldn't fill token transaction sources");

        //token destination
        tx_destination_entry de = create_token_tx_destination(to, token_amount);
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

      void fill_migration_tx_sources_and_destinations(const cryptonote::account_base &from, const cryptonote::account_base &to,
                                                      uint64_t token_amount, uint64_t fee, std::vector<tx_source_entry> &sources,
                                                      std::vector<tx_destination_entry> &destinations, const crypto::hash &bitcoin_transaction_hash)
      {
        sources.clear();
        destinations.clear();

        const uint64_t cash_airdrop_amount = cryptonote::get_airdrop_cash(token_amount);

        if (!fill_migration_tx_sources(sources, from, token_amount, cash_airdrop_amount + fee, bitcoin_transaction_hash))
          throw std::runtime_error("couldn't fill transaction sources");

        tx_destination_entry de_cash = create_tx_destination(to, cash_airdrop_amount);
        destinations.push_back(de_cash);


        uint64_t cache_back = get_inputs_amount(sources) - (cash_airdrop_amount + fee);
        if (0 < cache_back)
        {
          tx_destination_entry de_change = create_tx_destination(from, cache_back);
          destinations.push_back(de_change);
        }

        tx_destination_entry de_token = create_token_tx_destination(to, token_amount);
        destinations.push_back(de_token);

      }

      void fill_token_lock_tx_sources_and_destinations(const cryptonote::account_base &from, const cryptonote::account_base &to,
                                                       uint64_t token_amount, uint64_t fee, size_t nmix, std::vector<tx_source_entry> &sources,
                                                       std::vector<tx_destination_entry> &destinations)
      {
        sources.clear();
        destinations.clear();

        //fill cache sources for fee
        if (!fill_tx_sources(sources, from, fee, nmix, cryptonote::tx_out_type::out_cash))
          throw std::runtime_error("couldn't fill transaction sources");

        //token source
        if (!fill_tx_sources(sources, from, token_amount, nmix, cryptonote::tx_out_type::out_locked_token))
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

      void fill_token_unlock_tx_sources_and_destinations(const cryptonote::account_base &from, const cryptonote::account_base &to,
                                                         uint64_t token_amount, uint64_t fee, size_t nmix, std::vector<tx_source_entry> &sources,
                                                         std::vector<tx_destination_entry> &destinations)
      {
        sources.clear();
        destinations.clear();

        //fill cache sources for fee
        if (!fill_tx_sources(sources, from, fee, nmix, cryptonote::tx_out_type::out_cash))
          throw std::runtime_error("couldn't fill transaction sources");

        //locked token source
        if (!fill_unlock_token_sources(sources, from, token_amount, nmix))
          throw std::runtime_error("couldn't fill token transaction sources for tokens to unlock");

        //locked token destination, there is no token change, all tokens are unlocked
        tx_destination_entry de_token = create_token_tx_destination(to, token_amount);
        destinations.push_back(de_token);

        //sender change for fee

        uint64_t cache_back = get_inputs_amount(sources) - fee;
        if (0 < cache_back)
        {
          tx_destination_entry de_change = create_tx_destination(from, cache_back);
          destinations.push_back(de_change);
        }
      }

      void fill_donation_tx_sources_and_destinations(const cryptonote::account_base &from, uint64_t cash_amount, uint64_t fee, size_t nmix,
              std::vector<tx_source_entry> &sources, std::vector<tx_destination_entry> &destinations)
      {
        sources.clear();
        destinations.clear();

        //fill cache sources for fee
        if (!fill_tx_sources(sources, from, fee+cash_amount, nmix, cryptonote::tx_out_type::out_network_fee))
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

      crypto::hash get_hash_from_string(const std::string hashstr)
      {
        //parse bitcoin transaction hash
        cryptonote::blobdata expected_bitcoin_hash_data;
        if (!epee::string_tools::parse_hexstr_to_binbuff(std::string(hashstr), expected_bitcoin_hash_data) || expected_bitcoin_hash_data.size() != sizeof(crypto::hash))
        {
          std::cerr << "failed to parse bitcoin transaction hash" << std::endl;
          return boost::value_initialized<crypto::hash>();
        }
        const crypto::hash bitcoin_transaction_hash = *reinterpret_cast<const crypto::hash *>(expected_bitcoin_hash_data.data());
        return bitcoin_transaction_hash;
      }


      bool construct_tx_to_key(cryptonote::transaction &tx, const cryptonote::account_base &from, const cryptonote::account_base &to, uint64_t amount,
                               uint64_t fee, size_t nmix)
      {
        std::vector<tx_source_entry> sources;
        std::vector<tx_destination_entry> destinations;
        fill_tx_sources_and_destinations(from, to, amount, fee, nmix, sources, destinations);

        return construct_tx(from.get_keys(), sources, destinations, from.get_keys().m_account_address, std::vector<uint8_t>(), tx, 0);
      }


      transaction construct_tx_with_fee(const block &blk_head,
                                        const account_base &acc_from, const account_base &acc_to, uint64_t amount, uint64_t fee)
      {
        transaction tx;
        construct_tx_to_key(tx, blk_head, acc_from, acc_to, amount, fee, 0);
        return tx;
      }


      bool construct_token_tx_to_key(cryptonote::transaction &tx, const cryptonote::account_base &from, const cryptonote::account_base &to,
                                     uint64_t token_amount, uint64_t fee, size_t nmix)
      {
        std::vector<tx_source_entry> sources;
        std::vector<tx_destination_entry> destinations;
        fill_token_tx_sources_and_destinations(from, to, token_amount, fee, nmix, sources, destinations);

        return construct_tx(from.get_keys(), sources, destinations, from.get_keys().m_account_address, std::vector<uint8_t>(), tx, 0);
      }

      bool construct_migration_tx_to_key(cryptonote::transaction &tx, const cryptonote::account_base &from, const cryptonote::account_base &to, uint64_t token_amount,
                                         uint64_t fee, const crypto::hash &bitcoin_hash)
      {
        std::vector<tx_source_entry> sources;
        std::vector<tx_destination_entry> destinations;
        fill_migration_tx_sources_and_destinations(from, to, token_amount, fee, sources, destinations, bitcoin_hash);

        std::vector<uint8_t> extra;
        add_bitcoin_hash_to_extra(extra, bitcoin_hash);

        return construct_tx(from.get_keys(), sources, destinations, from.get_keys().m_account_address, extra, tx, 0);
      }

      bool construct_token_lock_transaction(cryptonote::transaction &tx, const cryptonote::account_base &from, const cryptonote::account_base &to,
                                            uint64_t token_amount, uint64_t fee, size_t nmix)
      {
        std::vector<tx_source_entry> sources;
        std::vector<tx_destination_entry> destinations;
        fill_token_lock_tx_sources_and_destinations(from, to, token_amount, fee, nmix, sources, destinations);

        return construct_tx(from.get_keys(), sources, destinations, from.get_keys().m_account_address, std::vector<uint8_t>(), tx, 0);
      }

      bool construct_token_unlock_transaction(cryptonote::transaction &tx, const cryptonote::account_base &from, const cryptonote::account_base &to,
                                              uint64_t token_amount, uint64_t fee, size_t nmix)
      {
        std::vector<tx_source_entry> sources;
        std::vector<tx_destination_entry> destinations;
        fill_token_unlock_tx_sources_and_destinations(from, to, token_amount, fee, nmix, sources, destinations);

        return construct_tx(from.get_keys(), sources, destinations, from.get_keys().m_account_address, std::vector<uint8_t>(), tx, 0);
      }

      bool construct_fee_donation_transaction(cryptonote::transaction &tx, const cryptonote::account_base &from, uint64_t cash_amount, uint64_t fee, size_t nmix)
      {
        std::vector<tx_source_entry> sources;
        std::vector<tx_destination_entry> destinations;

        fill_donation_tx_sources_and_destinations(from, cash_amount, fee, nmix, sources, destinations);

        return construct_tx(from.get_keys(), sources, destinations, from.get_keys().m_account_address, std::vector<uint8_t>(), tx, 0);
      }


      bool construct_block(cryptonote::block &blk, uint64_t height, const crypto::hash &prev_id,
                           const cryptonote::account_base &miner_acc, uint64_t timestamp, uint64_t already_generated_coins,
                           std::vector<size_t> &block_sizes, const std::list<cryptonote::transaction> &tx_list, size_t &actual_block_size)
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
        BOOST_FOREACH(auto &tx, tx_list)
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
        {
          blk.timestamp++;
        }

        return true;
      }

      bool construct_block(cryptonote::block &blk, uint64_t height, const crypto::hash &prev_id, const cryptonote::account_base &miner_acc, uint64_t timestamp, size_t &block_size, std::list<cryptonote::transaction> tx_list)
      {
        std::vector<size_t> block_sizes;
        return construct_block(blk, height, prev_id, miner_acc, timestamp, 0, block_sizes, tx_list, block_size);
      }

      ~SafexBlockchainDBTest()
      {
        delete m_db;
        remove_files();
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

      void remove_files()
      {
        // remove each file the db created, making sure it starts with fname.
        for (auto &f : m_filenames)
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

      void set_prefix(const std::string &prefix)
      {
        m_prefix = prefix;
      }
  };

  using testing::Types;

  typedef Types<BlockchainLMDB> implementations;

  TYPED_TEST_CASE(SafexBlockchainDBTest, implementations);

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

    for (int i = 0; i < NUMBER_OF_BLOCKS; i++)
      ASSERT_NO_THROW(this->m_db->add_block(this->m_blocks[i], this->m_test_sizes[i], this->m_test_diffs[i], this->m_test_coins[i], this->m_test_tokens[i], this->m_txs[i]));


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

    uint64_t number_of_locked_tokens = this->m_db->get_locked_token_sum_for_interval(safex::calulate_starting_block_for_interval(0));
    ASSERT_EQ(number_of_locked_tokens, 300 * SAFEX_TOKEN); //100+400+100-100+200-400

    std::vector<uint64_t> data =  this->m_db->get_token_lock_expiry_outputs(SAFEX_DEFAULT_TOKEN_LOCK_EXPIRY_PERIOD+11);
    ASSERT_EQ(data.size(), 2);

    data =  this->m_db->get_token_lock_expiry_outputs(SAFEX_DEFAULT_TOKEN_LOCK_EXPIRY_PERIOD+15);
    ASSERT_EQ(data.size(), 0);

    data =  this->m_db->get_token_lock_expiry_outputs(SAFEX_DEFAULT_TOKEN_LOCK_EXPIRY_PERIOD+19);
    ASSERT_EQ(data.size(), 1);


    uint64_t token_lock_output_num =  this->m_db->get_num_outputs(tx_out_type::out_locked_token);
    ASSERT_EQ(token_lock_output_num, 4);

    uint64_t test_output_id = data[0]; //first tx in 11 block

    crypto::public_key pkey = this->m_db->get_output_key(tx_out_type::out_locked_token, test_output_id)[0];
    bool match = false;
    crypto::hash matching_tx_hash;

    //find pkey key in transaction output of block 19
    for (transaction& tx: this->m_txs[19])
    {
      for (tx_out out: tx.vout)
      {
        crypto::public_key check = *boost::apply_visitor(cryptonote::destination_public_key_visitor(), out.target); //get public key of first output of first tx in 11 block
        if (memcmp(pkey.data, check.data, sizeof(pkey.data)) == 0) {
          match = true;
          matching_tx_hash = tx.hash;
        }
      }
    }
    ASSERT_EQ(match, true);

    tx_out_index index1 = this->m_db->get_output_tx_and_index_from_global(test_output_id);
    ASSERT_EQ(matching_tx_hash, index1.first);


    ASSERT_THROW(this->m_db->get_output_key(tx_out_type::out_locked_token, 313), DB_ERROR);
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
    }, cryptonote::tx_out_type::out_locked_token);

    ASSERT_NO_THROW(this->m_db->close());

  }

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
      //ASSERT_NO_THROW(this->m_db->add_block(this->m_blocks[i], this->m_test_sizes[i], this->m_test_diffs[i], this->m_test_coins[i], this->m_test_tokens[i], this->m_txs[i]));
      try
      {
        this->m_db->add_block(this->m_blocks[i], this->m_test_sizes[i], this->m_test_diffs[i], this->m_test_coins[i], this->m_test_tokens[i], this->m_txs[i]);
      }
      catch (std::exception &e)
      {
        std::cout << "Error: " << e.what() << std::endl;
      }
    }

    uint64_t number_of_locked_tokens = this->m_db->get_locked_token_sum_for_interval(safex::calulate_starting_block_for_interval(0));
    ASSERT_EQ(number_of_locked_tokens, 300 * SAFEX_TOKEN); //100+400+100-100+200-400

    uint64_t fee_sum = this->m_db->get_network_fee_sum_for_interval(safex::calulate_starting_block_for_interval(0));
    ASSERT_EQ(fee_sum, 14.5 * SAFEX_CASH_COIN); // 2 + 12.5



    ASSERT_NO_THROW(this->m_db->close());

  }


}  // anonymous namespace
