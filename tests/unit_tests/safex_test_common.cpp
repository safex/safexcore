//
// Created by amarko on 19.4.19..
//

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
bool find_nonce_for_given_block(block &bl, const difficulty_type &diffic, uint64_t height)
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
  return tx_destination_entry{token_amount, to.get_keys().m_account_address, false, tx_out_type::out_staked_token};
}



bool init_output_indices(map_hash2tx_t &txmap, map_output_idx_t &outs, std::map<uint64_t, std::vector<size_t> > &outs_mine, const std::vector<cryptonote::block> &blockchain,
                         const cryptonote::account_base &from, cryptonote::tx_out_type out_type)
{

  BOOST_FOREACH (const block &blk, blockchain)
        {
          std::vector<const transaction *> vtx;
          vtx.push_back(&blk.miner_tx);

          BOOST_FOREACH(const crypto::hash &h, blk.tx_hashes)
                {
                  const map_hash2tx_t::const_iterator cit = txmap.find(h);
                  if (txmap.end() == cit)
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

              if ((out_type == cryptonote::tx_out_type::out_token) || (out_type == cryptonote::tx_out_type::out_staked_token))
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
                  if (temp.output_type == static_cast<uint8_t>(tx_out_type::out_staked_token))
                  {
                    //cast tx_out_type and use it as imaginary amount for advanced outputs
                    output_index oi(out.target, out.amount, out.token_amount, boost::get<txin_gen>(*blk.miner_tx.vin.begin()).height, i, j, &blk, vtx[i]);
                    outs[static_cast<uint64_t>(tx_out_type::out_staked_token)].push_back(oi);
                    size_t tx_global_idx = outs[static_cast<uint64_t>(tx_out_type::out_staked_token)].size() - 1;
                    outs[static_cast<uint64_t>(tx_out_type::out_staked_token)][tx_global_idx].idx = tx_global_idx;
                    // Is out to me?
                    if (is_out_to_acc(from.get_keys(), out_key, get_tx_pub_key_from_extra(tx), get_additional_tx_pub_keys_from_extra(tx), j))
                    {
                      outs_mine[static_cast<uint64_t>(tx_out_type::out_staked_token)].push_back(tx_global_idx);
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


bool init_spent_output_indices(map_hash2tx_t &txmap, map_output_idx_t &outs, map_output_t &outs_mine, const std::vector<cryptonote::block> &blockchain,
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
            BOOST_FOREACH(auto &tx_pair, txmap)
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


bool fill_unlock_token_sources(map_hash2tx_t &txmap, std::vector<block> &blocks,  std::vector<tx_source_entry> &sources, const cryptonote::account_base &from, uint64_t value_amount, size_t nmix,
                               cryptonote::tx_out_type out_type)
{
  map_output_idx_t outs;
  map_output_t outs_mine;
  if (!init_output_indices(txmap, outs, outs_mine, blocks, from, cryptonote::tx_out_type::out_staked_token))
    return false;

  if (!init_spent_output_indices(txmap, outs, outs_mine, blocks, from))
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




bool fill_migration_tx_sources(map_hash2tx_t &txmap, std::vector<block> &blocks, std::vector<tx_source_entry> &sources, const cryptonote::account_base &from,
                               uint64_t token_amount, uint64_t cash_airdrop_amount, const crypto::hash &bitcoin_transaction_hash)
{
  map_output_idx_t outs;
  map_output_t outs_mine;

  if (!init_output_indices(txmap, outs, outs_mine, blocks, from))
    return false;

  if (!init_spent_output_indices(txmap, outs, outs_mine, blocks, from))
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

void fill_migration_tx_sources_and_destinations(map_hash2tx_t &txmap,  std::vector<block> &blocks,  const cryptonote::account_base &from, const cryptonote::account_base &to,
                                                uint64_t token_amount, uint64_t fee, std::vector<tx_source_entry> &sources,
                                                std::vector<tx_destination_entry> &destinations, const crypto::hash &bitcoin_transaction_hash)
{
  sources.clear();
  destinations.clear();

  const uint64_t cash_airdrop_amount = cryptonote::get_airdrop_cash(token_amount);

  if (!fill_migration_tx_sources(txmap,blocks, sources, from, token_amount, cash_airdrop_amount + fee, bitcoin_transaction_hash))
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

bool fill_tx_sources(map_hash2tx_t &txmap,  std::vector<block> &blocks,std::vector<tx_source_entry> &sources, const cryptonote::account_base &from, uint64_t value_amount, size_t nmix,
                     cryptonote::tx_out_type out_type = cryptonote::tx_out_type::out_cash)
{
  map_output_idx_t outs;
  map_output_t outs_mine;
  if (!init_output_indices(txmap, outs, outs_mine, blocks, from, out_type))
    return false;

  if (!init_spent_output_indices(txmap, outs, outs_mine, blocks, from))
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
                     (out_type == cryptonote::tx_out_type::out_staked_token))
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

void fill_token_unlock_tx_sources_and_destinations(map_hash2tx_t &txmap,  std::vector<block> &blocks, const cryptonote::account_base &from, const cryptonote::account_base &to,
                                                   uint64_t token_amount, uint64_t fee, size_t nmix, std::vector<tx_source_entry> &sources,
                                                   std::vector<tx_destination_entry> &destinations)
{
  sources.clear();
  destinations.clear();

  //fill cache sources for fee
  if (!fill_tx_sources(txmap, blocks, sources, from, fee, nmix, cryptonote::tx_out_type::out_cash))
    throw std::runtime_error("couldn't fill transaction sources");

  //locked token source
  if (!fill_unlock_token_sources(txmap, blocks, sources, from, token_amount, nmix))
    throw std::runtime_error("couldn't fill token transaction sources for tokens to unlock");

  //interest calculation should go here, that will be tested in core tests


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

void fill_tx_sources_and_destinations(map_hash2tx_t &txmap,  std::vector<block> &blocks, const cryptonote::account_base &from, const cryptonote::account_base &to,
                                      uint64_t amount, uint64_t fee, size_t nmix, std::vector<tx_source_entry> &sources,
                                      std::vector<tx_destination_entry> &destinations)
{
  sources.clear();
  destinations.clear();

  if (!fill_tx_sources(txmap, blocks, sources, from, amount + fee, nmix))
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

void fill_token_tx_sources_and_destinations(map_hash2tx_t &txmap,  std::vector<block> &blocks, const cryptonote::account_base &from, const cryptonote::account_base &to,
                                            uint64_t token_amount, uint64_t fee, size_t nmix, std::vector<tx_source_entry> &sources,
                                            std::vector<tx_destination_entry> &destinations)
{
  sources.clear();
  destinations.clear();

  //fill cache sources for fee
  if (!fill_tx_sources(txmap, blocks, sources, from, fee, nmix, cryptonote::tx_out_type::out_cash))
    throw std::runtime_error("couldn't fill transaction sources");

  //token source
  if (!fill_tx_sources(txmap, blocks, sources, from, token_amount, nmix, cryptonote::tx_out_type::out_token))
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


void fill_token_lock_tx_sources_and_destinations(map_hash2tx_t &txmap,  std::vector<block> &blocks, const cryptonote::account_base &from, const cryptonote::account_base &to,
                                                 uint64_t token_amount, uint64_t fee, size_t nmix, std::vector<tx_source_entry> &sources,
                                                 std::vector<tx_destination_entry> &destinations)
{
  sources.clear();
  destinations.clear();

  //fill cache sources for fee
  if (!fill_tx_sources(txmap, blocks, sources, from, fee, nmix, cryptonote::tx_out_type::out_cash))
    throw std::runtime_error("couldn't fill transaction sources");

  //token source
  if (!fill_tx_sources(txmap, blocks, sources, from, token_amount, nmix, cryptonote::tx_out_type::out_staked_token))
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

uint64_t get_inputs_amount(const std::vector<cryptonote::tx_source_entry> &s)
{
  uint64_t r = 0;
  BOOST_FOREACH(const tx_source_entry &e, s)
        {
          r += e.amount;
        }

  return r;
}



void fill_donation_tx_sources_and_destinations(map_hash2tx_t &txmap,  std::vector<block> &blocks, const cryptonote::account_base &from, uint64_t cash_amount, uint64_t fee, size_t nmix,
                                               std::vector<tx_source_entry> &sources, std::vector<tx_destination_entry> &destinations)
{
  sources.clear();
  destinations.clear();

  //fill cache sources for fee
  if (!fill_tx_sources(txmap, blocks, sources, from, fee+cash_amount, nmix, cryptonote::tx_out_type::out_network_fee))
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


bool construct_tx_to_key(map_hash2tx_t &txmap,  std::vector<block> &blocks, cryptonote::transaction &tx, const cryptonote::account_base &from, const cryptonote::account_base &to, uint64_t amount,
                         uint64_t fee, size_t nmix)
{
  std::vector<tx_source_entry> sources;
  std::vector<tx_destination_entry> destinations;
  fill_tx_sources_and_destinations(txmap, blocks, from, to, amount, fee, nmix, sources, destinations);

  return construct_tx(from.get_keys(), sources, destinations, from.get_keys().m_account_address, std::vector<uint8_t>(), tx, 0);
}

bool construct_token_tx_to_key(map_hash2tx_t &txmap,  std::vector<cryptonote::block> &blocks, cryptonote::transaction &tx, const cryptonote::account_base &from, const cryptonote::account_base &to,
                               uint64_t token_amount, uint64_t fee, size_t nmix)
{
  std::vector<tx_source_entry> sources;
  std::vector<tx_destination_entry> destinations;
  fill_token_tx_sources_and_destinations(txmap, blocks, from, to, token_amount, fee, nmix, sources, destinations);

  return construct_tx(from.get_keys(), sources, destinations, from.get_keys().m_account_address, std::vector<uint8_t>(), tx, 0);
}

bool construct_migration_tx_to_key(map_hash2tx_t &txmap,  std::vector<cryptonote::block> &blocks, cryptonote::transaction &tx, const cryptonote::account_base &from, const cryptonote::account_base &to, uint64_t token_amount,
                                   uint64_t fee, const crypto::hash &bitcoin_hash)
{
  std::vector<tx_source_entry> sources;
  std::vector<tx_destination_entry> destinations;
  fill_migration_tx_sources_and_destinations(txmap, blocks, from, to, token_amount, fee, sources, destinations, bitcoin_hash);

  std::vector<uint8_t> extra;
  add_bitcoin_hash_to_extra(extra, bitcoin_hash);

  return construct_tx(from.get_keys(), sources, destinations, from.get_keys().m_account_address, extra, tx, 0);
}

bool construct_token_lock_transaction(map_hash2tx_t &txmap,  std::vector<cryptonote::block> &blocks, cryptonote::transaction &tx, const cryptonote::account_base &from, const cryptonote::account_base &to,
                                      uint64_t token_amount, uint64_t fee, size_t nmix)
{
  std::vector<tx_source_entry> sources;
  std::vector<tx_destination_entry> destinations;
  fill_token_lock_tx_sources_and_destinations(txmap, blocks, from, to, token_amount, fee, nmix, sources, destinations);

  return construct_tx(from.get_keys(), sources, destinations, from.get_keys().m_account_address, std::vector<uint8_t>(), tx, 0);
}

bool construct_token_unlock_transaction(map_hash2tx_t &txmap,  std::vector<cryptonote::block> &blocks, cryptonote::transaction &tx,
        const cryptonote::account_base &from, const cryptonote::account_base &to, uint64_t token_amount, uint64_t fee, size_t nmix)
{
  std::vector<tx_source_entry> sources;
  std::vector<tx_destination_entry> destinations;
  fill_token_unlock_tx_sources_and_destinations(txmap, blocks, from, to, token_amount, fee, nmix, sources, destinations);

  return construct_tx(from.get_keys(), sources, destinations, from.get_keys().m_account_address, std::vector<uint8_t>(), tx, 0);
}

bool construct_fee_donation_transaction(map_hash2tx_t &txmap,  std::vector<cryptonote::block> &blocks, cryptonote::transaction &tx,
        const cryptonote::account_base &from, uint64_t cash_amount, uint64_t fee, size_t nmix)
{
  std::vector<tx_source_entry> sources;
  std::vector<tx_destination_entry> destinations;

  fill_donation_tx_sources_and_destinations(txmap, blocks, from, cash_amount, fee, nmix, sources, destinations);

  return construct_tx(from.get_keys(), sources, destinations, from.get_keys().m_account_address, std::vector<uint8_t>(), tx, 0);
}


uint64_t get_inputs_token_amount(const std::vector<cryptonote::tx_source_entry> &s)
{
  uint64_t r = 0;
  BOOST_FOREACH(const tx_source_entry &e, s)
        {
          r += e.token_amount;
        }

  return r;
}
