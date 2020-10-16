// Copyright (c) 2020, The Safex Project
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

#include "chaingen.h"
#include "double_advanced_tx.h"

using namespace epee;
using namespace cryptonote;


//======================================================================================================================

gen_double_advanced_tx_in_different_chains::gen_double_advanced_tx_in_different_chains()
{
  REGISTER_CALLBACK_METHOD(gen_double_advanced_tx_in_different_chains, check_double_advanced_tx);
}

bool gen_double_advanced_tx_in_different_chains::generate(std::vector<test_event_entry>& events) const
{
  INIT_DOUBLE_ADVANCED_TX_TEST();

  SET_EVENT_VISITOR_SETT(events, event_visitor_settings::set_txs_keeped_by_block, true);
  MAKE_TOKEN_TX(events, tx_1, alice_account, bob_account, MK_TOKENS(10000), blk_1);




  std::vector<cryptonote::tx_source_entry> sources;
  std::vector<cryptonote::tx_destination_entry> destinations;

  fill_tx_sources_and_destinations(events, blk_1r, alice_account, bob_account, send_amount - TESTS_DEFAULT_FEE, TESTS_DEFAULT_FEE, 0, sources, destinations);

  auto src_cash = sources[0];
  // Remove tx_1, it is being inserted back a little later
  events.pop_back();



  fill_token_tx_sources_and_destinations(events, blk_1r, alice_account, bob_account, MK_TOKENS(10000), TESTS_DEFAULT_FEE, 0, sources, destinations);

  for(auto &se: sources){
      if(se.amount > 0){
          se = src_cash;
          break;
      }
  }

  for(auto &de: destinations){
      if(de.amount > 0){
          de.amount = send_amount - TESTS_DEFAULT_FEE;
          break;
      }
  }


  cryptonote::transaction tx_2;
  if (!construct_tx(alice_account.get_keys(), sources, destinations, alice_account.get_keys().m_account_address, std::vector<uint8_t>(), tx_2, 0))
      return false;




  // Main chain
  events.push_back(tx_1);
  MAKE_NEXT_BLOCK_TX1(events, blk_2, blk_1r, miner_account, tx_1);

  // Alternative chain
  events.push_back(tx_2);
  MAKE_NEXT_BLOCK_TX1(events, blk_3, blk_1r, miner_account, tx_2);
  // Switch to alternative chain
  MAKE_NEXT_BLOCK(events, blk_4, blk_3, miner_account);
 CHECK_AND_NO_ASSERT_MES(expected_blockchain_height == get_block_height(blk_4) + 1, false, "expected_blockchain_height has invalid value");

  DO_CALLBACK(events, "check_double_advanced_tx");

  return true;
}

bool gen_double_advanced_tx_in_different_chains::check_double_advanced_tx(cryptonote::core& c, size_t /*ev_index*/, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_double_advanced_tx_in_different_chains::check_double_advanced_tx");

  std::list<block> block_list;
  bool r = c.get_blocks(0, 100 + 2 * CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, block_list);
  CHECK_TEST_CONDITION(r);

  std::vector<block> blocks(block_list.begin(), block_list.end());
  CHECK_EQ(expected_blockchain_height, blocks.size());

  CHECK_EQ(1, c.get_pool_transactions_count());
  CHECK_EQ(1, c.get_alternative_blocks_count());

  cryptonote::account_base bob_account = boost::get<cryptonote::account_base>(events[1]);
  cryptonote::account_base alice_account = boost::get<cryptonote::account_base>(events[2]);

  std::vector<cryptonote::block> chain;
  map_hash2tx_t mtx;
  r = find_block_chain(events, chain, mtx, get_block_hash(blocks.back()));
  CHECK_TEST_CONDITION(r);

  CHECK_EQ(expected_bob_balance, get_balance(bob_account, blocks, mtx));
  CHECK_EQ(expected_alice_balance, get_balance(alice_account, blocks, mtx));
  CHECK_EQ(expected_bob_token_balance, get_token_balance(bob_account, blocks, mtx));
  CHECK_EQ(expected_alice_token_balance, get_token_balance(alice_account, blocks, mtx));

  return true;
}
