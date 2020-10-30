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

#pragma once

//======================================================================================================================

template<class concrete_test>
gen_double_advanced_tx_base<concrete_test>::gen_double_advanced_tx_base()
  : m_invalid_tx_index(invalid_index_value)
  , m_invalid_block_index(invalid_index_value)
{
  REGISTER_CALLBACK_METHOD(gen_double_advanced_tx_base<concrete_test>, mark_last_valid_block);
  REGISTER_CALLBACK_METHOD(gen_double_advanced_tx_base<concrete_test>, mark_invalid_tx);
  REGISTER_CALLBACK_METHOD(gen_double_advanced_tx_base<concrete_test>, mark_invalid_block);
  REGISTER_CALLBACK_METHOD(gen_double_advanced_tx_base<concrete_test>, check_double_advanced_tx);
}

template<class concrete_test>
bool gen_double_advanced_tx_base<concrete_test>::check_tx_verification_context(const cryptonote::tx_verification_context& tvc, bool tx_added, size_t event_idx, const cryptonote::transaction& /*tx*/)
{
  if (m_invalid_tx_index == event_idx)
    return tvc.m_verifivation_failed;
  else
    return !tvc.m_verifivation_failed && tx_added;
}

template<class concrete_test>
bool gen_double_advanced_tx_base<concrete_test>::check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& /*block*/)
{
  if (m_invalid_block_index == event_idx)
    return bvc.m_verifivation_failed;
  else
    return !bvc.m_verifivation_failed;
}

template<class concrete_test>
bool gen_double_advanced_tx_base<concrete_test>::mark_last_valid_block(cryptonote::core& c, size_t /*ev_index*/, const std::vector<test_event_entry>& /*events*/)
{
  std::list<cryptonote::block> block_list;
  bool r = c.get_blocks(c.get_current_blockchain_height() - 1, 1, block_list);
  CHECK_AND_ASSERT_MES(r, false, "core::get_blocks failed");
  m_last_valid_block = block_list.back();
  return true;
}

template<class concrete_test>
bool gen_double_advanced_tx_base<concrete_test>::mark_invalid_tx(cryptonote::core& /*c*/, size_t ev_index, const std::vector<test_event_entry>& /*events*/)
{
  m_invalid_tx_index = ev_index + 1;
  return true;
}

template<class concrete_test>
bool gen_double_advanced_tx_base<concrete_test>::mark_invalid_block(cryptonote::core& /*c*/, size_t ev_index, const std::vector<test_event_entry>& /*events*/)
{
  m_invalid_block_index = ev_index + 1;
  return true;
}

template<class concrete_test>
bool gen_double_advanced_tx_base<concrete_test>::check_double_advanced_tx(cryptonote::core& c, size_t /*ev_index*/, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_double_advanced_tx_base::check_double_advanced_tx");

  if (concrete_test::has_invalid_tx)
  {
    CHECK_NOT_EQ(invalid_index_value, m_invalid_tx_index);
  }
  CHECK_NOT_EQ(invalid_index_value, m_invalid_block_index);

  std::list<cryptonote::block> block_list;
  bool r = c.get_blocks(0, 18 + 5 * CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, block_list);
  CHECK_TEST_CONDITION(r);
  CHECK_TEST_CONDITION(m_last_valid_block == block_list.back());

  CHECK_EQ(concrete_test::expected_pool_txs_count, c.get_pool_transactions_count());

  cryptonote::account_base bob_account = boost::get<cryptonote::account_base>(events[1]);
  cryptonote::account_base alice_account = boost::get<cryptonote::account_base>(events[2]);

  std::vector<cryptonote::block> chain;
  map_hash2tx_t mtx;
  std::vector<cryptonote::block> blocks(block_list.begin(), block_list.end());
  r = find_block_chain(events, chain, mtx, get_block_hash(blocks.back()));
  CHECK_TEST_CONDITION(r);
  CHECK_EQ(concrete_test::expected_bob_balance, get_balance(bob_account, blocks, mtx));
  CHECK_EQ(concrete_test::expected_alice_balance, get_balance(alice_account, blocks, mtx));
  CHECK_EQ(concrete_test::expected_bob_token_balance, get_token_balance(bob_account, blocks, mtx));
  CHECK_EQ(concrete_test::expected_alice_token_balance, get_token_balance(alice_account, blocks, mtx));

  return true;
}

//======================================================================================================================

template<bool txs_keeped_by_block>
bool gen_double_purchase_tx_in_the_same_block<txs_keeped_by_block>::generate(std::vector<test_event_entry>& events) const
{
  INIT_DOUBLE_ADVANCED_TX_TEST();

  DO_CALLBACK(events, "mark_last_valid_block");
  SET_EVENT_VISITOR_SETT(events, event_visitor_settings::set_txs_keeped_by_block, txs_keeped_by_block);


  auto safex_alice_purchase_from_bob = safex::safex_purchase{1, safex_offer_alice.price, safex_offer_alice.offer_id, false};

  //create purchase
  MAKE_TX_CREATE_SAFEX_PURCHASE_LIST_START(events, txlist_3, alice_account, safex_alice_purchase_from_bob, alice_account.get_keys().m_account_address,  blk_1r);
  if (has_invalid_tx)
  {
      DO_CALLBACK(events, "mark_invalid_tx");
  }
  //create purchase, but the item is out of stock
  MAKE_CREATE_SAFEX_PURCHASE_TX_LIST(events, txlist_3, bob_account, safex_alice_purchase_from_bob, alice_account.get_keys().m_account_address, blk_1r);
  DO_CALLBACK(events, "mark_invalid_block");
  MAKE_NEXT_BLOCK_TX_LIST(events, blk_13, blk_1r, miner_account, txlist_3);

  DO_CALLBACK(events, "check_double_advanced_tx");

  return true;
}

template<bool txs_keeped_by_block>
bool gen_edit_offer_purchase_tx_in_the_same_block<txs_keeped_by_block>::generate(std::vector<test_event_entry>& events) const
{
  INIT_DOUBLE_ADVANCED_TX_TEST();

  DO_CALLBACK(events, "mark_last_valid_block");
  SET_EVENT_VISITOR_SETT(events, event_visitor_settings::set_txs_keeped_by_block, txs_keeped_by_block);


  auto safex_alice_purchase_from_bob = safex::safex_purchase{1, safex_offer_alice.price, safex_offer_alice.offer_id, false};

  safex_offer_alice.price += MK_COINS(10);
  safex_offer_alice.min_sfx_price += MK_COINS(10);
  //edit offer
  MAKE_TX_EDIT_SAFEX_OFFER_LIST_START(events, txlist_3, alice_account, safex_account_alice.pkey, safex_offer_alice, m_safex_account1_keys.get_keys(), blk_1r);
  if (has_invalid_tx)
  {
      DO_CALLBACK(events, "mark_invalid_tx");
  }
  //create purchase, but the item is out of stock
  MAKE_CREATE_SAFEX_PURCHASE_TX_LIST(events, txlist_3, bob_account, safex_alice_purchase_from_bob, alice_account.get_keys().m_account_address, blk_1r);
  DO_CALLBACK(events, "mark_invalid_block");
  MAKE_NEXT_BLOCK_TX_LIST(events, blk_13, blk_1r, miner_account, txlist_3);

  DO_CALLBACK(events, "check_double_advanced_tx");

  return true;
}
