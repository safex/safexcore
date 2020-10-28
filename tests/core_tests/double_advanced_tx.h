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
#include "chaingen.h"


const std::string bitcoin_tx_hashes_str1[6] = {"3b7ac2a66eded32dcdc61f0fec7e9ddb30ccb3c6f5f06c0743c786e979130c5f", "3c904e67190d2d8c5cc93147c1a3ead133c61fc3fa578915e9bf95544705e63c", "2d825e690c4cb904556285b74a6ce565f16ba9d2f09784a7e5be5f7cdb05ae1d", "89352ec1749c872146eabddd56cd0d1492a3be6d2f9df98f6fbbc0d560120182", "80220aec436a2298bae6b35c920017d36646cda874a0516e121e658a888d2b55", "361074a34cf1723c7f797f2764b4c34a8e1584475c28503867778ca90bebbc0a"};


template<class concrete_test>
class gen_double_advanced_tx_base : public test_chain_unit_base
{
public:
  static const uint64_t send_amount = FIRST_BLOCK_REWARD - TESTS_DEFAULT_FEE;

  gen_double_advanced_tx_base();

  bool check_tx_verification_context(const cryptonote::tx_verification_context& tvc, bool tx_added, size_t event_idx, const cryptonote::transaction& tx);
  bool check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& block);

  bool mark_last_valid_block(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
  bool mark_invalid_tx(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
  bool mark_invalid_block(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
  bool check_double_advanced_tx(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);

private:
  cryptonote::block m_last_valid_block;
  size_t m_invalid_tx_index;
  size_t m_invalid_block_index;
};


template<bool txs_keeped_by_block>
struct gen_double_advanced_tx_in_the_same_block : public gen_double_advanced_tx_base< gen_double_advanced_tx_in_the_same_block<txs_keeped_by_block> >
{
  static const uint64_t send_amount = MK_TOKENS(10000)*AIRDROP_TOKEN_TO_CASH_REWARD_RATE - TESTS_DEFAULT_FEE;
  static const bool has_invalid_tx = !txs_keeped_by_block;
  static const size_t expected_pool_txs_count = has_invalid_tx ? 1 : 2;
  static const uint64_t expected_bob_balance = MK_TOKENS(10000)*AIRDROP_TOKEN_TO_CASH_REWARD_RATE;
  static const uint64_t expected_alice_balance = MK_TOKENS(10000)*AIRDROP_TOKEN_TO_CASH_REWARD_RATE + send_amount - 2*TESTS_DEFAULT_FEE;
  static const uint64_t expected_bob_token_balance = MK_TOKENS(10000);
  static const uint64_t expected_alice_token_balance = MK_TOKENS(10000);

  bool generate(std::vector<test_event_entry>& events) const;
};


template<bool txs_keeped_by_block>
struct gen_double_advanced_tx_in_different_blocks : public gen_double_advanced_tx_base< gen_double_advanced_tx_in_different_blocks<txs_keeped_by_block> >
{
  static const uint64_t send_amount = MK_TOKENS(10000)*AIRDROP_TOKEN_TO_CASH_REWARD_RATE - TESTS_DEFAULT_FEE;
  static const bool has_invalid_tx = !txs_keeped_by_block;
  static const size_t expected_pool_txs_count = has_invalid_tx ? 0 : 1;
  static const uint64_t expected_bob_balance = 0;
  static const uint64_t expected_alice_balance = MK_TOKENS(10000)*AIRDROP_TOKEN_TO_CASH_REWARD_RATE + send_amount - TESTS_DEFAULT_FEE;
  static const uint64_t expected_bob_token_balance = MK_TOKENS(10000);
  static const uint64_t expected_alice_token_balance = 0;

  bool generate(std::vector<test_event_entry>& events) const;
};


template<bool txs_keeped_by_block>
struct gen_double_advanced_tx_in_alt_chain_in_the_same_block : public gen_double_advanced_tx_base< gen_double_advanced_tx_in_alt_chain_in_the_same_block<txs_keeped_by_block> >
{
  static const uint64_t send_amount = MK_TOKENS(10000)*AIRDROP_TOKEN_TO_CASH_REWARD_RATE - TESTS_DEFAULT_FEE;
  static const bool has_invalid_tx = !txs_keeped_by_block;
  static const size_t expected_pool_txs_count = has_invalid_tx ? 1 : 2;
  static const uint64_t expected_bob_balance = 0;
  static const uint64_t expected_alice_balance = MK_TOKENS(10000)*AIRDROP_TOKEN_TO_CASH_REWARD_RATE + send_amount;
  static const uint64_t expected_bob_token_balance = 0;
  static const uint64_t expected_alice_token_balance = MK_TOKENS(10000);

  bool generate(std::vector<test_event_entry>& events) const;
};


template<bool txs_keeped_by_block>
struct gen_double_advanced_tx_in_alt_chain_in_different_blocks : public gen_double_advanced_tx_base< gen_double_advanced_tx_in_alt_chain_in_different_blocks<txs_keeped_by_block> >
{
  static const uint64_t send_amount = MK_TOKENS(10000)*AIRDROP_TOKEN_TO_CASH_REWARD_RATE - TESTS_DEFAULT_FEE;
  static const bool has_invalid_tx = !txs_keeped_by_block;
  static const size_t expected_pool_txs_count = has_invalid_tx ? 1 : 2;
  static const uint64_t expected_bob_balance = 0;
  static const uint64_t expected_alice_balance = MK_TOKENS(10000)*AIRDROP_TOKEN_TO_CASH_REWARD_RATE + send_amount;
  static const uint64_t expected_bob_token_balance = 0;
  static const uint64_t expected_alice_token_balance = MK_TOKENS(10000);

  bool generate(std::vector<test_event_entry>& events) const;
};


class gen_double_advanced_tx_in_different_chains : public test_chain_unit_base
{
public:
  static const uint64_t send_amount = MK_TOKENS(10000)*AIRDROP_TOKEN_TO_CASH_REWARD_RATE - TESTS_DEFAULT_FEE;
  static const size_t expected_blockchain_height = 7 + 5 * CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW + 2;
  static const uint64_t expected_bob_balance =  MK_TOKENS(10000)*AIRDROP_TOKEN_TO_CASH_REWARD_RATE - MK_COINS(10) - TESTS_DEFAULT_FEE;
  static const uint64_t expected_alice_balance = MK_TOKENS(10000)*AIRDROP_TOKEN_TO_CASH_REWARD_RATE + send_amount + (95*(MK_COINS(10)/100)) - 2*TESTS_DEFAULT_FEE;
  static const uint64_t expected_bob_token_balance = MK_TOKENS(10000);
  static const uint64_t expected_alice_token_balance = MK_TOKENS(10000);

  gen_double_advanced_tx_in_different_chains();

  bool generate(std::vector<test_event_entry>& events) const;

  bool check_double_advanced_tx(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
};


#define INIT_DOUBLE_ADVANCED_TX_TEST()                                           \
  uint64_t ts_start = 1514764801;                                          \
  GENERATE_ACCOUNT(miner_account);                                         \
  crypto::public_key miner_public_key = AUTO_VAL_INIT(miner_public_key); \
  crypto::secret_key_to_public_key(miner_account.get_keys().m_spend_secret_key, miner_public_key); \
  cryptonote::fakechain::set_core_tests_public_key(miner_public_key); \
  safex::safex_account safex_account_alice; \
  safex::safex_account_key_handler m_safex_account1_keys; \
  m_safex_account1_keys.generate(); \
  safex_account_alice.username = "alice01"; \
  safex_account_alice.pkey = m_safex_account1_keys.get_keys().m_public_key; \
  safex_account_alice.account_data = {'l','o','r','e','m',' ','i','p','s','u','m'}; \
  MAKE_GENESIS_BLOCK(events, blk_0, miner_account, ts_start);              \
  MAKE_ACCOUNT(events, bob_account);                                       \
  MAKE_ACCOUNT(events, alice_account);                                     \
  auto safex_offer_alice = safex::safex_offer("Black Sabbath T-shirt", 1, MK_COINS(10), "Quality 100% cotton t-shirt with the heaviest band in the universe", safex_account_alice.username,alice_account.get_keys().m_view_secret_key,alice_account.get_keys().m_account_address); \
  MAKE_NEXT_BLOCK(events, blk_1s, blk_0, miner_account); \
  MAKE_NEXT_BLOCK(events, blk_2z, blk_1s, miner_account); \
  REWIND_BLOCKS(events, blk_2r, blk_2z, miner_account);                     \
  MAKE_TX_MIGRATION_LIST_START(events, txlist_0, miner_account, alice_account, MK_TOKENS(10000), blk_2z, get_hash_from_string(bitcoin_tx_hashes_str1[0])); \
  MAKE_MIGRATION_TX_LIST(events, txlist_0, miner_account, bob_account, MK_TOKENS(10000), blk_2z, get_hash_from_string(bitcoin_tx_hashes_str1[1])); \
  MAKE_NEXT_BLOCK_TX_LIST(events, blk_3z, blk_2r, miner_account, txlist_0); \
  REWIND_BLOCKS(events, blk_4z, blk_3z, miner_account); \
  MAKE_TX_CREATE_SAFEX_ACCOUNT_LIST_START(events, txlist_1, alice_account, safex_account_alice.username, safex_account_alice.pkey, safex_account_alice.account_data, m_safex_account1_keys.get_keys(), events.size() + SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_PERIOD_FAKECHAIN, blk_4z); \
  MAKE_NEXT_BLOCK_TX_LIST(events, blk_5z, blk_4z, miner_account, txlist_1); \
  MAKE_TX(events, tx_fund, miner_account, alice_account, send_amount, blk_5z);   \
  MAKE_NEXT_BLOCK_TX1(events, blk_6z, blk_5z, miner_account, tx_fund);         \
  REWIND_BLOCKS(events, blk_1, blk_6z, miner_account); \
  MAKE_TX_CREATE_SAFEX_OFFER_LIST_START(events, txlist_2, alice_account, safex_account_alice.pkey, safex_offer_alice, m_safex_account1_keys.get_keys(), blk_1); \
  MAKE_NEXT_BLOCK_TX_LIST(events, blk_br, blk_1, miner_account, txlist_2); \
  REWIND_BLOCKS(events, blk_br2, blk_br, miner_account); \
  REWIND_BLOCKS(events, blk_1r, blk_br2, miner_account);


#include "double_advanced_tx.inl"
