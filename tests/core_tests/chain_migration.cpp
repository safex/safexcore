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

#include "include_base_utils.h"

#include "console_handler.h"

#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"

#include "chaingen.h"
#include "chain_migration.h"

using namespace std;

using namespace epee;
using namespace cryptonote;



////////
// class gen_simple_chain_migration_001;

crypto::hash gen_simple_chain_migration_001::get_hash_from_string(const std::string hashstr) {
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

gen_simple_chain_migration_001::gen_simple_chain_migration_001()
{
  REGISTER_CALLBACK("verify_migration_transactions", gen_simple_chain_migration_001::verify_migration_transactions);
}

bool gen_simple_chain_migration_001::generate(std::vector<test_event_entry> &events)
{
    uint64_t ts_start = 1530720632;

    GENERATE_ACCOUNT(miner);
    crypto::public_key miner_public_key = AUTO_VAL_INIT(miner_public_key);
    crypto::secret_key_to_public_key(miner.get_keys().m_spend_secret_key, miner_public_key);
    cryptonote::fakechain::set_core_tests_public_key(miner_public_key);
    GENERATE_ACCOUNT(miner2);

    MAKE_GENESIS_BLOCK(events, blk_0, miner, ts_start);

    MAKE_ACCOUNT(events, alice);
    MAKE_ACCOUNT(events, bob);

    MAKE_NEXT_BLOCK(events, blk_1, blk_0, miner);
    MAKE_NEXT_BLOCK(events, blk_1_side, blk_0, miner2);
    MAKE_NEXT_BLOCK(events, blk_2, blk_1, miner);

    REWIND_BLOCKS(events, blk_2r, blk_2, miner);
    MAKE_TX_MIGRATION_LIST_START(events, txlist_0, miner, alice, MK_TOKENS(1), blk_2, get_hash_from_string(bitcoin_tx_hashes_str[0]));
    MAKE_MIGRATION_TX_LIST(events, txlist_0, miner, alice, MK_TOKENS(2), blk_2, get_hash_from_string(bitcoin_tx_hashes_str[1]));
    MAKE_MIGRATION_TX_LIST(events, txlist_0, miner, alice, MK_TOKENS(4), blk_2, get_hash_from_string(bitcoin_tx_hashes_str[2]));
    MAKE_INVALID_MIGRATION_TX_LIST(events, txlist_0, miner, alice, MK_TOKENS(6), blk_2, get_hash_from_string(bitcoin_tx_hashes_str[2]));
    MAKE_INVALID_MIGRATION_TX_LIST(events, txlist_0, miner, bob, MK_TOKENS(6), blk_2, get_hash_from_string(bitcoin_tx_hashes_str[2]));
    MAKE_INVALID_MIGRATION_TX_LIST(events, txlist_0, miner2, bob, MK_TOKENS(16), blk_2, get_hash_from_string(bitcoin_tx_hashes_str[4]));
    MAKE_NEXT_BLOCK_TX_LIST(events, blk_3, blk_2r, miner, txlist_0);
    REWIND_BLOCKS(events, blk_3r, blk_3, miner);
    MAKE_MIGRATION_TX(events, tx_1, miner, bob, MK_TOKENS(50), blk_3, get_hash_from_string(bitcoin_tx_hashes_str[3]));
    MAKE_NEXT_BLOCK_TX1(events, blk_4, blk_3r, miner, tx_1);
    REWIND_BLOCKS(events, blk_4r, blk_4, miner);
    MAKE_INVALID_MIGRATION_TX(events, tx_2, miner2, bob, MK_TOKENS(70), blk_4, get_hash_from_string(bitcoin_tx_hashes_str[5]));
    if (tx_2.vin.size() > 0)
    {
      MAKE_NEXT_BLOCK_TX1(events, blk_5, blk_4r, miner2, tx_2);
      REWIND_BLOCKS(events, blk_5r, blk_5, miner);
    }


    DO_CALLBACK(events, "verify_migration_transactions");

    return true;
}

bool gen_simple_chain_migration_001::verify_migration_transactions(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_migration_001::check_migration_transactions");
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == gen_simple_chain_migration_001::expected_blockchain_height);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == gen_simple_chain_migration_001::expected_blockchain_total_transactions);

  std::list<cryptonote::block> block_list;
  bool r = c.get_blocks((uint64_t)0, gen_simple_chain_migration_001::expected_blockchain_height-1, block_list);
  CHECK_TEST_CONDITION(r);

  cryptonote::account_base alice_account = boost::get<cryptonote::account_base>(events[1]);
  cryptonote::account_base bob_account = boost::get<cryptonote::account_base>(events[2]);


  std::vector<cryptonote::block> chain;
  map_hash2tx_t mtx;
  std::vector<cryptonote::block> blocks(block_list.begin(), block_list.end());
  r = find_block_chain(events, chain, mtx, get_block_hash(blocks.back()));
  CHECK_TEST_CONDITION(r);

  cout << "check_migration_transactions: alice = " << get_balance(alice_account, blocks, mtx) << " token balance= " << get_token_balance(alice_account, blocks, mtx)  << endl;
  cout << "check_migration_transactions: bob = " << get_balance(bob_account, blocks, mtx) << " token balance= " << get_token_balance(bob_account, blocks, mtx)  << endl;

  CHECK_EQ(gen_simple_chain_migration_001::expected_bob_cash_balance, get_balance(bob_account, blocks, mtx));
  CHECK_EQ(gen_simple_chain_migration_001::expected_alice_cash_balance, get_balance(alice_account, blocks, mtx));
  CHECK_EQ(gen_simple_chain_migration_001::expected_bob_token_balance, get_token_balance(bob_account, blocks, mtx));
  CHECK_EQ(gen_simple_chain_migration_001::expected_alice_token_balance, get_token_balance(alice_account, blocks, mtx));
  return true;
}
