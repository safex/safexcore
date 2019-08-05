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

#include "safex/safex_core.h"

#include "chaingen.h"
#include "token_stake.h"



using namespace std;

using namespace epee;
using namespace cryptonote;


// class token_lock_001;

crypto::hash gen_token_lock_001::get_hash_from_string(const std::string hashstr) {
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

gen_token_lock_001::gen_token_lock_001()
{
  REGISTER_CALLBACK("verify_token_lock", gen_token_lock_001::verify_token_lock);
}

bool gen_token_lock_001::generate(std::vector<test_event_entry> &events)
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
    MAKE_ACCOUNT(events, daniel);
    MAKE_ACCOUNT(events, jack);

    MAKE_NEXT_BLOCK(events, blk_1, blk_0, miner);
    MAKE_NEXT_BLOCK(events, blk_2, blk_1, miner);

    REWIND_BLOCKS(events, blk_2r, blk_2, miner);
    MAKE_TX_MIGRATION_LIST_START(events, txlist_0, miner, alice, MK_TOKENS(200000), blk_2, get_hash_from_string(bitcoin_tx_hashes_str[0]));
    MAKE_MIGRATION_TX_LIST(events, txlist_0, miner, bob, MK_TOKENS(20000), blk_2, get_hash_from_string(bitcoin_tx_hashes_str[1]));
    MAKE_MIGRATION_TX_LIST(events, txlist_0, miner, daniel, MK_TOKENS(10000), blk_2, get_hash_from_string(bitcoin_tx_hashes_str[2]));
    MAKE_NEXT_BLOCK_TX_LIST(events, blk_3, blk_2r, miner, txlist_0);
    REWIND_BLOCKS(events, blk_4, blk_3, miner);

    //lock some tokens
    MAKE_TX_TOKEN_LOCK_LIST_START(events, txlist_1, alice, MK_TOKENS(80000), blk_4);
    MAKE_TOKEN_LOCK_TX_LIST(events, txlist_1, bob, MK_TOKENS(20000), blk_4);
    MAKE_NEXT_BLOCK_TX_LIST(events, blk_5, blk_4, miner, txlist_1);
    REWIND_BLOCKS(events, blk_6, blk_5, miner);

    MAKE_TX_TOKEN_LOCK_LIST_START(events, txlist_2, alice, MK_TOKENS(15000), blk_6);
    MAKE_NEXT_BLOCK_TX_LIST(events, blk_6r, blk_6, miner, txlist_2);

    REWIND_BLOCKS(events, blk_7, blk_6r, miner);

    MAKE_TX_TOKEN_UNLOCK_LIST_START(events, txlist_3, alice, MK_TOKENS(80000), blk_7);
    MAKE_TOKEN_LOCK_TX_LIST(events, txlist_3, daniel, MK_TOKENS(10000), blk_7);
    MAKE_NEXT_BLOCK_TX_LIST(events, blk_7r, blk_7, miner, txlist_3);

    REWIND_BLOCKS(events, blk_8, blk_7r, miner);

    MAKE_TX_TOKEN_LOCK_LIST_START(events, txlist_4, alice, MK_TOKENS(25000), blk_8);
    MAKE_TOKEN_UNLOCK_TX_LIST(events, txlist_4, bob, MK_TOKENS(20000), blk_8);
    MAKE_TOKEN_UNLOCK_TX_LIST(events, txlist_4, daniel, MK_TOKENS(10000), blk_8);
    MAKE_NEXT_BLOCK_TX_LIST(events, blk_9, blk_8, miner, txlist_4);

    DO_CALLBACK(events, "verify_token_lock");

    return true;
}

bool gen_token_lock_001::verify_token_lock(cryptonote::core &c, size_t ev_index, const std::vector<test_event_entry> &events)
{
    DEFINE_TESTS_ERROR_CONTEXT("token_lock_001::verify_network_fee");
    std::cout << "current_blockchain_height:" << c.get_current_blockchain_height() << " get_blockchain_total_transactions:" << c.get_blockchain_total_transactions() << std::endl;

    CHECK_TEST_CONDITION(c.get_current_blockchain_height() == gen_token_lock_001::expected_blockchain_height);
    CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == gen_token_lock_001::expected_blockchain_total_transactions);

    std::list<cryptonote::block> block_list;
    bool r = c.get_blocks((uint64_t)0, gen_token_lock_001::expected_blockchain_height, block_list);
    CHECK_TEST_CONDITION(r);

    cryptonote::account_base alice_account = boost::get<cryptonote::account_base>(events[1]);
    cryptonote::account_base bob_account = boost::get<cryptonote::account_base>(events[2]);
    cryptonote::account_base daniel_account = boost::get<cryptonote::account_base>(events[3]);

    std::vector<cryptonote::block> chain;
    map_hash2tx_t mtx;
    std::vector<cryptonote::block> blocks(block_list.begin(), block_list.end());
    bool re = find_block_chain(events, chain, mtx, get_block_hash(blocks.back()));
    CHECK_TEST_CONDITION(re);

    //cout << "check_token_lock_balance: cash alice = " << get_balance(alice_account, blocks, mtx) << endl;
    cout << "final alice token balance= " << print_money(get_token_balance(alice_account, blocks, mtx)) << " locked token balance= " << print_money(get_locked_token_balance(alice_account, blocks, mtx)) << endl;
    cout << "final bob token balance= " << print_money(get_token_balance(bob_account, blocks, mtx)) << " locked token balance= " << print_money(get_locked_token_balance(bob_account, blocks, mtx)) << endl;
    cout << "final daniel token balance= " << print_money(get_token_balance(daniel_account, blocks, mtx)) << " locked token balance= " << print_money(get_locked_token_balance(daniel_account, blocks, mtx)) << endl;

    int64_t locked_tokens = c.get_staked_tokens(0, gen_token_lock_001::expected_blockchain_height);
    uint64_t locked_tokens2 = c.get_staked_tokens();
    cout << "total core locked tokens: " << print_money(locked_tokens) << " currently locked tokens" << print_money(locked_tokens2) << endl;
    CHECK_EQ(static_cast<uint64_t>(locked_tokens), locked_tokens2);

    CHECK_EQ(gen_token_lock_001::expected_alice_token_balance, get_token_balance(alice_account, blocks, mtx));
    CHECK_EQ(gen_token_lock_001::expected_bob_token_balance, get_token_balance(bob_account, blocks, mtx));
    CHECK_EQ(gen_token_lock_001::expected_daniel_token_balance, get_token_balance(daniel_account, blocks, mtx));
    CHECK_EQ(gen_token_lock_001::expected_staked_tokens, c.get_staked_tokens(0, gen_token_lock_001::expected_blockchain_height));


    //todo implement condition check

    return true;
}
