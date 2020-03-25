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

#include "chaingen.h"
#include "chain_split_safex.h"

using namespace std;

using namespace epee;
using namespace cryptonote;


gen_simple_chain_split_safex::gen_simple_chain_split_safex()
{
  REGISTER_CALLBACK("check_split_account_present_1", gen_simple_chain_split_safex::check_split_account_present_1);
  REGISTER_CALLBACK("check_split_account_present_2", gen_simple_chain_split_safex::check_split_account_present_2);
  REGISTER_CALLBACK("check_split_switched_account", gen_simple_chain_split_safex::check_split_switched_account);
  REGISTER_CALLBACK("check_split_switched_back_account", gen_simple_chain_split_safex::check_split_switched_back_account);

  m_safex_account1_keys.generate();

  safex_account_alice.username = "alice01";
  safex_account_alice.pkey = m_safex_account1_keys.get_keys().m_public_key;
  safex_account_alice.account_data = {'l','o','r','e','m',' ','i','p','s','u','m'};

}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::generate(std::vector<test_event_entry> &events) const
{
  uint64_t ts_start = 1338224400;



  GENERATE_ACCOUNT(first_miner_account);

  crypto::public_key miner_public_key = AUTO_VAL_INIT(miner_public_key);
  crypto::secret_key_to_public_key(first_miner_account.get_keys().m_spend_secret_key, miner_public_key);
  cryptonote::fakechain::set_core_tests_public_key(miner_public_key);

  //                                                                                          events index
  MAKE_GENESIS_BLOCK(events, blk_0, first_miner_account, ts_start);                           //  0
  MAKE_NEXT_BLOCK(events, blk_1, blk_0, first_miner_account);                                 //  1
  MAKE_NEXT_BLOCK(events, blk_2, blk_1, first_miner_account);                                 //  2
  MAKE_NEXT_BLOCK(events, blk_3, blk_2, first_miner_account);                                 //  3
  REWIND_BLOCKS(events, blk_3r, blk_3, first_miner_account);                                  //  63
  MAKE_TX_MIGRATION_LIST_START(events, txlist_0, first_miner_account, first_miner_account, MK_TOKENS(10000), blk_3, get_hash_from_string(bitcoin_tx_hashes_str[0])); // 64
  MAKE_NEXT_BLOCK_TX_LIST(events, blk_4, blk_3r, first_miner_account, txlist_0);              // 65
  MAKE_NEXT_BLOCK(events, blk_5, blk_4, first_miner_account);                                 // 66
  MAKE_NEXT_BLOCK(events, blk_6, blk_5, first_miner_account);                                 // 67
  MAKE_NEXT_BLOCK(events, blk_7, blk_6, first_miner_account);                                 // 68
  MAKE_NEXT_BLOCK(events, blk_8, blk_7, first_miner_account);                                 // 69
  MAKE_NEXT_BLOCK(events, blk_9, blk_8, first_miner_account);                                 // 70
  MAKE_NEXT_BLOCK(events, blk_10, blk_9, first_miner_account);                                //  71
  MAKE_NEXT_BLOCK(events, blk_11, blk_10, first_miner_account);                               //  72
  MAKE_NEXT_BLOCK(events, blk_12, blk_11, first_miner_account);                               //  73
  MAKE_NEXT_BLOCK(events, blk_13, blk_12, first_miner_account);                               //  74
  MAKE_NEXT_BLOCK(events, blk_14, blk_13, first_miner_account);                               //  75
  REWIND_BLOCKS(events, blk_14r, blk_14, first_miner_account);                                //  135
  MAKE_TX_CREATE_SAFEX_ACCOUNT_LIST_START(events, txlist_2, first_miner_account, safex_account_alice.username, safex_account_alice.pkey, safex_account_alice.account_data, m_safex_account1_keys.get_keys(), events.size()+SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_PERIOD, blk_14); // 136
  MAKE_NEXT_BLOCK_TX_LIST(events, blk_15, blk_14r, first_miner_account, txlist_2);            //  137
  MAKE_NEXT_BLOCK(events, blk_16, blk_15, first_miner_account);                               //  138     //height: 137
//  //split again and check back switching
  MAKE_NEXT_BLOCK(events, blk_17, blk_8, first_miner_account);                                //  139   //70th block
  MAKE_NEXT_BLOCK(events, blk_18, blk_17,  first_miner_account);                              //  140
  REWIND_BLOCKS(events, blk_19, blk_18, first_miner_account);                                 //  200
  MAKE_NEXT_BLOCK(events, blk_20, blk_19,  first_miner_account);                              //  201
  MAKE_NEXT_BLOCK(events, blk_21, blk_20,  first_miner_account);                              //  202
  DO_CALLBACK(events, "check_split_account_present_1");                                       //  203
  MAKE_NEXT_BLOCK(events, blk_22, blk_21, first_miner_account);                               //  204
  MAKE_NEXT_BLOCK(events, blk_23, blk_22, first_miner_account);                               //  205
  MAKE_NEXT_BLOCK(events, blk_24, blk_23, first_miner_account);                               //  206
  MAKE_NEXT_BLOCK(events, blk_25, blk_24, first_miner_account);                               //  207
  DO_CALLBACK(events, "check_split_account_present_2");                                         //  208
  MAKE_NEXT_BLOCK(events, blk_26, blk_25, first_miner_account);                               //  209
  DO_CALLBACK(events, "check_split_switched_account");                                         //  210
  MAKE_NEXT_BLOCK(events, blk_27, blk_16, first_miner_account);                               //  211
  MAKE_NEXT_BLOCK(events, blk_28, blk_27, first_miner_account);                               //  212
  DO_CALLBACK(events, "check_split_switched_back_account");                                //  213


  return true;
}

//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_account_present_1(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_account_present_1");
  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 137);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 139);
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[138])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 64);

  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_account_present_2(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_account_present_2");

  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 137);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 139);
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[138])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 68);

  std::vector<std::pair<string,string>> safex_accounts;
  CHECK_TEST_CONDITION(c.get_safex_accounts(safex_accounts));

  CHECK_TEST_CONDITION(safex_accounts.size() == 1);

  return true;
}//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_switched_account(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_switched_account");

  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 138);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 139);
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[209])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 68);

  std::vector<std::pair<string,string>> safex_accounts;
  CHECK_TEST_CONDITION(c.get_safex_accounts(safex_accounts));

  CHECK_TEST_CONDITION(safex_accounts.size() == 0);

  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_switched_back_account(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_switched_back_account");

  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 139);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 141);
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[212])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 69);

  std::vector<std::pair<string,string>> safex_accounts;
  CHECK_TEST_CONDITION(c.get_safex_accounts(safex_accounts));

  CHECK_TEST_CONDITION(safex_accounts.size() == 1);

  return true;
}
//-----------------------------------------------------------------------------------------------------



