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
  REGISTER_CALLBACK("check_split_not_switched", gen_simple_chain_split_safex::check_split_not_switched);
  REGISTER_CALLBACK("check_split_not_switched2", gen_simple_chain_split_safex::check_split_not_switched2);
  REGISTER_CALLBACK("check_split_switched", gen_simple_chain_split_safex::check_split_switched);
  REGISTER_CALLBACK("check_split_not_switched_back", gen_simple_chain_split_safex::check_split_not_switched_back);
  REGISTER_CALLBACK("check_split_switched_back_1", gen_simple_chain_split_safex::check_split_switched_back_1);
  REGISTER_CALLBACK("check_split_switched_back_2", gen_simple_chain_split_safex::check_split_switched_back_2);
  REGISTER_CALLBACK("check_mempool_1", gen_simple_chain_split_safex::check_mempool_1);
  REGISTER_CALLBACK("check_mempool_2", gen_simple_chain_split_safex::check_mempool_2);

  m_safex_account1_keys.generate();

  safex_account_alice.username = "alice01";
  safex_account_alice.pkey = m_safex_account1_keys.get_keys().m_public_key;
  safex_account_alice.account_data = {'l','o','r','e','m',' ','i','p','s','u','m'};

}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::generate(std::vector<test_event_entry> &events) const
{
  uint64_t ts_start = 1338224400;
  /*
   1    2    3    4    5    6     7     8      9    10    11    12    13    14    15    16    17    18   19   20     21    22    23   <-- main blockchain height
  (0 )-(1 )-(2 )-(3 )-(4 )-(5 ) -(6 ) -(7 ) -(8 )|-(17) -(18) -(19) -(20) -(21)|-(22)|-(23)|-(24)|
                              \ -(9 ) -(10)|-(11)|-(12)|-(13) -(14) -(15) -(16)       
                                                                                      -(25) -(26)|
                                                                                -(27)|             #check switching to alternative
                                                              ----------------------------------------------------------------------------------
                                                                                      -(28) -(29) -(30) -(31)|
                                                                                -(32)|              #check switching orphans to main
                                                              ----------------------------------------------------------------------------------
                                                                                      -(33) -(34)       -(35) -(36)       -(37) -(38)|
                                                                                -(39)|           #<--this part becomes alternative chain connected to main
                                                                                                                    -(40)|  #still marked as orphaned 
                                                                                                  -(41)|
                                                                                                   #check orphaned with block in the middle of the orphaned chain 
  */



  GENERATE_ACCOUNT(first_miner_account);

  crypto::public_key miner_public_key = AUTO_VAL_INIT(miner_public_key);
  crypto::secret_key_to_public_key(first_miner_account.get_keys().m_spend_secret_key, miner_public_key);
  cryptonote::fakechain::set_core_tests_public_key(miner_public_key);

  //                                                                                          events index
  MAKE_GENESIS_BLOCK(events, blk_0, first_miner_account, ts_start);                           //  0
  MAKE_NEXT_BLOCK(events, blk_1, blk_0, first_miner_account);                                 //  1
  MAKE_NEXT_BLOCK(events, blk_2, blk_1, first_miner_account);                                 //  2
  MAKE_NEXT_BLOCK(events, blk_3, blk_2, first_miner_account);
  REWIND_BLOCKS(events, blk_3r, blk_3, first_miner_account);  //  3
  MAKE_TX_MIGRATION_LIST_START(events, txlist_0, first_miner_account, first_miner_account, MK_TOKENS(10000), blk_3, get_hash_from_string(bitcoin_tx_hashes_str[0]));
  MAKE_NEXT_BLOCK_TX_LIST(events, blk_4, blk_3r, first_miner_account, txlist_0);
  MAKE_NEXT_BLOCK(events, blk_5, blk_4, first_miner_account);                                 //  5
  MAKE_NEXT_BLOCK(events, blk_6, blk_5, first_miner_account);                                 //  6
  MAKE_NEXT_BLOCK(events, blk_7, blk_6, first_miner_account);                                 //  7
  MAKE_NEXT_BLOCK(events, blk_8, blk_7, first_miner_account);                                 //  8
  //split
  MAKE_NEXT_BLOCK(events, blk_9, blk_5, first_miner_account);                                 //  9
  MAKE_NEXT_BLOCK(events, blk_10, blk_9, first_miner_account);                                //  10
  DO_CALLBACK(events, "check_split_not_switched");                                            //  11
  MAKE_NEXT_BLOCK(events, blk_11, blk_10, first_miner_account);                               //  12
  DO_CALLBACK(events, "check_split_not_switched2");                                           //  13
  MAKE_NEXT_BLOCK(events, blk_12, blk_11, first_miner_account);                               //  14
  DO_CALLBACK(events, "check_split_switched");                                                //  15
  MAKE_NEXT_BLOCK(events, blk_13, blk_12, first_miner_account);                               //  16
  MAKE_NEXT_BLOCK(events, blk_14, blk_13, first_miner_account);
  REWIND_BLOCKS(events, blk_14r, blk_14, first_miner_account);  //  3
  MAKE_TX_CREATE_SAFEX_ACCOUNT_LIST_START(events, txlist_2, first_miner_account, safex_account_alice.username, safex_account_alice.pkey, safex_account_alice.account_data, m_safex_account1_keys.get_keys(), events.size()+SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_PERIOD, blk_14);
  MAKE_NEXT_BLOCK_TX_LIST(events, blk_15, blk_14r, first_miner_account, txlist_2);
  MAKE_NEXT_BLOCK(events, blk_16, blk_15, first_miner_account);                               //  19
//  //split again and check back switching
  MAKE_NEXT_BLOCK(events, blk_17, blk_8, first_miner_account);                                //  20
  MAKE_NEXT_BLOCK(events, blk_18, blk_17,  first_miner_account);                              //  21
  REWIND_BLOCKS(events, blk_19, blk_18, first_miner_account);
  MAKE_NEXT_BLOCK(events, blk_20, blk_19,  first_miner_account);                              //  23
  MAKE_NEXT_BLOCK(events, blk_21, blk_20,  first_miner_account);                              //  24
  DO_CALLBACK(events, "check_split_not_switched_back");                                       //  25
  MAKE_NEXT_BLOCK(events, blk_22, blk_21, first_miner_account);                               //  26
  DO_CALLBACK(events, "check_split_switched_back_1");                                         //  27
  MAKE_NEXT_BLOCK(events, blk_23, blk_22, first_miner_account);                               //  28
  DO_CALLBACK(events, "check_split_switched_back_2");                                         //  29


  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_mempool_2(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_mempool_2");
  CHECK_TEST_CONDITION(c.get_pool_transactions_count() == 2);
  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_mempool_1(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_mempool_1");
  CHECK_TEST_CONDITION(c.get_pool_transactions_count() == 3);
  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_not_switched(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_not_switched");
  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 69);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 70);

  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[69])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 2);
  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_not_switched2(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_not_switched2");
  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 69);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 70);
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[69])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 3);
  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_switched(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_switched");

  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 70);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 71);
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[75])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 3);
  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_not_switched_back(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_not_switched_back");
  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 134);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 136);
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[141])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 67);

  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_switched_back_1(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_switched_back_1");

  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 134);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 136);
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[141])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 68);

  std::vector<std::pair<string,string>> safex_accounts;
  CHECK_TEST_CONDITION(c.get_safex_accounts(safex_accounts));

  CHECK_TEST_CONDITION(safex_accounts.size() == 1);

  return true;
}//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_switched_back_2(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_switched_back_2");

  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 135);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 136);
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[209])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 68);

  std::vector<std::pair<string,string>> safex_accounts;
  CHECK_TEST_CONDITION(c.get_safex_accounts(safex_accounts));

  CHECK_TEST_CONDITION(safex_accounts.size() == 0);

  return true;
}
//-----------------------------------------------------------------------------------------------------



