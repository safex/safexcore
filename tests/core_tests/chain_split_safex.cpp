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

bool gen_simple_chain_split_safex::expected_data_fields_intialized{false};
const std::string gen_simple_chain_split_safex::data_alternative{"Edited account"};

uint64_t  gen_simple_chain_split_safex::expected_network_fee;
uint64_t  gen_simple_chain_split_safex::expected_alice_balance;
uint64_t  gen_simple_chain_split_safex::expected_bob_balance;

safex::safex_offer gen_simple_chain_split_safex::expected_alice_safex_offer;
safex::safex_offer gen_simple_chain_split_safex::expected_alice_safex_offer_edited;
safex::safex_price_peg gen_simple_chain_split_safex::expected_alice_safex_price_peg;
safex::safex_price_peg gen_simple_chain_split_safex::expected_alice_safex_price_peg_edited;

gen_simple_chain_split_safex::gen_simple_chain_split_safex()
{
  REGISTER_CALLBACK("check_split_account_present_1", gen_simple_chain_split_safex::check_split_account_present_1);
  REGISTER_CALLBACK("check_split_account_present_2", gen_simple_chain_split_safex::check_split_account_present_2);
  REGISTER_CALLBACK("check_split_switched_account", gen_simple_chain_split_safex::check_split_switched_account);
  REGISTER_CALLBACK("check_split_switched_back_account", gen_simple_chain_split_safex::check_split_switched_back_account);
  REGISTER_CALLBACK("check_split_account_edit_1", gen_simple_chain_split_safex::check_split_account_edit_1);
  REGISTER_CALLBACK("check_split_switched_account_edit", gen_simple_chain_split_safex::check_split_switched_account_edit);
  REGISTER_CALLBACK("check_split_switched_back_account_edit", gen_simple_chain_split_safex::check_split_switched_back_account_edit);
  REGISTER_CALLBACK("check_split_offer_present_1", gen_simple_chain_split_safex::check_split_offer_present_1);
  REGISTER_CALLBACK("check_split_switched_offer", gen_simple_chain_split_safex::check_split_switched_offer);
  REGISTER_CALLBACK("check_split_switched_back_offer", gen_simple_chain_split_safex::check_split_switched_back_offer);
  REGISTER_CALLBACK("check_split_offer_edit_1", gen_simple_chain_split_safex::check_split_offer_edit_1);
  REGISTER_CALLBACK("check_split_switched_offer_edit", gen_simple_chain_split_safex::check_split_switched_offer_edit);
  REGISTER_CALLBACK("check_split_switched_back_offer_edit", gen_simple_chain_split_safex::check_split_switched_back_offer_edit);
  REGISTER_CALLBACK("check_split_price_peg_present_1", gen_simple_chain_split_safex::check_split_price_peg_present_1);
  REGISTER_CALLBACK("check_split_switched_price_peg", gen_simple_chain_split_safex::check_split_switched_price_peg);
  REGISTER_CALLBACK("check_split_switched_back_price_peg", gen_simple_chain_split_safex::check_split_switched_back_price_peg);
  REGISTER_CALLBACK("check_split_price_peg_edit_1", gen_simple_chain_split_safex::check_split_price_peg_edit_1);
  REGISTER_CALLBACK("check_split_switched_price_peg_edit", gen_simple_chain_split_safex::check_split_switched_price_peg_edit);
  REGISTER_CALLBACK("check_split_switched_back_price_peg_edit", gen_simple_chain_split_safex::check_split_switched_back_price_peg_edit);

  m_safex_account1_keys.generate();

  first_miner_account.generate();

  safex_account_alice.username = "alice01";
  safex_account_alice.pkey = m_safex_account1_keys.get_keys().m_public_key;
  safex_account_alice.account_data = {'l','o','r','e','m',' ','i','p','s','u','m'};
  safex_offer_alice = safex::safex_offer("Black Sabbath T-shirt",100,MK_COINS(10),"Quality 100% cotton t-shirt with the heaviest band in the universe",
                                         safex_account_alice.username,first_miner_account.get_keys().m_view_secret_key,first_miner_account.get_keys().m_account_address);

  safex_offer_alice_edited = safex_offer_alice;

  safex_offer_alice_edited.min_sfx_price = MK_COINS(200);
  safex_offer_alice_edited.price = MK_COINS(200);
  safex_offer_alice_edited.description = {'s','u','p','e','r'};
  safex_offer_alice_edited.quantity = 85;

  safex_price_peg_alice = safex::safex_price_peg{"Alice price peg",safex_account_alice.username,"USD","USD to SFX price peg",30};

  safex_price_peg_alice_edited = safex_price_peg_alice;

  safex_price_peg_alice_edited.rate = 37;

  if (!expected_data_fields_intialized)
  {

    expected_alice_balance = 0;
    expected_bob_balance = 0;
    expected_network_fee = 0;

    expected_alice_balance += MK_TOKENS(10000)*AIRDROP_TOKEN_TO_CASH_REWARD_RATE;
    expected_alice_balance -= 5*TESTS_DEFAULT_FEE;


    expected_data_fields_intialized = true;
    expected_alice_safex_offer = safex_offer_alice;
    expected_alice_safex_offer_edited = safex_offer_alice_edited;
    expected_alice_safex_price_peg = safex_price_peg_alice;
    expected_alice_safex_price_peg_edited = safex_price_peg_alice_edited;

  }
}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::generate(std::vector<test_event_entry> &events) const
{
  uint64_t ts_start = 1338224400;

  crypto::public_key miner_public_key = AUTO_VAL_INIT(miner_public_key);
  crypto::secret_key_to_public_key(first_miner_account.get_keys().m_spend_secret_key, miner_public_key);
  cryptonote::fakechain::set_core_tests_public_key(miner_public_key);

  MAKE_GENESIS_BLOCK(events, blk_0, first_miner_account, ts_start);                           //  0

  MAKE_ACCOUNT(events, alice_account);
  MAKE_ACCOUNT(events, bob_account);                                                          // All events + 2
  MAKE_NEXT_BLOCK(events, blk_1, blk_0, first_miner_account);                                 //  1
  MAKE_NEXT_BLOCK(events, blk_2, blk_1, first_miner_account);                                 //  2
  MAKE_NEXT_BLOCK(events, blk_3, blk_2, first_miner_account);                                 //  3
  REWIND_BLOCKS(events, blk_3r, blk_3, first_miner_account);                                  //  63
  MAKE_TX_MIGRATION_LIST_START(events, txlist_0, first_miner_account, alice_account, MK_TOKENS(10000), blk_3, get_hash_from_string(bitcoin_tx_hashes_str[0])); // 64
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

  // Create safex account

  REWIND_BLOCKS(events, blk_14r, blk_14, first_miner_account);                                //  135
  MAKE_TX_CREATE_SAFEX_ACCOUNT_LIST_START(events, txlist_1, alice_account, safex_account_alice.username, safex_account_alice.pkey, safex_account_alice.account_data, m_safex_account1_keys.get_keys(), events.size()+SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_PERIOD, blk_14); // 136
  MAKE_NEXT_BLOCK_TX_LIST(events, blk_15, blk_14r, first_miner_account, txlist_1);            //  137
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

  // Edit safex account

  REWIND_BLOCKS(events, blk_28r, blk_28, first_miner_account);                                //  273
  MAKE_TX_EDIT_SAFEX_ACCOUNT_LIST_START(events, txlist_2, alice_account, safex_account_alice.username, std::vector<uint8_t>(data_alternative.begin(), data_alternative.end()), m_safex_account1_keys.get_keys(), blk_28); // 274
  MAKE_NEXT_BLOCK_TX_LIST(events, blk_29, blk_28r, first_miner_account, txlist_2);            //  275
  DO_CALLBACK(events, "check_split_account_edit_1");                                 //  276
  //  //split again and check back switching
  MAKE_NEXT_BLOCK(events, blk_30, blk_27, first_miner_account);                               //  277
  MAKE_NEXT_BLOCK(events, blk_31, blk_30, first_miner_account);                               //  278
  REWIND_BLOCKS(events, blk_31r, blk_31, first_miner_account);                                //  338
  MAKE_NEXT_BLOCK(events, blk_32, blk_31r, first_miner_account);                              //  339
  DO_CALLBACK(events, "check_split_switched_account_edit");                         //  340
  MAKE_NEXT_BLOCK(events, blk_33, blk_29, first_miner_account);                               //  341
  MAKE_NEXT_BLOCK(events, blk_34, blk_33, first_miner_account);                               //  342
  DO_CALLBACK(events, "check_split_switched_back_account_edit");                     //  343

  // Create safex offer

  REWIND_BLOCKS(events, blk_34r, blk_34, first_miner_account);                                //  403
  MAKE_TX_CREATE_SAFEX_OFFER_LIST_START(events, txlist_3, alice_account, safex_account_alice.pkey, safex_offer_alice, m_safex_account1_keys.get_keys(), blk_34); // 404
  MAKE_NEXT_BLOCK_TX_LIST(events, blk_35, blk_34r, first_miner_account, txlist_3);            //  405
  DO_CALLBACK(events, "check_split_offer_present_1");                                //  406
  //  //split again and check back switching
  MAKE_NEXT_BLOCK(events, blk_36, blk_33, first_miner_account);                               //  407
  MAKE_NEXT_BLOCK(events, blk_37, blk_36, first_miner_account);                               //  408
  REWIND_BLOCKS(events, blk_37r, blk_37, first_miner_account);                                //  468
  MAKE_NEXT_BLOCK(events, blk_38, blk_37r, first_miner_account);                              //  469
  DO_CALLBACK(events, "check_split_switched_offer");                                //  470
  MAKE_NEXT_BLOCK(events, blk_39, blk_35, first_miner_account);                               //  471
  MAKE_NEXT_BLOCK(events, blk_40, blk_39, first_miner_account);                               //  472
  DO_CALLBACK(events, "check_split_switched_back_offer");                           //  473

  // Edit safex offer

  REWIND_BLOCKS(events, blk_40r, blk_40, first_miner_account);                                //  533
  MAKE_TX_EDIT_SAFEX_OFFER_LIST_START(events, txlist_4, alice_account, safex_account_alice.pkey, safex_offer_alice_edited, m_safex_account1_keys.get_keys(), blk_40); // 534
  MAKE_NEXT_BLOCK_TX_LIST(events, blk_41, blk_40r, first_miner_account, txlist_4);            //  535
  DO_CALLBACK(events, "check_split_offer_edit_1");                                  //  536
  //  //split again and check back switching
  MAKE_NEXT_BLOCK(events, blk_42, blk_39, first_miner_account);                               //  537
  MAKE_NEXT_BLOCK(events, blk_43, blk_42, first_miner_account);                               //  538
  REWIND_BLOCKS(events, blk_43r, blk_43, first_miner_account);                                //  598
  MAKE_NEXT_BLOCK(events, blk_44, blk_43r, first_miner_account);                              //  599
  DO_CALLBACK(events, "check_split_switched_offer_edit");                            //  600
  MAKE_NEXT_BLOCK(events, blk_45, blk_41, first_miner_account);                               //  601
  MAKE_NEXT_BLOCK(events, blk_46, blk_45, first_miner_account);                               //  602
  DO_CALLBACK(events, "check_split_switched_back_offer_edit");                       //  603

  // Create safex price peg

  REWIND_BLOCKS(events, blk_46r, blk_46, first_miner_account);                                //  663
  MAKE_TX_CREATE_SAFEX_PRICE_PEG_LIST_START(events, txlist_5, alice_account, safex_account_alice.pkey, safex_price_peg_alice, m_safex_account1_keys.get_keys(), blk_46); // 664
  MAKE_NEXT_BLOCK_TX_LIST(events, blk_47, blk_46r, first_miner_account, txlist_5);            //  665
  DO_CALLBACK(events, "check_split_price_peg_present_1");                            //  666
  //  //split again and check back switching
  MAKE_NEXT_BLOCK(events, blk_48, blk_45, first_miner_account);                               //  667
  MAKE_NEXT_BLOCK(events, blk_49, blk_48, first_miner_account);                               //  668
  REWIND_BLOCKS(events, blk_49r, blk_49, first_miner_account);                                //  728
  MAKE_NEXT_BLOCK(events, blk_50, blk_49r, first_miner_account);                              //  729
  DO_CALLBACK(events, "check_split_switched_price_peg");                            //  730
  MAKE_NEXT_BLOCK(events, blk_51, blk_47, first_miner_account);                               //  731
  MAKE_NEXT_BLOCK(events, blk_52, blk_51, first_miner_account);                               //  732
  DO_CALLBACK(events, "check_split_switched_back_price_peg");                       //  733

  // Edit safex price peg

  REWIND_BLOCKS(events, blk_52r, blk_52, first_miner_account);                                //  793
  MAKE_TX_UPDATE_SAFEX_PRICE_PEG_LIST_START(events, txlist_6, alice_account, safex_account_alice.pkey, safex_price_peg_alice_edited, m_safex_account1_keys.get_keys(), blk_52); // 794
  MAKE_NEXT_BLOCK_TX_LIST(events, blk_53, blk_52r, first_miner_account, txlist_6);            //  795
  DO_CALLBACK(events, "check_split_price_peg_edit_1");                              //  796
  //  //split again and check back switching
  MAKE_NEXT_BLOCK(events, blk_54, blk_51, first_miner_account);                               //  797
  MAKE_NEXT_BLOCK(events, blk_55, blk_54, first_miner_account);                               //  798
  REWIND_BLOCKS(events, blk_55r, blk_55, first_miner_account);                                //  858
  MAKE_NEXT_BLOCK(events, blk_56, blk_55r, first_miner_account);                              //  859
  DO_CALLBACK(events, "check_split_switched_price_peg_edit");                            //  860
  MAKE_NEXT_BLOCK(events, blk_58, blk_53, first_miner_account);                               //  861
  MAKE_NEXT_BLOCK(events, blk_59, blk_58, first_miner_account);                               //  862
  DO_CALLBACK(events, "check_split_switched_back_price_peg_edit");                       //  863

  return true;
}

//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_account_present_1(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_account_present_1");
  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 137);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 139);
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[140])));
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
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[140])));
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
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[211])));
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
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[214])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 69);

  std::vector<std::pair<string,string>> safex_accounts;
  CHECK_TEST_CONDITION(c.get_safex_accounts(safex_accounts));

  safex::safex_account sfx_account;
  bool res = c.get_safex_account_info(safex_account_alice.username,sfx_account);
  CHECK_TEST_CONDITION(res);
  CHECK_TEST_CONDITION(std::equal(safex_account_alice.account_data.begin(), safex_account_alice.account_data.end(), sfx_account.account_data.begin()));
  CHECK_TEST_CONDITION(safex_accounts.size() == 1);

  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_account_edit_1(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_account_edit_1");

  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 200);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 203);
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[277])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 69);

  std::vector<std::pair<string,string>> safex_accounts;
  CHECK_TEST_CONDITION(c.get_safex_accounts(safex_accounts));

  safex::safex_account sfx_account;
  bool res = c.get_safex_account_info(safex_account_alice.username,sfx_account);
  CHECK_TEST_CONDITION(res);
  std::string sfx_account_data{sfx_account.account_data.begin(),sfx_account.account_data.end()};
  CHECK_EQ(sfx_account_data,data_alternative);
  CHECK_TEST_CONDITION(safex_accounts.size() == 1);

  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_switched_account_edit(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_switched_account_edit");

  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 201);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 203);
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[341])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 131);

  std::vector<std::pair<string,string>> safex_accounts;
  CHECK_TEST_CONDITION(c.get_safex_accounts(safex_accounts));

  safex::safex_account sfx_account;
  bool res = c.get_safex_account_info(safex_account_alice.username,sfx_account);
  CHECK_TEST_CONDITION(res);
  CHECK_TEST_CONDITION(std::equal(safex_account_alice.account_data.begin(), safex_account_alice.account_data.end(), sfx_account.account_data.begin()));
  CHECK_TEST_CONDITION(safex_accounts.size() == 1);

  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_switched_back_account_edit(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_switched_back_account_edit");

  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 202);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 205);
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[344])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 132);

  std::vector<std::pair<string,string>> safex_accounts;
  CHECK_TEST_CONDITION(c.get_safex_accounts(safex_accounts));

  safex::safex_account sfx_account;
  bool res = c.get_safex_account_info(safex_account_alice.username,sfx_account);
  CHECK_TEST_CONDITION(res);
  std::string sfx_account_data{sfx_account.account_data.begin(),sfx_account.account_data.end()};
  CHECK_EQ(sfx_account_data,data_alternative);
  CHECK_TEST_CONDITION(safex_accounts.size() == 1);

  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_offer_present_1(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_offer_present_1");

  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 263);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 267);
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[407])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 132);
  // safex account
  std::vector<std::pair<string,string>> safex_accounts;
  CHECK_TEST_CONDITION(c.get_safex_accounts(safex_accounts));

  safex::safex_account sfx_account;
  bool res = c.get_safex_account_info(safex_account_alice.username,sfx_account);
  CHECK_TEST_CONDITION(res);
  std::string sfx_account_data{sfx_account.account_data.begin(),sfx_account.account_data.end()};
  CHECK_EQ(sfx_account_data,data_alternative);
  CHECK_TEST_CONDITION(safex_accounts.size() == 1);
  // safex offer
  std::vector<safex::safex_offer> safex_offers;
  CHECK_TEST_CONDITION(c.get_safex_offers(safex_offers));

  safex::safex_offer sfx_offer;
  res =  c.get_blockchain_storage().get_safex_offer(expected_alice_safex_offer.offer_id, sfx_offer);
  CHECK_TEST_CONDITION(res);
  CHECK_TEST_CONDITION(expected_alice_safex_offer.title.compare(sfx_offer.title) == 0);
  CHECK_EQ(expected_alice_safex_offer.price, sfx_offer.price);
  CHECK_EQ(expected_alice_safex_offer.min_sfx_price, sfx_offer.min_sfx_price);
  CHECK_EQ(expected_alice_safex_offer.price_peg_used, sfx_offer.price_peg_used);
  CHECK_EQ(expected_alice_safex_offer.quantity, sfx_offer.quantity);
  CHECK_TEST_CONDITION(std::equal(expected_alice_safex_offer.description.begin(), expected_alice_safex_offer.description.end(), sfx_offer.description.begin()));
  CHECK_EQ(expected_alice_safex_offer.seller_private_view_key, sfx_offer.seller_private_view_key);
  CHECK_TEST_CONDITION(expected_alice_safex_offer.seller_address == sfx_offer.seller_address);
  CHECK_TEST_CONDITION(safex_offers.size() == 1);


  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_switched_offer(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_switched_offer");

  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 264);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 267);
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[471])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 194);
  // safex account
  std::vector<std::pair<string,string>> safex_accounts;
  CHECK_TEST_CONDITION(c.get_safex_accounts(safex_accounts));

  safex::safex_account sfx_account;
  bool res = c.get_safex_account_info(safex_account_alice.username,sfx_account);
  CHECK_TEST_CONDITION(res);
  std::string sfx_account_data{sfx_account.account_data.begin(),sfx_account.account_data.end()};
  CHECK_EQ(sfx_account_data,data_alternative);
  CHECK_TEST_CONDITION(safex_accounts.size() == 1);
  // safex offer
  std::vector<safex::safex_offer> safex_offers;
  CHECK_TEST_CONDITION(c.get_safex_offers(safex_offers));
  CHECK_TEST_CONDITION(safex_offers.size() == 0);


  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_switched_back_offer(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_switched_back_offer");

  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 265);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 269);
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[474])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 195);
  // safex account
  std::vector<std::pair<string,string>> safex_accounts;
  CHECK_TEST_CONDITION(c.get_safex_accounts(safex_accounts));

  safex::safex_account sfx_account;
  bool res = c.get_safex_account_info(safex_account_alice.username,sfx_account);
  CHECK_TEST_CONDITION(res);
  std::string sfx_account_data{sfx_account.account_data.begin(),sfx_account.account_data.end()};
  CHECK_EQ(sfx_account_data,data_alternative);
  CHECK_TEST_CONDITION(safex_accounts.size() == 1);
  // safex offer
  std::vector<safex::safex_offer> safex_offers;
  CHECK_TEST_CONDITION(c.get_safex_offers(safex_offers));

  safex::safex_offer sfx_offer;
  res =  c.get_blockchain_storage().get_safex_offer(expected_alice_safex_offer.offer_id, sfx_offer);
  CHECK_TEST_CONDITION(res);
  CHECK_TEST_CONDITION(expected_alice_safex_offer.title.compare(sfx_offer.title) == 0);
  CHECK_EQ(expected_alice_safex_offer.price, sfx_offer.price);
  CHECK_EQ(expected_alice_safex_offer.min_sfx_price, sfx_offer.min_sfx_price);
  CHECK_EQ(expected_alice_safex_offer.price_peg_used, sfx_offer.price_peg_used);
  CHECK_EQ(expected_alice_safex_offer.quantity, sfx_offer.quantity);
  CHECK_TEST_CONDITION(std::equal(expected_alice_safex_offer.description.begin(), expected_alice_safex_offer.description.end(), sfx_offer.description.begin()));
  CHECK_EQ(expected_alice_safex_offer.seller_private_view_key, sfx_offer.seller_private_view_key);
  CHECK_TEST_CONDITION(expected_alice_safex_offer.seller_address == sfx_offer.seller_address);
  CHECK_TEST_CONDITION(safex_offers.size() == 1);

  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_offer_edit_1(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_offer_edit_1");

  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 326);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 331);
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[537])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 195);
  // safex account
  std::vector<std::pair<string,string>> safex_accounts;
  CHECK_TEST_CONDITION(c.get_safex_accounts(safex_accounts));

  safex::safex_account sfx_account;
  bool res = c.get_safex_account_info(safex_account_alice.username,sfx_account);
  CHECK_TEST_CONDITION(res);
  std::string sfx_account_data{sfx_account.account_data.begin(),sfx_account.account_data.end()};
  CHECK_EQ(sfx_account_data,data_alternative);
  CHECK_TEST_CONDITION(safex_accounts.size() == 1);
  // safex offer
  std::vector<safex::safex_offer> safex_offers;
  CHECK_TEST_CONDITION(c.get_safex_offers(safex_offers));

  safex::safex_offer sfx_offer;
  res =  c.get_blockchain_storage().get_safex_offer(expected_alice_safex_offer_edited.offer_id, sfx_offer);
  CHECK_TEST_CONDITION(res);
  CHECK_TEST_CONDITION(expected_alice_safex_offer_edited.title.compare(sfx_offer.title) == 0);
  CHECK_EQ(expected_alice_safex_offer_edited.price, sfx_offer.price);
  CHECK_EQ(expected_alice_safex_offer_edited.min_sfx_price, sfx_offer.min_sfx_price);
  CHECK_EQ(expected_alice_safex_offer_edited.price_peg_used, sfx_offer.price_peg_used);
  CHECK_EQ(expected_alice_safex_offer_edited.quantity, sfx_offer.quantity);
  CHECK_TEST_CONDITION(std::equal(expected_alice_safex_offer_edited.description.begin(), expected_alice_safex_offer_edited.description.end(), sfx_offer.description.begin()));
  CHECK_EQ(expected_alice_safex_offer_edited.seller_private_view_key, sfx_offer.seller_private_view_key);
  CHECK_TEST_CONDITION(expected_alice_safex_offer_edited.seller_address == sfx_offer.seller_address);
  CHECK_TEST_CONDITION(safex_offers.size() == 1);


  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_switched_offer_edit(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_switched_offer_edit");

  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 327);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 331);
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[601])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 257);
  // safex account
  std::vector<std::pair<string,string>> safex_accounts;
  CHECK_TEST_CONDITION(c.get_safex_accounts(safex_accounts));

  safex::safex_account sfx_account;
  bool res = c.get_safex_account_info(safex_account_alice.username,sfx_account);
  CHECK_TEST_CONDITION(res);
  std::string sfx_account_data{sfx_account.account_data.begin(),sfx_account.account_data.end()};
  CHECK_EQ(sfx_account_data,data_alternative);
  CHECK_TEST_CONDITION(safex_accounts.size() == 1);
  // safex offer
  std::vector<safex::safex_offer> safex_offers;
  CHECK_TEST_CONDITION(c.get_safex_offers(safex_offers));

  safex::safex_offer sfx_offer;
  res =  c.get_blockchain_storage().get_safex_offer(expected_alice_safex_offer.offer_id, sfx_offer);
  CHECK_TEST_CONDITION(res);
  CHECK_TEST_CONDITION(expected_alice_safex_offer.title.compare(sfx_offer.title) == 0);
  CHECK_EQ(expected_alice_safex_offer.price, sfx_offer.price);
  CHECK_EQ(expected_alice_safex_offer.min_sfx_price, sfx_offer.min_sfx_price);
  CHECK_EQ(expected_alice_safex_offer.price_peg_used, sfx_offer.price_peg_used);
  CHECK_EQ(expected_alice_safex_offer.quantity, sfx_offer.quantity);
  CHECK_TEST_CONDITION(std::equal(expected_alice_safex_offer.description.begin(), expected_alice_safex_offer.description.end(), sfx_offer.description.begin()));
  CHECK_EQ(expected_alice_safex_offer.seller_private_view_key, sfx_offer.seller_private_view_key);
  CHECK_TEST_CONDITION(expected_alice_safex_offer.seller_address == sfx_offer.seller_address);
  CHECK_TEST_CONDITION(safex_offers.size() == 1);


  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_switched_back_offer_edit(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_switched_back_offer_edit");

  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 328);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 333);
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[604])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 258);
  // safex account
  std::vector<std::pair<string,string>> safex_accounts;
  CHECK_TEST_CONDITION(c.get_safex_accounts(safex_accounts));

  safex::safex_account sfx_account;
  bool res = c.get_safex_account_info(safex_account_alice.username,sfx_account);
  CHECK_TEST_CONDITION(res);
  std::string sfx_account_data{sfx_account.account_data.begin(),sfx_account.account_data.end()};
  CHECK_EQ(sfx_account_data,data_alternative);
  CHECK_TEST_CONDITION(safex_accounts.size() == 1);
  // safex offer
  std::vector<safex::safex_offer> safex_offers;
  CHECK_TEST_CONDITION(c.get_safex_offers(safex_offers));

  safex::safex_offer sfx_offer;
  res =  c.get_blockchain_storage().get_safex_offer(expected_alice_safex_offer.offer_id, sfx_offer);
  CHECK_TEST_CONDITION(res);
  CHECK_TEST_CONDITION(expected_alice_safex_offer_edited.title.compare(sfx_offer.title) == 0);
  CHECK_EQ(expected_alice_safex_offer_edited.price, sfx_offer.price);
  CHECK_EQ(expected_alice_safex_offer_edited.min_sfx_price, sfx_offer.min_sfx_price);
  CHECK_EQ(expected_alice_safex_offer_edited.price_peg_used, sfx_offer.price_peg_used);
  CHECK_EQ(expected_alice_safex_offer_edited.quantity, sfx_offer.quantity);
  CHECK_TEST_CONDITION(std::equal(expected_alice_safex_offer_edited.description.begin(), expected_alice_safex_offer_edited.description.end(), sfx_offer.description.begin()));
  CHECK_EQ(expected_alice_safex_offer_edited.seller_private_view_key, sfx_offer.seller_private_view_key);
  CHECK_TEST_CONDITION(expected_alice_safex_offer_edited.seller_address == sfx_offer.seller_address);
  CHECK_TEST_CONDITION(safex_offers.size() == 1);

  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_price_peg_present_1(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_price_peg_present_1");

  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 389);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 395);
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[667])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 258);
  // safex account
  std::vector<std::pair<string,string>> safex_accounts;
  CHECK_TEST_CONDITION(c.get_safex_accounts(safex_accounts));

  safex::safex_account sfx_account;
  bool res = c.get_safex_account_info(safex_account_alice.username,sfx_account);
  CHECK_TEST_CONDITION(res);
  std::string sfx_account_data{sfx_account.account_data.begin(),sfx_account.account_data.end()};
  CHECK_EQ(sfx_account_data,data_alternative);
  CHECK_TEST_CONDITION(safex_accounts.size() == 1);
  // safex offer
  std::vector<safex::safex_offer> safex_offers;
  CHECK_TEST_CONDITION(c.get_safex_offers(safex_offers));

  safex::safex_offer sfx_offer;
  res =  c.get_blockchain_storage().get_safex_offer(expected_alice_safex_offer_edited.offer_id, sfx_offer);
  CHECK_TEST_CONDITION(res);
  CHECK_TEST_CONDITION(expected_alice_safex_offer_edited.title.compare(sfx_offer.title) == 0);
  CHECK_EQ(expected_alice_safex_offer_edited.price, sfx_offer.price);
  CHECK_EQ(expected_alice_safex_offer_edited.min_sfx_price, sfx_offer.min_sfx_price);
  CHECK_EQ(expected_alice_safex_offer_edited.price_peg_used, sfx_offer.price_peg_used);
  CHECK_EQ(expected_alice_safex_offer_edited.quantity, sfx_offer.quantity);
  CHECK_TEST_CONDITION(std::equal(expected_alice_safex_offer_edited.description.begin(), expected_alice_safex_offer_edited.description.end(), sfx_offer.description.begin()));
  CHECK_EQ(expected_alice_safex_offer_edited.seller_private_view_key, sfx_offer.seller_private_view_key);
  CHECK_TEST_CONDITION(expected_alice_safex_offer_edited.seller_address == sfx_offer.seller_address);
  CHECK_TEST_CONDITION(safex_offers.size() == 1);
  // safex price peg
  std::vector<safex::safex_price_peg> safex_price_pegs;
  CHECK_TEST_CONDITION(c.get_safex_price_pegs(safex_price_pegs));

  safex::safex_price_peg sfx_price_peg;
  res =  c.get_blockchain_storage().get_safex_price_peg(expected_alice_safex_price_peg.price_peg_id, sfx_price_peg);
  CHECK_TEST_CONDITION(res);
  CHECK_TEST_CONDITION(expected_alice_safex_price_peg.title.compare(sfx_price_peg.title) == 0);
  CHECK_EQ(expected_alice_safex_price_peg.creator, sfx_price_peg.creator);
  CHECK_EQ(expected_alice_safex_price_peg.rate, sfx_price_peg.rate);
  CHECK_EQ(expected_alice_safex_price_peg.title, sfx_price_peg.title);
  CHECK_EQ(expected_alice_safex_price_peg.currency, sfx_price_peg.currency);
  CHECK_TEST_CONDITION(std::equal(expected_alice_safex_price_peg.description.begin(), expected_alice_safex_price_peg.description.end(), sfx_price_peg.description.begin()));
  CHECK_TEST_CONDITION(safex_price_pegs.size() == 1);


  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_switched_price_peg(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_switched_price_peg");

  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 390);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 395.);
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[731])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 320);
  // safex account
  std::vector<std::pair<string,string>> safex_accounts;
  CHECK_TEST_CONDITION(c.get_safex_accounts(safex_accounts));

  safex::safex_account sfx_account;
  bool res = c.get_safex_account_info(safex_account_alice.username,sfx_account);
  CHECK_TEST_CONDITION(res);
  std::string sfx_account_data{sfx_account.account_data.begin(),sfx_account.account_data.end()};
  CHECK_EQ(sfx_account_data,data_alternative);
  CHECK_TEST_CONDITION(safex_accounts.size() == 1);
  // safex offer
  std::vector<safex::safex_offer> safex_offers;
  CHECK_TEST_CONDITION(c.get_safex_offers(safex_offers));

  safex::safex_offer sfx_offer;
  res =  c.get_blockchain_storage().get_safex_offer(expected_alice_safex_offer_edited.offer_id, sfx_offer);
  CHECK_TEST_CONDITION(res);
  CHECK_TEST_CONDITION(expected_alice_safex_offer_edited.title.compare(sfx_offer.title) == 0);
  CHECK_EQ(expected_alice_safex_offer_edited.price, sfx_offer.price);
  CHECK_EQ(expected_alice_safex_offer_edited.min_sfx_price, sfx_offer.min_sfx_price);
  CHECK_EQ(expected_alice_safex_offer_edited.price_peg_used, sfx_offer.price_peg_used);
  CHECK_EQ(expected_alice_safex_offer_edited.quantity, sfx_offer.quantity);
  CHECK_TEST_CONDITION(std::equal(expected_alice_safex_offer_edited.description.begin(), expected_alice_safex_offer_edited.description.end(), sfx_offer.description.begin()));
  CHECK_EQ(expected_alice_safex_offer_edited.seller_private_view_key, sfx_offer.seller_private_view_key);
  CHECK_TEST_CONDITION(expected_alice_safex_offer_edited.seller_address == sfx_offer.seller_address);
  CHECK_TEST_CONDITION(safex_offers.size() == 1);
  // safex price peg
  std::vector<safex::safex_price_peg> safex_price_pegs;
  CHECK_TEST_CONDITION(c.get_safex_price_pegs(safex_price_pegs));

  CHECK_TEST_CONDITION(safex_price_pegs.size() == 0);

  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_switched_back_price_peg(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_switched_back_price_peg");

  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 391);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 397);
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[734])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 321);
  // safex account
  std::vector<std::pair<string,string>> safex_accounts;
  CHECK_TEST_CONDITION(c.get_safex_accounts(safex_accounts));

  safex::safex_account sfx_account;
  bool res = c.get_safex_account_info(safex_account_alice.username,sfx_account);
  CHECK_TEST_CONDITION(res);
  std::string sfx_account_data{sfx_account.account_data.begin(),sfx_account.account_data.end()};
  CHECK_EQ(sfx_account_data,data_alternative);
  CHECK_TEST_CONDITION(safex_accounts.size() == 1);
  // safex offer
  std::vector<safex::safex_offer> safex_offers;
  CHECK_TEST_CONDITION(c.get_safex_offers(safex_offers));

  safex::safex_offer sfx_offer;
  res =  c.get_blockchain_storage().get_safex_offer(expected_alice_safex_offer_edited.offer_id, sfx_offer);
  CHECK_TEST_CONDITION(res);
  CHECK_TEST_CONDITION(expected_alice_safex_offer_edited.title.compare(sfx_offer.title) == 0);
  CHECK_EQ(expected_alice_safex_offer_edited.price, sfx_offer.price);
  CHECK_EQ(expected_alice_safex_offer_edited.min_sfx_price, sfx_offer.min_sfx_price);
  CHECK_EQ(expected_alice_safex_offer_edited.price_peg_used, sfx_offer.price_peg_used);
  CHECK_EQ(expected_alice_safex_offer_edited.quantity, sfx_offer.quantity);
  CHECK_TEST_CONDITION(std::equal(expected_alice_safex_offer_edited.description.begin(), expected_alice_safex_offer_edited.description.end(), sfx_offer.description.begin()));
  CHECK_EQ(expected_alice_safex_offer_edited.seller_private_view_key, sfx_offer.seller_private_view_key);
  CHECK_TEST_CONDITION(expected_alice_safex_offer_edited.seller_address == sfx_offer.seller_address);
  CHECK_TEST_CONDITION(safex_offers.size() == 1);
  // safex price peg
  std::vector<safex::safex_price_peg> safex_price_pegs;
  CHECK_TEST_CONDITION(c.get_safex_price_pegs(safex_price_pegs));

  safex::safex_price_peg sfx_price_peg;
  res =  c.get_blockchain_storage().get_safex_price_peg(expected_alice_safex_price_peg.price_peg_id, sfx_price_peg);
  CHECK_TEST_CONDITION(res);
  CHECK_TEST_CONDITION(expected_alice_safex_price_peg.title.compare(sfx_price_peg.title) == 0);
  CHECK_EQ(expected_alice_safex_price_peg.creator, sfx_price_peg.creator);
  CHECK_EQ(expected_alice_safex_price_peg.rate, sfx_price_peg.rate);
  CHECK_EQ(expected_alice_safex_price_peg.title, sfx_price_peg.title);
  CHECK_EQ(expected_alice_safex_price_peg.currency, sfx_price_peg.currency);
  CHECK_TEST_CONDITION(std::equal(expected_alice_safex_price_peg.description.begin(), expected_alice_safex_price_peg.description.end(), sfx_price_peg.description.begin()));
  CHECK_TEST_CONDITION(safex_price_pegs.size() == 1);

  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_price_peg_edit_1(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_price_peg_edit_1");

  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 452);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 459);
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[797])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 321);
  // safex account
  std::vector<std::pair<string,string>> safex_accounts;
  CHECK_TEST_CONDITION(c.get_safex_accounts(safex_accounts));

  safex::safex_account sfx_account;
  bool res = c.get_safex_account_info(safex_account_alice.username,sfx_account);
  CHECK_TEST_CONDITION(res);
  std::string sfx_account_data{sfx_account.account_data.begin(),sfx_account.account_data.end()};
  CHECK_EQ(sfx_account_data,data_alternative);
  CHECK_TEST_CONDITION(safex_accounts.size() == 1);
  // safex offer
  std::vector<safex::safex_offer> safex_offers;
  CHECK_TEST_CONDITION(c.get_safex_offers(safex_offers));

  safex::safex_offer sfx_offer;
  res =  c.get_blockchain_storage().get_safex_offer(expected_alice_safex_offer_edited.offer_id, sfx_offer);
  CHECK_TEST_CONDITION(res);
  CHECK_TEST_CONDITION(expected_alice_safex_offer_edited.title.compare(sfx_offer.title) == 0);
  CHECK_EQ(expected_alice_safex_offer_edited.price, sfx_offer.price);
  CHECK_EQ(expected_alice_safex_offer_edited.min_sfx_price, sfx_offer.min_sfx_price);
  CHECK_EQ(expected_alice_safex_offer_edited.price_peg_used, sfx_offer.price_peg_used);
  CHECK_EQ(expected_alice_safex_offer_edited.quantity, sfx_offer.quantity);
  CHECK_TEST_CONDITION(std::equal(expected_alice_safex_offer_edited.description.begin(), expected_alice_safex_offer_edited.description.end(), sfx_offer.description.begin()));
  CHECK_EQ(expected_alice_safex_offer_edited.seller_private_view_key, sfx_offer.seller_private_view_key);
  CHECK_TEST_CONDITION(expected_alice_safex_offer_edited.seller_address == sfx_offer.seller_address);
  CHECK_TEST_CONDITION(safex_offers.size() == 1);
  // safex price peg
  std::vector<safex::safex_price_peg> safex_price_pegs;
  CHECK_TEST_CONDITION(c.get_safex_price_pegs(safex_price_pegs));

  safex::safex_price_peg sfx_price_peg;
  res =  c.get_blockchain_storage().get_safex_price_peg(expected_alice_safex_price_peg_edited.price_peg_id, sfx_price_peg);
  CHECK_TEST_CONDITION(res);
  CHECK_TEST_CONDITION(expected_alice_safex_price_peg_edited.title.compare(sfx_price_peg.title) == 0);
  CHECK_EQ(expected_alice_safex_price_peg_edited.creator, sfx_price_peg.creator);
  CHECK_EQ(expected_alice_safex_price_peg_edited.rate, sfx_price_peg.rate);
  CHECK_EQ(expected_alice_safex_price_peg_edited.title, sfx_price_peg.title);
  CHECK_EQ(expected_alice_safex_price_peg_edited.currency, sfx_price_peg.currency);
  CHECK_TEST_CONDITION(std::equal(expected_alice_safex_price_peg_edited.description.begin(), expected_alice_safex_price_peg_edited.description.end(), sfx_price_peg.description.begin()));
  CHECK_TEST_CONDITION(safex_price_pegs.size() == 1);


  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_switched_price_peg_edit(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_switched_price_peg_edit");

  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 453);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 459);
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[861])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 383);
  // safex account
  std::vector<std::pair<string,string>> safex_accounts;
  CHECK_TEST_CONDITION(c.get_safex_accounts(safex_accounts));

  safex::safex_account sfx_account;
  bool res = c.get_safex_account_info(safex_account_alice.username,sfx_account);
  CHECK_TEST_CONDITION(res);
  std::string sfx_account_data{sfx_account.account_data.begin(),sfx_account.account_data.end()};
  CHECK_EQ(sfx_account_data,data_alternative);
  CHECK_TEST_CONDITION(safex_accounts.size() == 1);
  // safex offer
  std::vector<safex::safex_offer> safex_offers;
  CHECK_TEST_CONDITION(c.get_safex_offers(safex_offers));

  safex::safex_offer sfx_offer;
  res =  c.get_blockchain_storage().get_safex_offer(expected_alice_safex_offer_edited.offer_id, sfx_offer);
  CHECK_TEST_CONDITION(res);
  CHECK_TEST_CONDITION(expected_alice_safex_offer_edited.title.compare(sfx_offer.title) == 0);
  CHECK_EQ(expected_alice_safex_offer_edited.price, sfx_offer.price);
  CHECK_EQ(expected_alice_safex_offer_edited.min_sfx_price, sfx_offer.min_sfx_price);
  CHECK_EQ(expected_alice_safex_offer_edited.price_peg_used, sfx_offer.price_peg_used);
  CHECK_EQ(expected_alice_safex_offer_edited.quantity, sfx_offer.quantity);
  CHECK_TEST_CONDITION(std::equal(expected_alice_safex_offer_edited.description.begin(), expected_alice_safex_offer_edited.description.end(), sfx_offer.description.begin()));
  CHECK_EQ(expected_alice_safex_offer_edited.seller_private_view_key, sfx_offer.seller_private_view_key);
  CHECK_TEST_CONDITION(expected_alice_safex_offer_edited.seller_address == sfx_offer.seller_address);
  CHECK_TEST_CONDITION(safex_offers.size() == 1);
  // safex price peg
  std::vector<safex::safex_price_peg> safex_price_pegs;
  CHECK_TEST_CONDITION(c.get_safex_price_pegs(safex_price_pegs));

  safex::safex_price_peg sfx_price_peg;
  res =  c.get_blockchain_storage().get_safex_price_peg(expected_alice_safex_price_peg.price_peg_id, sfx_price_peg);
  CHECK_TEST_CONDITION(res);
  CHECK_TEST_CONDITION(expected_alice_safex_price_peg.title.compare(sfx_price_peg.title) == 0);
  CHECK_EQ(expected_alice_safex_price_peg.creator, sfx_price_peg.creator);
  CHECK_EQ(expected_alice_safex_price_peg.rate, sfx_price_peg.rate);
  CHECK_EQ(expected_alice_safex_price_peg.title, sfx_price_peg.title);
  CHECK_EQ(expected_alice_safex_price_peg.currency, sfx_price_peg.currency);
  CHECK_TEST_CONDITION(std::equal(expected_alice_safex_price_peg.description.begin(), expected_alice_safex_price_peg.description.end(), sfx_price_peg.description.begin()));
  CHECK_TEST_CONDITION(safex_price_pegs.size() == 1);

  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_simple_chain_split_safex::check_split_switched_back_price_peg_edit(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_simple_chain_split_safex::check_split_switched_back_price_peg_edit");

  //check height
  CHECK_TEST_CONDITION(c.get_current_blockchain_height() == 454);
  CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == 461);
  CHECK_TEST_CONDITION(c.get_tail_id() == get_block_hash(boost::get<cryptonote::block>(events[864])));
  CHECK_TEST_CONDITION(c.get_alternative_blocks_count() == 384);
  // safex account
  std::vector<std::pair<string,string>> safex_accounts;
  CHECK_TEST_CONDITION(c.get_safex_accounts(safex_accounts));

  safex::safex_account sfx_account;
  bool res = c.get_safex_account_info(safex_account_alice.username,sfx_account);
  CHECK_TEST_CONDITION(res);
  std::string sfx_account_data{sfx_account.account_data.begin(),sfx_account.account_data.end()};
  CHECK_EQ(sfx_account_data,data_alternative);
  CHECK_TEST_CONDITION(safex_accounts.size() == 1);
  // safex offer
  std::vector<safex::safex_offer> safex_offers;
  CHECK_TEST_CONDITION(c.get_safex_offers(safex_offers));

  safex::safex_offer sfx_offer;
  res =  c.get_blockchain_storage().get_safex_offer(expected_alice_safex_offer_edited.offer_id, sfx_offer);
  CHECK_TEST_CONDITION(res);
  CHECK_TEST_CONDITION(expected_alice_safex_offer_edited.title.compare(sfx_offer.title) == 0);
  CHECK_EQ(expected_alice_safex_offer_edited.price, sfx_offer.price);
  CHECK_EQ(expected_alice_safex_offer_edited.min_sfx_price, sfx_offer.min_sfx_price);
  CHECK_EQ(expected_alice_safex_offer_edited.price_peg_used, sfx_offer.price_peg_used);
  CHECK_EQ(expected_alice_safex_offer_edited.quantity, sfx_offer.quantity);
  CHECK_TEST_CONDITION(std::equal(expected_alice_safex_offer_edited.description.begin(), expected_alice_safex_offer_edited.description.end(), sfx_offer.description.begin()));
  CHECK_EQ(expected_alice_safex_offer_edited.seller_private_view_key, sfx_offer.seller_private_view_key);
  CHECK_TEST_CONDITION(expected_alice_safex_offer_edited.seller_address == sfx_offer.seller_address);
  CHECK_TEST_CONDITION(safex_offers.size() == 1);
  // safex price peg
  std::vector<safex::safex_price_peg> safex_price_pegs;
  CHECK_TEST_CONDITION(c.get_safex_price_pegs(safex_price_pegs));

  safex::safex_price_peg sfx_price_peg;
  res =  c.get_blockchain_storage().get_safex_price_peg(expected_alice_safex_price_peg_edited.price_peg_id, sfx_price_peg);
  CHECK_TEST_CONDITION(res);
  CHECK_TEST_CONDITION(expected_alice_safex_price_peg_edited.title.compare(sfx_price_peg.title) == 0);
  CHECK_EQ(expected_alice_safex_price_peg_edited.creator, sfx_price_peg.creator);
  CHECK_EQ(expected_alice_safex_price_peg_edited.rate, sfx_price_peg.rate);
  CHECK_EQ(expected_alice_safex_price_peg_edited.title, sfx_price_peg.title);
  CHECK_EQ(expected_alice_safex_price_peg_edited.currency, sfx_price_peg.currency);
  CHECK_TEST_CONDITION(std::equal(expected_alice_safex_price_peg_edited.description.begin(), expected_alice_safex_price_peg_edited.description.end(), sfx_price_peg.description.begin()));
  CHECK_TEST_CONDITION(safex_price_pegs.size() == 1);

  std::list<cryptonote::block> block_list;
  bool r = c.get_blocks((uint64_t)0, 391, block_list);
  CHECK_TEST_CONDITION(r);

  std::vector<cryptonote::block> chain;
  map_hash2tx_t mtx;
  std::vector<cryptonote::block> blocks(block_list.begin(), block_list.end());
  bool re = find_block_chain(events, chain, mtx, get_block_hash(blocks.back()));
  CHECK_TEST_CONDITION(re);

  cryptonote::account_base alice_account = boost::get<cryptonote::account_base>(events[1]);
  cryptonote::account_base bob_account = boost::get<cryptonote::account_base>(events[2]);


  uint64_t network_fee_collected = c.get_collected_network_fee(0, 391);
  CHECK_EQ(network_fee_collected, expected_network_fee);


  uint64_t alice_balance =  get_balance(alice_account, chain, mtx);
  CHECK_EQ(alice_balance, expected_alice_balance);

  uint64_t bob_balance =  get_balance(bob_account, chain, mtx);
  CHECK_EQ(bob_balance, expected_bob_balance);

  return true;
}