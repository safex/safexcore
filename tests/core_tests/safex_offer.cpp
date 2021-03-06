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
#include <boost/format.hpp>

#include "include_base_utils.h"

#include "console_handler.h"

#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"

#include "safex/safex_core.h"

#include "chaingen.h"
#include "safex_offer.h"



using namespace std;

using namespace epee;
using namespace cryptonote;


const std::string gen_safex_offer_001::data2_alternative{"Bob's alternative data"};
const std::string gen_safex_offer_001::data2_alternative_2{"Bob's second alternative data"};
const std::string gen_safex_offer_001::data3_alternative{"Daniels's alternative data 2 ----------------------------------------------------- some other data here -----------------------------------------------"
" and more data here ----------------------------------------------------------------------------------*****************--------------------------------"};

bool gen_safex_offer_001::expected_data_fields_intialized{false};
crypto::public_key gen_safex_offer_001::expected_alice_account_key{};
crypto::public_key gen_safex_offer_001::expected_bob_account_key{};
crypto::public_key gen_safex_offer_001::expected_daniel_account_key{};

std::vector<uint8_t> gen_safex_offer_001::expected_alice_account_data;
std::vector<uint8_t> gen_safex_offer_001::expected_bob_account_data;
std::vector<uint8_t> gen_safex_offer_001::expected_daniel_account_data;

safex::safex_offer gen_safex_offer_001::expected_alice_safex_offer;
safex::safex_offer gen_safex_offer_001::expected_bob_safex_offer;

gen_safex_offer_001::gen_safex_offer_001()
{



  m_safex_account1_keys.generate();
  m_safex_account2_keys.generate();
  m_safex_account3_keys.generate();
  m_safex_account4_keys.generate();

  safex_account_alice.username = "alice01";
  safex_account_alice.pkey = m_safex_account1_keys.get_keys().m_public_key;
  safex_account_alice.account_data = {'l','o','r','e','m',' ','i','p','s','u','m'};


  safex_account_bob.username = "bob02";
  safex_account_bob.pkey = m_safex_account2_keys.get_keys().m_public_key;
  std::string data2 = "Bob's data";
  safex_account_bob.account_data = std::vector<uint8_t>(data2.begin(), data2.end());


  safex_account_daniel.username = "daniel03";
  safex_account_daniel.pkey = m_safex_account3_keys.get_keys().m_public_key;
  std::string data3 = "This is some data for test";
  safex_account_daniel.account_data = std::vector<uint8_t>(data3.begin(), data3.end());


  safex_account_edward.username = "edward04";
  safex_account_edward.pkey = m_safex_account4_keys.get_keys().m_public_key;
  std::string data4 = "Тхис ис соме Едвардс дата фор тест";
  safex_account_edward.account_data = std::vector<uint8_t>(data4.begin(), data4.end());

    alice.generate();
    bob.generate();

    safex_offer_alice = safex::safex_offer("Black Sabbath T-shirt",100,MK_COINS(10),"Quality 100% cotton t-shirt with the heaviest band in the universe",
                                           safex_account_alice.username,alice.get_keys().m_view_secret_key,alice.get_keys().m_account_address);
    safex_offer_bob = safex::safex_offer("Metallica T-shirt",1000,MK_COINS(10),"Quality 100% cotton t-shirt with the loudest band in the universe",
                                         safex_account_bob.username,bob.get_keys().m_view_secret_key,bob.get_keys().m_account_address);

    safex_price_peg_bob = safex::safex_price_peg("TestPricePeg",safex_account_bob.username,"USD","Best price my man",3.5*COIN);

    safex_offer_bob.set_price_peg(safex_price_peg_bob.price_peg_id,800,MK_COINS(1000));

  if (!expected_data_fields_intialized)
  {
    expected_alice_account_key = safex_account_alice.pkey;
    expected_bob_account_key = safex_account_bob.pkey;
    expected_daniel_account_key = safex_account_daniel.pkey;
    expected_data_fields_intialized = true;
    expected_alice_account_data = std::vector<uint8_t>(std::begin(safex_account_alice.account_data), std::end(safex_account_alice.account_data));
    expected_bob_account_data = std::vector<uint8_t>(std::begin(data2_alternative_2), std::end(data2_alternative_2));
    expected_daniel_account_data = std::vector<uint8_t>(std::begin(data3_alternative), std::end(data3_alternative));


   expected_alice_safex_offer = safex_offer_alice;
   expected_bob_safex_offer = safex_offer_bob;

    std::string new_str_desc{"Now in white!!!"};
    expected_alice_safex_offer.description = {new_str_desc.begin(),new_str_desc.end()};;
  }

  REGISTER_CALLBACK("verify_safex_offer", gen_safex_offer_001::verify_safex_offer);
}

bool gen_safex_offer_001::generate(std::vector<test_event_entry> &events)
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
    MAKE_ACCOUNT(events, edward);

    MAKE_NEXT_BLOCK(events, blk_1, blk_0, miner);
    MAKE_NEXT_BLOCK(events, blk_2, blk_1, miner);

    REWIND_BLOCKS(events, blk_2r, blk_2, miner);
    MAKE_TX_MIGRATION_LIST_START(events, txlist_0, miner, alice, MK_TOKENS(10000), blk_2, get_hash_from_string(bitcoin_tx_hashes_str[0]));
    MAKE_MIGRATION_TX_LIST(events, txlist_0, miner, bob, MK_TOKENS(10000), blk_2, get_hash_from_string(bitcoin_tx_hashes_str[1]));
    MAKE_MIGRATION_TX_LIST(events, txlist_0, miner, daniel, MK_TOKENS(25000), blk_2, get_hash_from_string(bitcoin_tx_hashes_str[2]));
    MAKE_NEXT_BLOCK_TX_LIST(events, blk_3, blk_2r, miner, txlist_0);
    REWIND_BLOCKS(events, blk_4, blk_3, miner);

    //create alice and bob accounts
    MAKE_TX_CREATE_SAFEX_ACCOUNT_LIST_START(events, txlist_2, alice, safex_account_alice.username, safex_account_alice.pkey, safex_account_alice.account_data, m_safex_account1_keys.get_keys(), events.size()+SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_PERIOD_FAKECHAIN, blk_4);
    MAKE_CREATE_SAFEX_ACCOUNT_TX_LIST(events, txlist_2, bob, safex_account_bob.username, safex_account_bob.pkey, safex_account_bob.account_data, m_safex_account2_keys.get_keys(), events.size()+SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_PERIOD_FAKECHAIN, blk_4);
    MAKE_MIGRATION_TX_LIST(events, txlist_2, miner, edward, MK_TOKENS(8000), blk_4, get_hash_from_string(bitcoin_tx_hashes_str[3]));
    MAKE_NEXT_BLOCK_TX_LIST(events, blk_5, blk_4, miner, txlist_2);
    REWIND_BLOCKS(events, blk_6, blk_5, miner);

    MAKE_TX_CREATE_SAFEX_ACCOUNT_LIST_START(events, txlist_3, daniel, safex_account_daniel.username, safex_account_daniel.pkey, safex_account_daniel.account_data, m_safex_account3_keys.get_keys(), events.size()+SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_PERIOD_FAKECHAIN, blk_6);
    MAKE_CREATE_SAFEX_PRICE_PEG_TX_LIST(events, txlist_3, bob, safex_account_bob.pkey, safex_price_peg_bob, m_safex_account2_keys.get_keys(), blk_6);
    MAKE_MIGRATION_TX_LIST(events, txlist_3, miner, bob, MK_TOKENS(20000), blk_6, get_hash_from_string(bitcoin_tx_hashes_str[4]));
    MAKE_NEXT_BLOCK_TX_LIST(events, blk_7, blk_6, miner, txlist_3);
    REWIND_BLOCKS(events, blk_8, blk_7, miner);

    MAKE_TX_EDIT_SAFEX_ACCOUNT_LIST_START(events, txlist_4, daniel, safex_account_daniel.username, std::vector<uint8_t>(data3_alternative.begin(), data3_alternative.end()), m_safex_account3_keys.get_keys(), blk_8);
    MAKE_EDIT_SAFEX_ACCOUNT_TX_LIST(events, txlist_4, bob, safex_account_bob.username, std::vector<uint8_t>(data2_alternative_2.begin(), data2_alternative_2.end()), m_safex_account2_keys.get_keys(), blk_8);
    MAKE_CREATE_SAFEX_ACCOUNT_TX_LIST(events, txlist_4, edward, safex_account_edward.username, safex_account_edward.pkey, safex_account_edward.account_data, m_safex_account4_keys.get_keys(), events.size()+SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_PERIOD_FAKECHAIN, blk_8);
    MAKE_NEXT_BLOCK_TX_LIST(events, blk_9, blk_8, miner, txlist_4);
    REWIND_BLOCKS(events, blk_10, blk_9, miner);

    //create test offer
    MAKE_TX_CREATE_SAFEX_OFFER_LIST_START(events, txlist_5, alice, safex_account_alice.pkey, safex_offer_alice, m_safex_account1_keys.get_keys(), blk_10);
    MAKE_CREATE_SAFEX_OFFER_TX_LIST(events, txlist_5, bob, safex_account_bob.pkey, safex_offer_bob, m_safex_account2_keys.get_keys(), blk_10);
    MAKE_NEXT_BLOCK_TX_LIST(events, blk_11, blk_10, miner, txlist_5);
    REWIND_BLOCKS(events, blk_12, blk_11, miner);



    safex_offer_alice.description = expected_alice_safex_offer.description;

    MAKE_TX_EDIT_SAFEX_OFFER_LIST_START(events, txlist_6, alice, safex_account_alice.pkey, safex_offer_alice, m_safex_account1_keys.get_keys(), blk_12);
    MAKE_NEXT_BLOCK_TX_LIST(events, blk_13, blk_12, miner, txlist_6);
    REWIND_BLOCKS(events, blk_14, blk_13, miner);

    DO_CALLBACK(events, "verify_safex_offer");

    return true;
}

bool gen_safex_offer_001::verify_safex_offer(cryptonote::core &c, size_t ev_index, const std::vector<test_event_entry> &events)
{
    DEFINE_TESTS_ERROR_CONTEXT("gen_safex_offer_001::verify_safex_offer");
    std::cout << "current_blockchain_height:" << c.get_current_blockchain_height() << " get_blockchain_total_transactions:" << c.get_blockchain_total_transactions() << std::endl;

    CHECK_TEST_CONDITION(c.get_current_blockchain_height() == gen_safex_offer_001::expected_blockchain_height);
    CHECK_TEST_CONDITION(c.get_blockchain_total_transactions() == gen_safex_offer_001::expected_blockchain_total_transactions);

    std::list<cryptonote::block> block_list;
    bool r = c.get_blocks((uint64_t)0, gen_safex_offer_001::expected_blockchain_height, block_list);
    CHECK_TEST_CONDITION(r);

    cryptonote::account_base alice_account = boost::get<cryptonote::account_base>(events[1]);
    cryptonote::account_base bob_account = boost::get<cryptonote::account_base>(events[2]);
    cryptonote::account_base daniel_account = boost::get<cryptonote::account_base>(events[3]);

    std::vector<cryptonote::block> chain;
    map_hash2tx_t mtx;
    std::vector<cryptonote::block> blocks(block_list.begin(), block_list.end());
    bool re = find_block_chain(events, chain, mtx, get_block_hash(blocks.back()));
    CHECK_TEST_CONDITION(re);
    //Check safex account
    crypto::public_key pkey{};
    const safex::account_username username01{safex_account_alice.username};
    c.get_blockchain_storage().get_safex_account_public_key(username01, pkey);
    CHECK_EQ(memcmp((void *)&pkey, (void *)&expected_alice_account_key, sizeof(pkey)), 0);

    crypto::public_key pkey2{};
    const safex::account_username username02{safex_account_bob.username};
    c.get_blockchain_storage().get_safex_account_public_key(username02, pkey2);
    CHECK_EQ(memcmp((void *)&pkey2, (void *)&expected_bob_account_key, sizeof(pkey2)), 0);

    crypto::public_key pkey3{};
    const safex::account_username username03{safex_account_daniel.username};
    c.get_blockchain_storage().get_safex_account_public_key(username03, pkey3);
    CHECK_EQ(memcmp((void *)&pkey3, (void *)&expected_daniel_account_key, sizeof(pkey3)), 0);


  std::vector<uint8_t> accdata01;
  c.get_blockchain_storage().get_safex_account_data(username01, accdata01);
  CHECK_TEST_CONDITION(std::equal(expected_alice_account_data.begin(), expected_alice_account_data.end(), accdata01.begin()));


  std::vector<uint8_t> accdata02;
  c.get_blockchain_storage().get_safex_account_data(username02, accdata02);
  CHECK_TEST_CONDITION(std::equal(expected_bob_account_data.begin(), expected_bob_account_data.end(), accdata02.begin()));

  //Check alice safex offer
  std::string offer_seller;
  c.get_blockchain_storage().get_safex_offer_seller(expected_alice_safex_offer.offer_id,offer_seller);
  CHECK_TEST_CONDITION(expected_alice_safex_offer.seller.compare(offer_seller) == 0);

    uint64_t offer_price;
  c.get_blockchain_storage().get_safex_offer_price(expected_alice_safex_offer.offer_id,offer_price);
  CHECK_EQ(expected_alice_safex_offer.price, offer_price);

  uint64_t offer_quantity;
  c.get_blockchain_storage().get_safex_offer_quantity(expected_alice_safex_offer.offer_id,offer_quantity);
  CHECK_EQ(expected_alice_safex_offer.quantity, offer_quantity);

  bool offer_active;
  c.get_blockchain_storage().get_safex_offer_active_status(expected_alice_safex_offer.offer_id,offer_active);
  CHECK_EQ(expected_alice_safex_offer.active, offer_active);

  safex::safex_offer sfx_offer;
  c.get_blockchain_storage().get_safex_offer(expected_alice_safex_offer.offer_id,sfx_offer);
  CHECK_TEST_CONDITION(expected_alice_safex_offer.title.compare(sfx_offer.title) == 0);
  CHECK_EQ(expected_alice_safex_offer.seller_private_view_key, sfx_offer.seller_private_view_key);
  CHECK_TEST_CONDITION(expected_alice_safex_offer.seller_address == sfx_offer.seller_address);

  CHECK_EQ(expected_alice_safex_offer.price_peg_used, sfx_offer.price_peg_used);
  CHECK_EQ(expected_alice_safex_offer.price_peg_id, sfx_offer.price_peg_id);
  CHECK_EQ(expected_alice_safex_offer.min_sfx_price, sfx_offer.min_sfx_price);
  
  CHECK_TEST_CONDITION(std::equal(sfx_offer.description.begin(), sfx_offer.description.end(), expected_alice_safex_offer.description.begin()));

  //Check bob safex offer
  c.get_blockchain_storage().get_safex_offer_seller(expected_bob_safex_offer.offer_id,offer_seller);
  CHECK_TEST_CONDITION(expected_bob_safex_offer.seller.compare(offer_seller) == 0);

  c.get_blockchain_storage().get_safex_offer_price(expected_bob_safex_offer.offer_id,offer_price);
  CHECK_EQ(expected_bob_safex_offer.price, offer_price);

  c.get_blockchain_storage().get_safex_offer_quantity(expected_bob_safex_offer.offer_id,offer_quantity);
  CHECK_EQ(expected_bob_safex_offer.quantity, offer_quantity);

  c.get_blockchain_storage().get_safex_offer_active_status(expected_bob_safex_offer.offer_id,offer_active);
  CHECK_EQ(expected_bob_safex_offer.active, offer_active);

  c.get_blockchain_storage().get_safex_offer(expected_bob_safex_offer.offer_id,sfx_offer);
  CHECK_TEST_CONDITION(expected_bob_safex_offer.title.compare(sfx_offer.title) == 0);
  CHECK_EQ(expected_bob_safex_offer.seller_private_view_key, sfx_offer.seller_private_view_key);
  CHECK_TEST_CONDITION(expected_bob_safex_offer.seller_address == sfx_offer.seller_address);

  CHECK_EQ(expected_bob_safex_offer.price_peg_used, sfx_offer.price_peg_used);
  CHECK_EQ(expected_bob_safex_offer.price_peg_id, sfx_offer.price_peg_id);
  CHECK_EQ(expected_bob_safex_offer.min_sfx_price, sfx_offer.min_sfx_price);

  CHECK_TEST_CONDITION(std::equal(sfx_offer.description.begin(), sfx_offer.description.end(), expected_bob_safex_offer.description.begin()));


  //Print offers
  std::vector<safex::safex_offer> offers;
  bool result = c.get_safex_offers(offers);
  CHECK_TEST_CONDITION(result);

  std::cout << boost::format("%30s %20s %20s %30s %100s %20s") % "Offer title" %  "Price" % "Quantity" % "Seller" % "Description" % "Offer ID"<<std::endl;
  for(auto offer: offers)
    std::cout<< boost::format("%30s %20s %20s %30s %100s %20s") % offer.title % offer.price % offer.quantity % offer.seller %
                  std::string(begin(offer.description), end(offer.description)) % offer.offer_id<<std::endl;
  return true;
}
