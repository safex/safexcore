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
#include "block_reward.h"
#include "block_validation.h"
#include "chain_split_1.h"
#include "chain_switch_1.h"
#include "double_spend.h"
#include "integer_overflow.h"
#include "ring_signature_1.h"
#include "tx_validation.h"
#include "v2_tests.h"

/************************************************************************/
/*                                                                      */
/************************************************************************/
class gen_network_fee_001: public test_chain_unit_base
{
public:
    gen_network_fee_001();

  const std::string bitcoin_tx_hashes_str[6] = {"3b7ac2a66eded32dcdc61f0fec7e9ddb30ccb3c6f5f06c0743c786e979130c5f", "3c904e67190d2d8c5cc93147c1a3ead133c61fc3fa578915e9bf95544705e63c", "2d825e690c4cb904556285b74a6ce565f16ba9d2f09784a7e5be5f7cdb05ae1d", "89352ec1749c872146eabddd56cd0d1492a3be6d2f9df98f6fbbc0d560120182", "80220aec436a2298bae6b35c920017d36646cda874a0516e121e658a888d2b55", "361074a34cf1723c7f797f2764b4c34a8e1584475c28503867778ca90bebbc0a"};

  bool generate(std::vector<test_event_entry> &events);
  bool verify_network_fee(cryptonote::core &c, size_t ev_index, const std::vector<test_event_entry> &events);
  crypto::hash get_hash_from_string(const std::string hashstr);

  static const size_t expected_blockchain_total_transactions = 385;
  static const size_t expected_blockchain_height = 371;

  static const uint64_t expected_alice_token_balance = 120000 * SAFEX_TOKEN;
  static const uint64_t expected_bob_token_balance = 40000 * SAFEX_TOKEN;
  static const uint64_t expected_daniel_token_balance = 0 * SAFEX_TOKEN;

  static const uint64_t expected_locked_tokens = 90000 * SAFEX_TOKEN;

};

