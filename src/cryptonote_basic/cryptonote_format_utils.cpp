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

#include "include_base_utils.h"
using namespace epee;

#include <atomic>
#include <boost/algorithm/string.hpp>
#include "wipeable_string.h"
#include "string_tools.h"
#include "serialization/string.h"
#include "cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "ringct/rctSigs.h"
#include "safex/command.h"

#undef SAFEX_DEFAULT_LOG_CATEGORY
#define SAFEX_DEFAULT_LOG_CATEGORY "cn"

#define ENCRYPTED_PAYMENT_ID_TAIL 0x8d

// #define ENABLE_HASH_CASH_INTEGRITY_CHECK

using namespace crypto;

static const uint64_t valid_decomposed_outputs[] = {
  (uint64_t)1, (uint64_t)2, (uint64_t)3, (uint64_t)4, (uint64_t)5, (uint64_t)6, (uint64_t)7, (uint64_t)8, (uint64_t)9, // 1 piconero
  (uint64_t)10, (uint64_t)20, (uint64_t)30, (uint64_t)40, (uint64_t)50, (uint64_t)60, (uint64_t)70, (uint64_t)80, (uint64_t)90,
  (uint64_t)100, (uint64_t)200, (uint64_t)300, (uint64_t)400, (uint64_t)500, (uint64_t)600, (uint64_t)700, (uint64_t)800, (uint64_t)900,
  (uint64_t)1000, (uint64_t)2000, (uint64_t)3000, (uint64_t)4000, (uint64_t)5000, (uint64_t)6000, (uint64_t)7000, (uint64_t)8000, (uint64_t)9000,
  (uint64_t)10000, (uint64_t)20000, (uint64_t)30000, (uint64_t)40000, (uint64_t)50000, (uint64_t)60000, (uint64_t)70000, (uint64_t)80000, (uint64_t)90000,
  (uint64_t)100000, (uint64_t)200000, (uint64_t)300000, (uint64_t)400000, (uint64_t)500000, (uint64_t)600000, (uint64_t)700000, (uint64_t)800000, (uint64_t)900000,
  (uint64_t)1000000, (uint64_t)2000000, (uint64_t)3000000, (uint64_t)4000000, (uint64_t)5000000, (uint64_t)6000000, (uint64_t)7000000, (uint64_t)8000000, (uint64_t)9000000, // 1 micronero
  (uint64_t)10000000, (uint64_t)20000000, (uint64_t)30000000, (uint64_t)40000000, (uint64_t)50000000, (uint64_t)60000000, (uint64_t)70000000, (uint64_t)80000000, (uint64_t)90000000,
  (uint64_t)100000000, (uint64_t)200000000, (uint64_t)300000000, (uint64_t)400000000, (uint64_t)500000000, (uint64_t)600000000, (uint64_t)700000000, (uint64_t)800000000, (uint64_t)900000000,
  (uint64_t)1000000000, (uint64_t)2000000000, (uint64_t)3000000000, (uint64_t)4000000000, (uint64_t)5000000000, (uint64_t)6000000000, (uint64_t)7000000000, (uint64_t)8000000000, (uint64_t)9000000000,
  (uint64_t)10000000000, (uint64_t)20000000000, (uint64_t)30000000000, (uint64_t)40000000000, (uint64_t)50000000000, (uint64_t)60000000000, (uint64_t)70000000000, (uint64_t)80000000000, (uint64_t)90000000000,
  (uint64_t)100000000000, (uint64_t)200000000000, (uint64_t)300000000000, (uint64_t)400000000000, (uint64_t)500000000000, (uint64_t)600000000000, (uint64_t)700000000000, (uint64_t)800000000000, (uint64_t)900000000000,
  (uint64_t)1000000000000, (uint64_t)2000000000000, (uint64_t)3000000000000, (uint64_t)4000000000000, (uint64_t)5000000000000, (uint64_t)6000000000000, (uint64_t)7000000000000, (uint64_t)8000000000000, (uint64_t)9000000000000,
  (uint64_t)10000000000000, (uint64_t)20000000000000, (uint64_t)30000000000000, (uint64_t)40000000000000, (uint64_t)50000000000000, (uint64_t)60000000000000, (uint64_t)70000000000000, (uint64_t)80000000000000, (uint64_t)90000000000000,
  (uint64_t)100000000000000, (uint64_t)200000000000000, (uint64_t)300000000000000, (uint64_t)400000000000000, (uint64_t)500000000000000, (uint64_t)600000000000000, (uint64_t)700000000000000, (uint64_t)800000000000000, (uint64_t)900000000000000,
  (uint64_t)1000000000000000, (uint64_t)2000000000000000, (uint64_t)3000000000000000, (uint64_t)4000000000000000, (uint64_t)5000000000000000, (uint64_t)6000000000000000, (uint64_t)7000000000000000, (uint64_t)8000000000000000, (uint64_t)9000000000000000,
  (uint64_t)10000000000000000, (uint64_t)20000000000000000, (uint64_t)30000000000000000, (uint64_t)40000000000000000, (uint64_t)50000000000000000, (uint64_t)60000000000000000, (uint64_t)70000000000000000, (uint64_t)80000000000000000, (uint64_t)90000000000000000,
  (uint64_t)100000000000000000, (uint64_t)200000000000000000, (uint64_t)300000000000000000, (uint64_t)400000000000000000, (uint64_t)500000000000000000, (uint64_t)600000000000000000, (uint64_t)700000000000000000, (uint64_t)800000000000000000, (uint64_t)900000000000000000,
  (uint64_t)1000000000000000000, (uint64_t)2000000000000000000, (uint64_t)3000000000000000000, (uint64_t)4000000000000000000, (uint64_t)5000000000000000000, (uint64_t)6000000000000000000, (uint64_t)7000000000000000000, (uint64_t)8000000000000000000, (uint64_t)9000000000000000000, // 1 meganero
  (uint64_t)10000000000000000000ull
};

static std::atomic<unsigned int> default_decimal_point(CRYPTONOTE_DISPLAY_DECIMAL_POINT);

static std::atomic<uint64_t> tx_hashes_calculated_count(0);
static std::atomic<uint64_t> tx_hashes_cached_count(0);
static std::atomic<uint64_t> block_hashes_calculated_count(0);
static std::atomic<uint64_t> block_hashes_cached_count(0);

#define CHECK_AND_ASSERT_THROW_MES_L1(expr, message) {if(!(expr)) {MWARNING(message); throw std::runtime_error(message);}}

namespace cryptonote
{
  static inline unsigned char *operator &(ec_point &point) {
    return &reinterpret_cast<unsigned char &>(point);
  }
  static inline const unsigned char *operator &(const ec_point &point) {
    return &reinterpret_cast<const unsigned char &>(point);
  }

  // a copy of rct::addKeys, since we can't link to libringct to avoid circular dependencies
  static void add_public_key(crypto::public_key &AB, const crypto::public_key &A, const crypto::public_key &B) {
      ge_p3 B2, A2;
      CHECK_AND_ASSERT_THROW_MES_L1(ge_frombytes_vartime(&B2, &B) == 0, "ge_frombytes_vartime failed at "+boost::lexical_cast<std::string>(__LINE__));
      CHECK_AND_ASSERT_THROW_MES_L1(ge_frombytes_vartime(&A2, &A) == 0, "ge_frombytes_vartime failed at "+boost::lexical_cast<std::string>(__LINE__));
      ge_cached tmp2;
      ge_p3_to_cached(&tmp2, &B2);
      ge_p1p1 tmp3;
      ge_add(&tmp3, &A2, &tmp2);
      ge_p1p1_to_p3(&A2, &tmp3);
      ge_p3_tobytes(&AB, &A2);
  }
}

namespace cryptonote
{
  //---------------------------------------------------------------
  void get_transaction_prefix_hash(const transaction_prefix& tx, crypto::hash& h)
  {
    std::ostringstream s;
    binary_archive<true> a(s);
    ::serialization::serialize(a, const_cast<transaction_prefix&>(tx));
    crypto::cn_fast_hash(s.str().data(), s.str().size(), h);
  }
  //---------------------------------------------------------------
  crypto::hash get_transaction_prefix_hash(const transaction_prefix& tx)
  {
    crypto::hash h = null_hash;
    get_transaction_prefix_hash(tx, h);
    return h;
  }
  //---------------------------------------------------------------
  bool expand_transaction_1(transaction &tx, bool base_only)
  {
    return true;
  }
  //---------------------------------------------------------------
  bool parse_and_validate_byte_array_from_blob(const blobdata& bytes_blob, std::vector<uint8_t> &data)
  {
    std::stringstream ss;
    ss << bytes_blob;
    binary_archive<false> ba(ss);
    bool r = ::serialization::serialize(ba, data);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse byte array from blob");
    return true;
  }
  //---------------------------------------------------------------
  bool parse_and_validate_tx_from_blob(const blobdata& tx_blob, transaction& tx)
  {
    std::stringstream ss;
    ss << tx_blob;
    binary_archive<false> ba(ss);
    bool r = ::serialization::serialize(ba, tx);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse transaction from blob");
    CHECK_AND_ASSERT_MES(expand_transaction_1(tx, false), false, "Failed to expand transaction data");
    tx.invalidate_hashes();
    return true;
  }
  //---------------------------------------------------------------
  bool parse_and_validate_tx_base_from_blob(const blobdata& tx_blob, transaction& tx)
  {
    std::stringstream ss;
    ss << tx_blob;
    binary_archive<false> ba(ss);
    bool r = tx.serialize_base(ba);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse transaction from blob");
    CHECK_AND_ASSERT_MES(expand_transaction_1(tx, true), false, "Failed to expand transaction data");
    return true;
  }
  //---------------------------------------------------------------
  bool parse_and_validate_tx_from_blob(const blobdata& tx_blob, transaction& tx, crypto::hash& tx_hash, crypto::hash& tx_prefix_hash)
  {
    std::stringstream ss;
    ss << tx_blob;
    binary_archive<false> ba(ss);
    bool r = ::serialization::serialize(ba, tx);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse transaction from blob");
    CHECK_AND_ASSERT_MES(expand_transaction_1(tx, false), false, "Failed to expand transaction data");
    tx.invalidate_hashes();
    //TODO: validate tx

    if(!get_transaction_hash(tx, tx_hash))
      return false;
    get_transaction_prefix_hash(tx, tx_prefix_hash);
    return true;
  }
  //---------------------------------------------------------------
  bool parse_and_validate_txout_to_script_from_blob(const blobdata& tx_blob, txout_to_script& txout)
  {
    std::stringstream ss;
    ss << tx_blob;
    binary_archive<false> ba(ss);
    bool r = ::serialization::serialize(ba, txout);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse txout_to_script from blob");
    return true;
  }
  //---------------------------------------------------------------
  bool generate_key_image_helper(const account_keys& ack, const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, const crypto::public_key& out_key, const crypto::public_key& tx_public_key, const std::vector<crypto::public_key>& additional_tx_public_keys, size_t real_output_index, keypair& in_ephemeral, crypto::key_image& ki, hw::device &hwdev)
  {
    crypto::key_derivation recv_derivation = AUTO_VAL_INIT(recv_derivation);
    bool r = hwdev.generate_key_derivation(tx_public_key, ack.m_view_secret_key, recv_derivation);
    if (!r)
    {
      MWARNING("key image helper: failed to generate_key_derivation(" << tx_public_key << ", " << ack.m_view_secret_key << ")");
      memcpy(&recv_derivation, rct::identity().bytes, sizeof(recv_derivation));
    }

    std::vector<crypto::key_derivation> additional_recv_derivations;
    for (size_t i = 0; i < additional_tx_public_keys.size(); ++i)
    {
      crypto::key_derivation additional_recv_derivation = AUTO_VAL_INIT(additional_recv_derivation);
      r = hwdev.generate_key_derivation(additional_tx_public_keys[i], ack.m_view_secret_key, additional_recv_derivation);
      if (!r)
      {
        MWARNING("key image helper: failed to generate_key_derivation(" << additional_tx_public_keys[i] << ", " << ack.m_view_secret_key << ")");
      }
      else
      {
        additional_recv_derivations.push_back(additional_recv_derivation);
      }
    }

    boost::optional<subaddress_receive_info> subaddr_recv_info = is_out_to_acc_precomp(subaddresses, out_key, recv_derivation, additional_recv_derivations, real_output_index, hwdev);
    CHECK_AND_ASSERT_MES(subaddr_recv_info, false, "key image helper: given output pubkey doesn't seem to belong to this address");

    return generate_key_image_helper_precomp(ack, out_key, subaddr_recv_info->derivation, real_output_index, subaddr_recv_info->index, in_ephemeral, ki, hwdev);
  }
  //---------------------------------------------------------------
  bool generate_key_image_helper_precomp(const account_keys& ack, const crypto::public_key& out_key, const crypto::key_derivation& recv_derivation, size_t real_output_index, const subaddress_index& received_index, keypair& in_ephemeral, crypto::key_image& ki, hw::device &hwdev)
  {
    if (ack.m_spend_secret_key == crypto::null_skey)
    {
      // for watch-only wallet, simply copy the known output pubkey
      in_ephemeral.pub = out_key;
      in_ephemeral.sec = crypto::null_skey;
    }
    else
    {
      // derive secret key with subaddress - step 1: original CN derivation
      crypto::secret_key scalar_step1;
      hwdev.derive_secret_key(recv_derivation, real_output_index, ack.m_spend_secret_key, scalar_step1); // computes Hs(a*R || idx) + b

      // step 2: add Hs(a || index_major || index_minor)
      crypto::secret_key subaddr_sk;
      crypto::secret_key scalar_step2;
      if (received_index.is_zero())
      {
        scalar_step2 = scalar_step1;    // treat index=(0,0) as a special case representing the main address
      }
      else
      {
        subaddr_sk = hwdev.get_subaddress_secret_key(ack.m_view_secret_key, received_index);
        hwdev.sc_secret_add(scalar_step2, scalar_step1,subaddr_sk);
      }

      in_ephemeral.sec = scalar_step2;

      if (ack.m_multisig_keys.empty())
      {
        // when not in multisig, we know the full spend secret key, so the output pubkey can be obtained by scalarmultBase
        CHECK_AND_ASSERT_MES(hwdev.secret_key_to_public_key(in_ephemeral.sec, in_ephemeral.pub), false, "Failed to derive public key");
      }
      else
      {
        // when in multisig, we only know the partial spend secret key. but we do know the full spend public key, so the output pubkey can be obtained by using the standard CN key derivation
        CHECK_AND_ASSERT_MES(hwdev.derive_public_key(recv_derivation, real_output_index, ack.m_account_address.m_spend_public_key, in_ephemeral.pub), false, "Failed to derive public key");
        // and don't forget to add the contribution from the subaddress part
        if (!received_index.is_zero())
        {
          crypto::public_key subaddr_pk;
          CHECK_AND_ASSERT_MES(hwdev.secret_key_to_public_key(subaddr_sk, subaddr_pk), false, "Failed to derive public key");
          add_public_key(in_ephemeral.pub, in_ephemeral.pub, subaddr_pk);
        }
      }

      CHECK_AND_ASSERT_MES(in_ephemeral.pub == out_key,
           false, "key image helper precomp: given output pubkey doesn't match the derived one");
    }

    hwdev.generate_key_image(in_ephemeral.pub, in_ephemeral.sec, ki);
    return true;
  }
  //---------------------------------------------------------------
  uint64_t power_integral(uint64_t a, uint64_t b)
  {
    if(b == 0)
      return 1;
    uint64_t total = a;
    for(uint64_t i = 1; i != b; i++)
      total *= a;
    return total;
  }
  //---------------------------------------------------------------
  bool parse_amount(uint64_t& amount, const std::string& str_amount_)
  {
    std::string str_amount = str_amount_;
    boost::algorithm::trim(str_amount);

    size_t point_index = str_amount.find_first_of('.');
    size_t fraction_size;
    if (std::string::npos != point_index)
    {
      fraction_size = str_amount.size() - point_index - 1;
      while (default_decimal_point < fraction_size && '0' == str_amount.back())
      {
        str_amount.erase(str_amount.size() - 1, 1);
        --fraction_size;
      }
      if (default_decimal_point < fraction_size)
        return false;
      str_amount.erase(point_index, 1);
    }
    else
    {
      fraction_size = 0;
    }

    if (str_amount.empty())
      return false;

    if (fraction_size < default_decimal_point)
    {
      str_amount.append(default_decimal_point - fraction_size, '0');
    }

    return string_tools::get_xtype_from_string(amount, str_amount);
  }
  //---------------------------------------------------------------
  bool get_tx_fee(const transaction& tx, uint64_t & fee)
  {
    uint64_t amount_in = 0;
    uint64_t amount_out = 0;

    for(auto& in: tx.vin)
    {
      auto cash_amount_opt = boost::apply_visitor(cash_amount_visitor(), in);
      if (!cash_amount_opt) continue;
      amount_in += *cash_amount_opt;
    }

    for(auto& o: tx.vout)
      amount_out += o.amount;

    CHECK_AND_ASSERT_MES(amount_in >= amount_out, false, "transaction spend (" << amount_out << ") more than it has inputed (" << amount_in << ")");
    fee = amount_in - amount_out;
    return true;
  }
  //---------------------------------------------------------------
  uint64_t get_tx_fee(const transaction& tx)
  {
    uint64_t r = 0;
    if(!get_tx_fee(tx, r))
      return 0;
    return r;
  }
  //---------------------------------------------------------------
  bool parse_tx_extra(const std::vector<uint8_t>& tx_extra, std::vector<tx_extra_field>& tx_extra_fields)
  {
    tx_extra_fields.clear();

    if(tx_extra.empty())
      return true;

    std::string extra_str(reinterpret_cast<const char*>(tx_extra.data()), tx_extra.size());
    std::istringstream iss(extra_str);
    binary_archive<false> ar(iss);

    bool eof = false;
    while (!eof)
    {
      tx_extra_field field;
      bool r = ::do_serialize(ar, field);
      CHECK_AND_NO_ASSERT_MES_L1(r, false, "failed to deserialize extra field. extra = " << string_tools::buff_to_hex_nodelimer(std::string(reinterpret_cast<const char*>(tx_extra.data()), tx_extra.size())));
      tx_extra_fields.push_back(field);

      std::ios_base::iostate state = iss.rdstate();
      eof = (EOF == iss.peek());
      iss.clear(state);
    }
    CHECK_AND_NO_ASSERT_MES_L1(::serialization::check_stream_state(ar), false, "failed to deserialize extra field. extra = " << string_tools::buff_to_hex_nodelimer(std::string(reinterpret_cast<const char*>(tx_extra.data()), tx_extra.size())));

    return true;
  }
  //---------------------------------------------------------------
  crypto::public_key get_tx_pub_key_from_extra(const std::vector<uint8_t>& tx_extra, size_t pk_index)
  {
    std::vector<tx_extra_field> tx_extra_fields;
    parse_tx_extra(tx_extra, tx_extra_fields);

    tx_extra_pub_key pub_key_field;
    if(!find_tx_extra_field_by_type(tx_extra_fields, pub_key_field, pk_index))
      return null_pkey;

    return pub_key_field.pub_key;
  }
  //---------------------------------------------------------------
  crypto::public_key get_tx_pub_key_from_extra(const transaction_prefix& tx_prefix, size_t pk_index)
  {
    return get_tx_pub_key_from_extra(tx_prefix.extra, pk_index);
  }
  //---------------------------------------------------------------
  crypto::public_key get_tx_pub_key_from_extra(const transaction& tx, size_t pk_index)
  {
    return get_tx_pub_key_from_extra(tx.extra, pk_index);
  }
  //---------------------------------------------------------------
  bool add_tx_pub_key_to_extra(transaction& tx, const crypto::public_key& tx_pub_key)
  {
    return add_tx_pub_key_to_extra(tx.extra, tx_pub_key);
  }
  //---------------------------------------------------------------
  bool add_tx_pub_key_to_extra(transaction_prefix& tx, const crypto::public_key& tx_pub_key)
  {
    return add_tx_pub_key_to_extra(tx.extra, tx_pub_key);
  }
  //---------------------------------------------------------------
  bool add_tx_pub_key_to_extra(std::vector<uint8_t>& tx_extra, const crypto::public_key& tx_pub_key)
  {
    tx_extra.resize(tx_extra.size() + 1 + sizeof(crypto::public_key));
    tx_extra[tx_extra.size() - 1 - sizeof(crypto::public_key)] = TX_EXTRA_TAG_PUBKEY;
    *reinterpret_cast<crypto::public_key*>(&tx_extra[tx_extra.size() - sizeof(crypto::public_key)]) = tx_pub_key;
    return true;
  }

  bool add_bitcoin_hash_to_extra(std::vector<uint8_t>& tx_extra, const crypto::hash& bitcoin_hash)
  {
    tx_extra.resize(tx_extra.size() + 1 + sizeof(crypto::hash));
    tx_extra[tx_extra.size() - 1 - sizeof(crypto::hash)] = TX_EXTRA_BITCOIN_HASH;
    *reinterpret_cast<crypto::hash*>(&tx_extra[tx_extra.size() - sizeof(crypto::hash)]) = bitcoin_hash;
    return true;
  }
  //---------------------------------------------------------------
  bool add_migration_pub_keys_to_extra(std::vector<uint8_t>& tx_extra, const std::vector<crypto::public_key>& migration_pub_keys)
  {
    // convert to variant
    tx_extra_field field = tx_extra_migration_pub_keys{ migration_pub_keys };
    // serialize
    std::ostringstream oss;
    binary_archive<true> ar(oss);
    bool r = ::do_serialize(ar, field);
    CHECK_AND_NO_ASSERT_MES_L1(r, false, "failed to serialize tx extra migration pub keys");
    // append
    std::string tx_extra_str = oss.str();
    size_t pos = tx_extra.size();
    tx_extra.resize(tx_extra.size() + tx_extra_str.size());
    memcpy(&tx_extra[pos], tx_extra_str.data(), tx_extra_str.size());
    return true;
  }

  std::vector<crypto::public_key> get_migration_pub_keys_from_extra(const std::vector<uint8_t>& tx_extra)
  {
    // parse
    std::vector<tx_extra_field> tx_extra_fields;
    parse_tx_extra(tx_extra, tx_extra_fields);
    // find corresponding field
    tx_extra_migration_pub_keys migration_pub_keys;
    if(!find_tx_extra_field_by_type(tx_extra_fields, migration_pub_keys))
      return {};
    return migration_pub_keys.data;
  }

    crypto::public_key get_migration_pub_key_from_extra(const std::vector<uint8_t>& tx_extra, const int index)
  {
    return get_migration_pub_keys_from_extra(tx_extra)[index];
  }
  //---------------------------------------------------------------
  std::vector<crypto::public_key> get_additional_tx_pub_keys_from_extra(const std::vector<uint8_t>& tx_extra)
  {
    // parse
    std::vector<tx_extra_field> tx_extra_fields;
    parse_tx_extra(tx_extra, tx_extra_fields);
    // find corresponding field
    tx_extra_additional_pub_keys additional_pub_keys;
    if(!find_tx_extra_field_by_type(tx_extra_fields, additional_pub_keys))
      return {};
    return additional_pub_keys.data;
  }
  //---------------------------------------------------------------
  std::vector<crypto::public_key> get_additional_tx_pub_keys_from_extra(const transaction_prefix& tx)
  {
    return get_additional_tx_pub_keys_from_extra(tx.extra);
  }
  //---------------------------------------------------------------
  bool add_additional_tx_pub_keys_to_extra(std::vector<uint8_t>& tx_extra, const std::vector<crypto::public_key>& additional_pub_keys)
  {
    // convert to variant
    tx_extra_field field = tx_extra_additional_pub_keys{ additional_pub_keys };
    // serialize
    std::ostringstream oss;
    binary_archive<true> ar(oss);
    bool r = ::do_serialize(ar, field);
    CHECK_AND_NO_ASSERT_MES_L1(r, false, "failed to serialize tx extra additional tx pub keys");
    // append
    std::string tx_extra_str = oss.str();
    size_t pos = tx_extra.size();
    tx_extra.resize(tx_extra.size() + tx_extra_str.size());
    memcpy(&tx_extra[pos], tx_extra_str.data(), tx_extra_str.size());
    return true;
  }
  //---------------------------------------------------------------
  bool add_extra_nonce_to_tx_extra(std::vector<uint8_t>& tx_extra, const blobdata& extra_nonce)
  {
    CHECK_AND_ASSERT_MES(extra_nonce.size() <= TX_EXTRA_NONCE_MAX_COUNT, false, "extra nonce could be 255 bytes max");
    size_t start_pos = tx_extra.size();
    tx_extra.resize(tx_extra.size() + 2 + extra_nonce.size());
    //write tag
    tx_extra[start_pos] = TX_EXTRA_NONCE;
    //write len
    ++start_pos;
    tx_extra[start_pos] = static_cast<uint8_t>(extra_nonce.size());
    //write data
    ++start_pos;
    memcpy(&tx_extra[start_pos], extra_nonce.data(), extra_nonce.size());
    return true;
  }
  //---------------------------------------------------------------
  bool remove_field_from_tx_extra(std::vector<uint8_t>& tx_extra, const std::type_info &type)
  {
    if (tx_extra.empty())
      return true;
    std::string extra_str(reinterpret_cast<const char*>(tx_extra.data()), tx_extra.size());
    std::istringstream iss(extra_str);
    binary_archive<false> ar(iss);
    std::ostringstream oss;
    binary_archive<true> newar(oss);

    bool eof = false;
    while (!eof)
    {
      tx_extra_field field;
      bool r = ::do_serialize(ar, field);
      CHECK_AND_NO_ASSERT_MES_L1(r, false, "failed to deserialize extra field. extra = " << string_tools::buff_to_hex_nodelimer(std::string(reinterpret_cast<const char*>(tx_extra.data()), tx_extra.size())));
      if (field.type() != type)
        ::do_serialize(newar, field);

      std::ios_base::iostate state = iss.rdstate();
      eof = (EOF == iss.peek());
      iss.clear(state);
    }
    CHECK_AND_NO_ASSERT_MES_L1(::serialization::check_stream_state(ar), false, "failed to deserialize extra field. extra = " << string_tools::buff_to_hex_nodelimer(std::string(reinterpret_cast<const char*>(tx_extra.data()), tx_extra.size())));
    tx_extra.clear();
    std::string s = oss.str();
    tx_extra.reserve(s.size());
    std::copy(s.begin(), s.end(), std::back_inserter(tx_extra));
    return true;
  }
  //---------------------------------------------------------------
  void set_payment_id_to_tx_extra_nonce(blobdata& extra_nonce, const crypto::hash& payment_id)
  {
    extra_nonce.clear();
    extra_nonce.push_back(TX_EXTRA_NONCE_PAYMENT_ID);
    const uint8_t* payment_id_ptr = reinterpret_cast<const uint8_t*>(&payment_id);
    std::copy(payment_id_ptr, payment_id_ptr + sizeof(payment_id), std::back_inserter(extra_nonce));
  }
  //---------------------------------------------------------------
  void set_encrypted_payment_id_to_tx_extra_nonce(blobdata& extra_nonce, const crypto::hash8& payment_id)
  {
    extra_nonce.clear();
    extra_nonce.push_back(TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID);
    const uint8_t* payment_id_ptr = reinterpret_cast<const uint8_t*>(&payment_id);
    std::copy(payment_id_ptr, payment_id_ptr + sizeof(payment_id), std::back_inserter(extra_nonce));
  }
  //---------------------------------------------------------------
  bool get_payment_id_from_tx_extra_nonce(const blobdata& extra_nonce, crypto::hash& payment_id)
  {
    if(sizeof(crypto::hash) + 1 != extra_nonce.size())
      return false;
    if(TX_EXTRA_NONCE_PAYMENT_ID != extra_nonce[0])
      return false;
    payment_id = *reinterpret_cast<const crypto::hash*>(extra_nonce.data() + 1);
    return true;
  }
  //---------------------------------------------------------------
  bool get_encrypted_payment_id_from_tx_extra_nonce(const blobdata& extra_nonce, crypto::hash8& payment_id)
  {
    if(sizeof(crypto::hash8) + 1 != extra_nonce.size())
      return false;
    if (TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID != extra_nonce[0])
      return false;
    payment_id = *reinterpret_cast<const crypto::hash8*>(extra_nonce.data() + 1);
    return true;
  }
  //---------------------------------------------------------------
  bool get_inputs_cash_amount(const transaction &tx, uint64_t &money)
  {
    money = 0;
    for(const auto& in: tx.vin)
    {
        uint64_t amount = *boost::apply_visitor(cash_amount_visitor(), in);
        money += amount;
    }
    return true;
  }
  //---------------------------------------------------------------
  bool get_inputs_token_amount(const transaction& tx, uint64_t& tokens)
  {
    tokens = 0;
    for(const auto& in: tx.vin)
    {
        uint64_t token_amount = *boost::apply_visitor(token_amount_visitor(), in);
        tokens += token_amount;
    }
    return true;
  }
  //---------------------------------------------------------------
  uint64_t get_input_token_migration_amount(const transaction &tx)
  {
    uint64_t migrated_tokens = 0;
    for (const auto &vin: tx.vin)
    {
      if (vin.type() == typeid(txin_token_migration))
      {
        migrated_tokens += boost::get<txin_token_migration>(vin).token_amount;
      }
    }
    return migrated_tokens;
  }
  //---------------------------------------------------------------
  int64_t get_token_staked_amount(const transaction &tx)
  {
    int64_t staked_tokens = 0;
    //count unstaked tokens
    for (const auto &vin: tx.vin)
    {
      if (vin.type() == typeid(txin_to_script))
      {
        const txin_to_script& in = boost::get<txin_to_script>(vin);
        if (in.command_type == safex::command_t::token_unstake) {
          staked_tokens -= in.token_amount;
        }
      }
    }

    //count staked tokens
    for (const auto &vout: tx.vout)
    {
      if (vout.target.type() == typeid(txout_to_script) && get_tx_out_type(vout.target) == cryptonote::tx_out_type::out_staked_token)
      {
        const txout_to_script& out = boost::get<txout_to_script>(vout.target);
        if (out.output_type == static_cast<uint8_t>(tx_out_type::out_staked_token)) {
          staked_tokens += vout.token_amount;
        }
      }
    }


    return staked_tokens;
  }
  //---------------------------------------------------------------
  uint64_t get_collected_network_fee_amount(const transaction &tx)
  {
    uint64_t network_fee = 0;

    //count collected fee
    for (const auto &vout: tx.vout)
    {
      if (vout.target.type() == typeid(txout_to_script) && get_tx_out_type(vout.target) == cryptonote::tx_out_type::out_network_fee)
      {
        const txout_to_script& out = boost::get<txout_to_script>(vout.target);
        if (out.output_type == static_cast<uint8_t>(tx_out_type::out_network_fee)) {
          network_fee += vout.amount;
        }
      }
    }

    return network_fee;
  }
  //---------------------------------------------------------------
  uint64_t get_network_distributed_fee_amount(const transaction &tx)
  {
    uint64_t network_fee = 0;
    //count distributed network fee
    for (const auto &vin: tx.vin)
    {
      if (vin.type() == typeid(txin_to_script))
      {
        const txin_to_script& in = boost::get<txin_to_script>(vin);
        if (in.command_type == safex::command_t::token_unstake) {
          network_fee += in.amount;
        }
      }
    }

    return network_fee;
  }
  //---------------------------------------------------------------
  uint64_t get_block_height(const block& b)
  {
    CHECK_AND_ASSERT_MES(b.miner_tx.vin.size() == 1, 0, "wrong miner tx in block: " << get_block_hash(b) << ", b.miner_tx.vin.size() != 1");
    CHECKED_GET_SPECIFIC_VARIANT(b.miner_tx.vin[0], const txin_gen, coinbase_in, 0);
    return coinbase_in.height;
  }
  //---------------------------------------------------------------
  bool check_inputs_types_supported(const transaction& tx)
  {
    for(const auto& in: tx.vin)
    {
      if (tx.version == 1) {
          CHECK_AND_ASSERT_MES((in.type() == typeid(txin_to_key))
              || (in.type() == typeid(txin_token_migration)) || (in.type() == typeid(txin_token_to_key)),
              false, "wrong variant type: " << in.type().name() << ", expected " << typeid(txin_to_key).name() << ", in transaction id=" << get_transaction_hash(tx));
      } else if (tx.version == 2) {
          CHECK_AND_ASSERT_MES((in.type() == typeid(txin_to_script)) || (in.type() == typeid(txin_to_key))
                                   || (in.type() == typeid(txin_token_migration)) || (in.type() == typeid(txin_token_to_key)),
                               false, "wrong variant type: " << in.type().name() << ", expected " << typeid(txin_to_key).name()
                                        << " or " << typeid(txin_token_to_key).name() << " or " << typeid(txin_token_migration).name()
                                        << " or " << typeid(txin_to_script).name() << ", in transaction id=" << get_transaction_hash(tx));
      }
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool check_outs_valid(const transaction &tx) {
      for (const tx_out &out: tx.vout) {

          if (tx.version == 1) {
              CHECK_AND_ASSERT_MES(((out.target.type() == typeid(txout_to_key)) || (out.target.type() == typeid(txout_token_to_key))),
                      false, "wrong variant type: " << out.target.type().name() << ", expected " << typeid(txout_to_key).name()
                      << " or " << typeid(txout_token_to_key).name() << ", in transaction id=" << get_transaction_hash(tx));
          } else if (tx.version == 2) {
              CHECK_AND_ASSERT_MES(((out.target.type() == typeid(txout_to_key)) ||
                                    (out.target.type() == typeid(txout_token_to_key)) ||
                                    (out.target.type() == typeid(txout_to_script))),
                                   false, "wrong variant type for advanced transaction: " << out.target.type().name() << ", expected " << typeid(txout_to_key).name()
                                    << " or " << typeid(txout_token_to_key).name() << " or " << typeid(txout_to_script).name() << ", in transaction id="
                                    << get_transaction_hash(tx));

          }


        CHECK_AND_NO_ASSERT_MES((0 < out.amount || 0 < out.token_amount || (out.target.type() == typeid(txout_to_script))), false,
                                "zero amount output in transaction id=" << get_transaction_hash(tx));




          auto pkey_opt = boost::apply_visitor(destination_public_key_visitor(), out.target);
          if (!pkey_opt)
              return false;

          if (!check_key(*pkey_opt))
              return false;
      }
      return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool check_money_overflow(const transaction& tx)
  {
    return check_inputs_overflow(tx) && check_outs_overflow(tx);
  }
  //---------------------------------------------------------------
  bool check_inputs_overflow(const transaction& tx)
  {
    uint64_t total_cash = 0;
    uint64_t total_tokens = 0;
    for(const auto& in: tx.vin)
    {
      uint64_t cash_amount = *boost::apply_visitor(cash_amount_visitor(), in);
      uint64_t token_amount = *boost::apply_visitor(token_amount_visitor(), in);

      if(total_cash > cash_amount + total_cash)
        return false;

      if(total_tokens > token_amount + total_tokens)
        return false;
      if(token_amount >= 100000000*SAFEX_TOKEN)
        return false;

      total_cash += cash_amount;
      total_tokens += token_amount;
    }

    return true;
  }
  //---------------------------------------------------------------
  bool check_outs_overflow(const transaction& tx)
  {
    uint64_t total_cash = 0;
    uint64_t total_tokens = 0;
    for(const auto& o: tx.vout)
    {
      if(total_cash > o.amount + total_cash)
        return false;
      total_cash += o.amount;

      if(total_tokens > o.token_amount + total_tokens)
        return false;
      if(o.token_amount >= 100000000*SAFEX_TOKEN)
        return false;
      total_tokens += o.token_amount;
    }
    return true;
  }
  //---------------------------------------------------------------
  uint64_t get_outs_cash_amount(const transaction &tx)
  {
    uint64_t outputs_cash = 0;
    for(const auto& o: tx.vout)
      outputs_cash += o.amount;
    return outputs_cash;
  }
  //---------------------------------------------------------------
  uint64_t get_outs_token_amount(const transaction& tx)
  {
    uint64_t output_tokens = 0;
    for(const auto& o: tx.vout)
      output_tokens += o.token_amount;
    return output_tokens;
  }
  //---------------------------------------------------------------
  std::string short_hash_str(const crypto::hash& h)
  {
    std::string res = string_tools::pod_to_hex(h);
    CHECK_AND_ASSERT_MES(res.size() == 64, res, "wrong hash256 with string_tools::pod_to_hex conversion");
    auto erased_pos = res.erase(8, 48);
    res.insert(8, "....");
    return res;
  }
  //---------------------------------------------------------------
  bool is_out_to_acc(const account_keys& acc, const crypto::public_key& out_key, const crypto::public_key& tx_pub_key, const std::vector<crypto::public_key>& additional_tx_pub_keys, size_t output_index)
  {
    crypto::key_derivation derivation;
    bool r = acc.get_device().generate_key_derivation(tx_pub_key, acc.m_view_secret_key, derivation);
    CHECK_AND_ASSERT_MES(r, false, "Failed to generate key derivation");
    crypto::public_key pk;
    r = acc.get_device().derive_public_key(derivation, output_index, acc.m_account_address.m_spend_public_key, pk);
    CHECK_AND_ASSERT_MES(r, false, "Failed to derive public key");
    if (pk == out_key)
      return true;
    // try additional tx pubkeys if available
    if (!additional_tx_pub_keys.empty())
    {
      CHECK_AND_ASSERT_MES(output_index < additional_tx_pub_keys.size(), false, "wrong number of additional tx pubkeys");
      r = acc.get_device().generate_key_derivation(additional_tx_pub_keys[output_index], acc.m_view_secret_key, derivation);
      CHECK_AND_ASSERT_MES(r, false, "Failed to generate key derivation");
      r = acc.get_device().derive_public_key(derivation, output_index, acc.m_account_address.m_spend_public_key, pk);
      CHECK_AND_ASSERT_MES(r, false, "Failed to derive public key");
      return pk == out_key;
    }
    return false;
  }
  //---------------------------------------------------------------
  bool is_safex_out_to_acc(const  crypto::public_key& safex_acc_pkey, const crypto::public_key& out_key)
  {
    if (safex_acc_pkey == out_key)
      return true;

    return false;
  }
  //---------------------------------------------------------------

  bool is_create_safex_account_token_fee(const std::vector<tx_out>& vout, const crypto::public_key& output_token_pubkey)
  {
    bool is_token_fee = true;
    bool is_create_account = false;
    std::array<char,32> iterator_pubkey;
    std::array<char,32> token_pubkey;
    std::copy(std::begin(output_token_pubkey.data), std::end(output_token_pubkey.data), std::begin(token_pubkey));
    for(auto tx_output: vout){
        // Only one output with SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_FEE token amount is the actual fee. We search for first isntance
        if(tx_output.target.type() == typeid(txout_token_to_key) && tx_output.token_amount == SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_FEE){
            const txout_token_to_key &out = boost::get<txout_token_to_key>(tx_output.target);
            std::copy(std::begin(out.key.data), std::end(out.key.data), std::begin(iterator_pubkey));

            if(iterator_pubkey < token_pubkey)
              is_token_fee = false;
        }


      if(tx_output.target.type() == typeid(txout_to_script) && get_tx_out_type(tx_output.target) == cryptonote::tx_out_type::out_safex_account)
          is_create_account = true;
    }
  return is_token_fee && is_create_account;
  }
  //---------------------------------------------------------------
  boost::optional<subaddress_receive_info> is_out_to_acc_precomp(const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, const crypto::public_key& out_key, const crypto::key_derivation& derivation, const std::vector<crypto::key_derivation>& additional_derivations, size_t output_index, hw::device &hwdev)
  {
    // try the shared tx pubkey
    crypto::public_key subaddress_spendkey;
    hwdev.derive_subaddress_public_key(out_key, derivation, output_index, subaddress_spendkey);
    auto found = subaddresses.find(subaddress_spendkey);
    if (found != subaddresses.end())
      return subaddress_receive_info{ found->second, derivation };
    // try additional tx pubkeys if available
    if (!additional_derivations.empty())
    {
      CHECK_AND_ASSERT_MES(output_index < additional_derivations.size(), boost::none, "wrong number of additional derivations");
      hwdev.derive_subaddress_public_key(out_key, additional_derivations[output_index], output_index, subaddress_spendkey);
      found = subaddresses.find(subaddress_spendkey);
      if (found != subaddresses.end())
        return subaddress_receive_info{ found->second, additional_derivations[output_index] };
    }
    return boost::none;
  }
  //---------------------------------------------------------------
  boost::optional<subaddress_receive_info> is_safex_output_to_acc_precomp(const safex::safex_account_keys& acc, const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, const crypto::public_key& out_key, size_t output_index, hw::device &hwdev)
  {
    if (acc.m_public_key == out_key) {
      //my account output
      return subaddress_receive_info{subaddress_index{0,0}, crypto::key_derivation{}};
    }

    return boost::none;
  }
  //---------------------------------------------------------------
  bool lookup_acc_outs(const account_keys& acc, const transaction& tx, std::vector<size_t>& outs, uint64_t& money_transfered)
  {
    crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(tx);
    if(null_pkey == tx_pub_key)
      return false;
    std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(tx);
    return lookup_acc_outs(acc, tx, tx_pub_key, additional_tx_pub_keys, outs, money_transfered);
  }
  //---------------------------------------------------------------
  bool lookup_acc_outs(const account_keys& acc, const transaction& tx, const crypto::public_key& tx_pub_key, const std::vector<crypto::public_key>& additional_tx_pub_keys, std::vector<size_t>& outs, uint64_t& money_transfered)
  {
    CHECK_AND_ASSERT_MES(additional_tx_pub_keys.empty() || additional_tx_pub_keys.size() == tx.vout.size(), false, "wrong number of additional pubkeys" );
    money_transfered = 0;
    size_t i = 0;
    for(const tx_out& o:  tx.vout)
    {
      CHECK_AND_ASSERT_MES(o.target.type() ==  typeid(txout_to_key), false, "wrong type id in transaction out" );
      if(is_out_to_acc(acc, boost::get<txout_to_key>(o.target).key, tx_pub_key, additional_tx_pub_keys, i))
      {
        outs.push_back(i);
        money_transfered += o.amount;
      }
      i++;
    }
    return true;
  }
  //---------------------------------------------------------------
  void get_blob_hash(const blobdata& blob, crypto::hash& res)
  {
    cn_fast_hash(blob.data(), blob.size(), res);
  }
  //---------------------------------------------------------------
  void set_default_decimal_point(unsigned int decimal_point)
  {
    switch (decimal_point)
    {
      case 10:
      case 9:
      case 8:
      case 7:
      case 6:
      case 3:
      case 0:
        default_decimal_point = decimal_point;
        break;
      default:
        ASSERT_MES_AND_THROW("Invalid decimal point specification: " << decimal_point);
    }
  }
  //---------------------------------------------------------------
  unsigned int get_default_decimal_point()
  {
    return default_decimal_point;
  }
  //---------------------------------------------------------------
  std::string get_unit(unsigned int decimal_point)
  {
    if (decimal_point == (unsigned int)-1)
      decimal_point = default_decimal_point;
    switch (std::atomic_load(&default_decimal_point))
    {
      case 10:
              return "safex cash";
      case 9:
        return "cabral";
      case 8:
        return "cortez";
      case 7:
        return "todor";
      case 6:
        return "dabek";
      default:
        ASSERT_MES_AND_THROW("Invalid decimal point specification: " << default_decimal_point);
    }
  }
  //---------------------------------------------------------------
  std::string print_money(uint64_t amount, unsigned int decimal_point)
  {
    if (decimal_point == (unsigned int)-1)
      decimal_point = default_decimal_point;
    std::string s = std::to_string(amount);
    if(s.size() < decimal_point+1)
    {
      s.insert(0, decimal_point+1 - s.size(), '0');
    }
    if (decimal_point > 0)
      s.insert(s.size() - decimal_point, ".");
    return s;
  }
  //---------------------------------------------------------------
  crypto::hash get_blob_hash(const blobdata& blob)
  {
    crypto::hash h = null_hash;
    get_blob_hash(blob, h);
    return h;
  }
  //---------------------------------------------------------------
  crypto::hash get_transaction_hash(const transaction& t)
  {
    crypto::hash h = null_hash;
    get_transaction_hash(t, h, NULL);
    CHECK_AND_ASSERT_THROW_MES(get_transaction_hash(t, h, NULL), "Failed to calculate transaction hash");
    return h;
  }
  //---------------------------------------------------------------
  bool get_transaction_hash(const transaction& t, crypto::hash& res)
  {
    return get_transaction_hash(t, res, NULL);
  }
  //---------------------------------------------------------------
  bool calculate_transaction_hash(const transaction &t, crypto::hash &res, size_t *blob_size)
  {
    size_t ignored_blob_size, &blob_size_ref = blob_size ? *blob_size : ignored_blob_size;
    return get_object_hash(t, res, blob_size_ref);

  }
  //---------------------------------------------------------------
  bool get_transaction_hash(const transaction& t, crypto::hash& res, size_t* blob_size)
  {
    if (t.is_hash_valid())
    {
#ifdef ENABLE_HASH_CASH_INTEGRITY_CHECK
      CHECK_AND_ASSERT_THROW_MES(!calculate_transaction_hash(t, res, blob_size) || t.hash == res, "tx hash cash integrity failure");
#endif
      res = t.hash;
      if (blob_size)
      {
        if (!t.is_blob_size_valid())
        {
          t.blob_size = get_object_blobsize(t);
          t.set_blob_size_valid(true);
        }
        *blob_size = t.blob_size;
      }
      ++tx_hashes_cached_count;
      return true;
    }
    ++tx_hashes_calculated_count;
    bool ret = calculate_transaction_hash(t, res, blob_size);
    if (!ret)
      return false;
    t.hash = res;
    t.set_hash_valid(true);
    if (blob_size)
    {
      t.blob_size = *blob_size;
      t.set_blob_size_valid(true);
    }
    return true;
  }
  //---------------------------------------------------------------
  bool get_transaction_hash(const transaction& t, crypto::hash& res, size_t& blob_size)
  {
    return get_transaction_hash(t, res, &blob_size);
  }
  //---------------------------------------------------------------
  blobdata get_block_hashing_blob(const block& b)
  {
    blobdata blob = t_serializable_object_to_blob(static_cast<block_header>(b));
    crypto::hash tree_root_hash = get_tx_tree_hash(b);
    blob.append(reinterpret_cast<const char*>(&tree_root_hash), sizeof(tree_root_hash));
    blob.append(tools::get_varint_data(b.tx_hashes.size()+1));
    return blob;
  }
  //---------------------------------------------------------------
  bool calculate_block_hash(const block& b, crypto::hash& res)
  {
    bool hash_result = get_object_hash(get_block_hashing_blob(b), res);
    return hash_result;
  }
  //---------------------------------------------------------------
  bool get_block_hash(const block& b, crypto::hash& res)
  {
    if (b.is_hash_valid())
    {
#ifdef ENABLE_HASH_CASH_INTEGRITY_CHECK
      CHECK_AND_ASSERT_THROW_MES(!calculate_block_hash(b, res) || b.hash == res, "block hash cash integrity failure");
#endif
      res = b.hash;
      ++block_hashes_cached_count;
      return true;
    }
    ++block_hashes_calculated_count;
    bool ret = calculate_block_hash(b, res);
    if (!ret)
      return false;
    b.hash = res;
    b.set_hash_valid(true);
    return true;
  }
  //---------------------------------------------------------------
  crypto::hash get_block_hash(const block& b)
  {
    crypto::hash p = null_hash;
    get_block_hash(b, p);
    return p;
  }
  //---------------------------------------------------------------
  std::vector<uint64_t> relative_output_offsets_to_absolute(const std::vector<uint64_t>& off)
  {
    std::vector<uint64_t> res = off;
    for(size_t i = 1; i < res.size(); i++)
      res[i] += res[i-1];
    return res;
  }
  //---------------------------------------------------------------
  std::vector<uint64_t> absolute_output_offsets_to_relative(const std::vector<uint64_t>& off)
  {
    std::vector<uint64_t> res = off;
    if(!off.size())
      return res;
    std::sort(res.begin(), res.end());//just to be sure, actually it is already should be sorted
    for(size_t i = res.size()-1; i != 0; i--)
      res[i] -= res[i-1];

    return res;
  }
  //---------------------------------------------------------------
  bool parse_and_validate_block_from_blob(const blobdata& b_blob, block& b)
  {
    std::stringstream ss;
    ss << b_blob;
    binary_archive<false> ba(ss);
    bool r = ::serialization::serialize(ba, b);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse block from blob");
    b.invalidate_hashes();
    b.miner_tx.invalidate_hashes();
    return true;
  }
  //---------------------------------------------------------------
  blobdata block_to_blob(const block& b)
  {
    return t_serializable_object_to_blob(b);
  }
  //---------------------------------------------------------------
  bool block_to_blob(const block& b, blobdata& b_blob)
  {
    return t_serializable_object_to_blob(b, b_blob);
  }
  //---------------------------------------------------------------
  blobdata tx_to_blob(const transaction& tx)
  {
    return t_serializable_object_to_blob(tx);
  }
  //---------------------------------------------------------------
  bool tx_to_blob(const transaction& tx, blobdata& b_blob)
  {
    return t_serializable_object_to_blob(tx, b_blob);
  }
  //---------------------------------------------------------------
  blobdata txout_script_to_blob(const txout_to_script& txout)
  {
    return t_serializable_object_to_blob(txout);
  }
  //---------------------------------------------------------------
  void get_tx_tree_hash(const std::vector<crypto::hash>& tx_hashes, crypto::hash& h)
  {
    tree_hash(tx_hashes.data(), tx_hashes.size(), h);
  }
  //---------------------------------------------------------------
  crypto::hash get_tx_tree_hash(const std::vector<crypto::hash>& tx_hashes)
  {
    crypto::hash h = null_hash;
    get_tx_tree_hash(tx_hashes, h);
    return h;
  }
  //---------------------------------------------------------------
  crypto::hash get_tx_tree_hash(const block& b)
  {
    std::vector<crypto::hash> txs_ids;
    crypto::hash h = null_hash;
    size_t bl_sz = 0;
    CHECK_AND_ASSERT_THROW_MES(get_transaction_hash(b.miner_tx, h, bl_sz), "Failed to calculate transaction hash");
    txs_ids.push_back(h);
    for(auto& th: b.tx_hashes)
      txs_ids.push_back(th);
    return get_tx_tree_hash(txs_ids);
  }
  //---------------------------------------------------------------
  bool is_valid_decomposed_amount(uint64_t amount)
  {
    const uint64_t *begin = valid_decomposed_outputs;
    const uint64_t *end = valid_decomposed_outputs + sizeof(valid_decomposed_outputs) / sizeof(valid_decomposed_outputs[0]);
    return std::binary_search(begin, end, amount);
  }
  //---------------------------------------------------------------
  void get_hash_stats(uint64_t &tx_hashes_calculated, uint64_t &tx_hashes_cached, uint64_t &block_hashes_calculated, uint64_t & block_hashes_cached)
  {
    tx_hashes_calculated = tx_hashes_calculated_count;
    tx_hashes_cached = tx_hashes_cached_count;
    block_hashes_calculated = block_hashes_calculated_count;
    block_hashes_cached = block_hashes_cached_count;
  }
  //---------------------------------------------------------------
  crypto::secret_key encrypt_key(crypto::secret_key key, const epee::wipeable_string &passphrase)
  {
    crypto::hash hash;
    crypto::cn_slow_hash(passphrase.data(), passphrase.size(), hash);
    sc_add((unsigned char*)key.data, (const unsigned char*)key.data, (const unsigned char*)hash.data);
    return key;
  }
  //---------------------------------------------------------------
  crypto::secret_key decrypt_key(crypto::secret_key key, const epee::wipeable_string &passphrase)
  {
    crypto::hash hash;
    crypto::cn_slow_hash(passphrase.data(), passphrase.size(), hash);
    sc_sub((unsigned char*)key.data, (const unsigned char*)key.data, (const unsigned char*)hash.data);
    return key;
  }
}
