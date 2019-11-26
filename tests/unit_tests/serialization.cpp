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

#include <cstring>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <vector>
#include <sstream>
#include <boost/foreach.hpp>
#include <boost/archive/portable_binary_iarchive.hpp>
#include <boost/archive/portable_binary_oarchive.hpp>
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "ringct/rctSigs.h"
#include "serialization/binary_archive.h"
#include "serialization/json_archive.h"
#include "serialization/debug_archive.h"
#include "serialization/variant.h"
#include "serialization/vector.h"
#include "serialization/binary_utils.h"
#include "wallet/wallet.h"
#include "gtest/gtest.h"
#include "unit_tests_utils.h"
#include "device/device.hpp"

#include "mnemonics/electrum-words.h"
#include "common/command_line.h"

using namespace std;
using namespace crypto;

struct Struct
{
  int32_t a;
  int32_t b;
  char blob[8];
};

template <class Archive>
struct serializer<Archive, Struct>
{
  static bool serialize(Archive &ar, Struct &s) {
    ar.begin_object();
    ar.tag("a");
    ar.serialize_int(s.a);
    ar.tag("b");
    ar.serialize_int(s.b);
    ar.tag("blob");
    ar.serialize_blob(s.blob, sizeof(s.blob));
    ar.end_object();
    return true;
  }
};

struct Struct1
{
  vector<boost::variant<Struct, int32_t>> si;
  vector<int16_t> vi;

  BEGIN_SERIALIZE_OBJECT()
    FIELD(si)
    FIELD(vi)
  END_SERIALIZE()
  /*template <bool W, template <bool> class Archive>
  bool do_serialize(Archive<W> &ar)
  {
    ar.begin_object();
    ar.tag("si");
    ::do_serialize(ar, si);
    ar.tag("vi");
    ::do_serialize(ar, vi);
    ar.end_object();
  }*/
};

struct Blob
{
  uint64_t a;
  uint32_t b;

  bool operator==(const Blob& rhs) const
  {
    return a == rhs.a;
  }
};

VARIANT_TAG(binary_archive, Struct, 0xe0);
VARIANT_TAG(binary_archive, int, 0xe1);
VARIANT_TAG(json_archive, Struct, "struct");
VARIANT_TAG(json_archive, int, "int");
VARIANT_TAG(debug_archive, Struct1, "struct1");
VARIANT_TAG(debug_archive, Struct, "struct");
VARIANT_TAG(debug_archive, int, "int");

BLOB_SERIALIZER(Blob);

bool try_parse(const string &blob)
{
  Struct1 s1;
  return serialization::parse_binary(blob, s1);
}

TEST(Serialization, BinaryArchiveInts) {
  uint64_t x = 0xff00000000, x1;

  ostringstream oss;
  binary_archive<true> oar(oss);
  oar.serialize_int(x);
  ASSERT_TRUE(oss.good());
  ASSERT_EQ(8, oss.str().size());
  ASSERT_EQ(string("\0\0\0\0\xff\0\0\0", 8), oss.str());

  istringstream iss(oss.str());
  binary_archive<false> iar(iss);
  iar.serialize_int(x1);
  ASSERT_EQ(8, iss.tellg());
  ASSERT_TRUE(iss.good());

  ASSERT_EQ(x, x1);
}

TEST(Serialization, BinaryArchiveVarInts) {
  uint64_t x = 0xff00000000, x1;

  ostringstream oss;
  binary_archive<true> oar(oss);
  oar.serialize_varint(x);
  ASSERT_TRUE(oss.good());
  ASSERT_EQ(6, oss.str().size());
  ASSERT_EQ(string("\x80\x80\x80\x80\xF0\x1F", 6), oss.str());

  istringstream iss(oss.str());
  binary_archive<false> iar(iss);
  iar.serialize_varint(x1);
  ASSERT_TRUE(iss.good());
  ASSERT_EQ(x, x1);
}

TEST(Serialization, Test1) {
  ostringstream str;
  binary_archive<true> ar(str);

  Struct1 s1;
  s1.si.push_back(0);
  {
    Struct s;
    s.a = 5;
    s.b = 65539;
    std::memcpy(s.blob, "12345678", 8);
    s1.si.push_back(s);
  }
  s1.si.push_back(1);
  s1.vi.push_back(10);
  s1.vi.push_back(22);

  string blob;
  ASSERT_TRUE(serialization::dump_binary(s1, blob));
  ASSERT_TRUE(try_parse(blob));

  ASSERT_EQ('\xE0', blob[6]);
  blob[6] = '\xE1';
  ASSERT_FALSE(try_parse(blob));
  blob[6] = '\xE2';
  ASSERT_FALSE(try_parse(blob));
}

TEST(Serialization, Overflow) {
  Blob x = { 0xff00000000 };
  Blob x1;

  string blob;
  ASSERT_TRUE(serialization::dump_binary(x, blob));
  ASSERT_EQ(sizeof(Blob), blob.size());

  ASSERT_TRUE(serialization::parse_binary(blob, x1));
  ASSERT_EQ(x, x1);

  vector<Blob> bigvector;
  ASSERT_FALSE(serialization::parse_binary(blob, bigvector));
  ASSERT_EQ(0, bigvector.size());
}

TEST(Serialization, serializes_vector_uint64_as_varint)
{
  std::vector<uint64_t> v;
  string blob;

  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(1, blob.size());

  // +1 byte
  v.push_back(0);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(2, blob.size());

  // +1 byte
  v.push_back(1);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(3, blob.size());

  // +2 bytes
  v.push_back(0x80);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(5, blob.size());

  // +2 bytes
  v.push_back(0xFF);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(7, blob.size());

  // +2 bytes
  v.push_back(0x3FFF);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(9, blob.size());

  // +3 bytes
  v.push_back(0x40FF);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(12, blob.size());

  // +10 bytes
  v.push_back(0xFFFFFFFFFFFFFFFF);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(22, blob.size());
}

TEST(Serialization, serializes_vector_int64_as_fixed_int)
{
  std::vector<int64_t> v;
  string blob;

  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(1, blob.size());

  // +8 bytes
  v.push_back(0);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(9, blob.size());

  // +8 bytes
  v.push_back(1);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(17, blob.size());

  // +8 bytes
  v.push_back(0x80);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(25, blob.size());

  // +8 bytes
  v.push_back(0xFF);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(33, blob.size());

  // +8 bytes
  v.push_back(0x3FFF);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(41, blob.size());

  // +8 bytes
  v.push_back(0x40FF);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(49, blob.size());

  // +8 bytes
  v.push_back(0xFFFFFFFFFFFFFFFF);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(57, blob.size());
}

namespace
{
  template<typename T>
  std::vector<T> linearize_vector2(const std::vector< std::vector<T> >& vec_vec)
  {
    std::vector<T> res;
    BOOST_FOREACH(const auto& vec, vec_vec)
    {
      res.insert(res.end(), vec.begin(), vec.end());
    }
    return res;
  }
}

TEST(Serialization, serializes_transacion_signatures_correctly)
{
  using namespace cryptonote;

  transaction tx;
  transaction tx1;
  string blob;

  // Empty tx
  tx.set_null();
  ASSERT_TRUE(serialization::dump_binary(tx, blob));
  ASSERT_EQ(5, blob.size()); // 5 bytes + 0 bytes extra + 0 bytes signatures
  ASSERT_TRUE(serialization::parse_binary(blob, tx1));
  ASSERT_EQ(tx, tx1);
  ASSERT_EQ(linearize_vector2(tx.signatures), linearize_vector2(tx1.signatures));

  // Miner tx without signatures
  txin_gen txin_gen1;
  txin_gen1.height = 0;
  tx.set_null();
  tx.vin.push_back(txin_gen1);
  ASSERT_TRUE(serialization::dump_binary(tx, blob));
  ASSERT_EQ(7, blob.size()); // 5 bytes + 2 bytes vin[0] + 0 bytes extra + 0 bytes signatures
  ASSERT_TRUE(serialization::parse_binary(blob, tx1));
  ASSERT_EQ(tx, tx1);
  ASSERT_EQ(linearize_vector2(tx.signatures), linearize_vector2(tx1.signatures));

  // Miner tx with empty signatures 2nd vector
  tx.signatures.resize(1);
  tx.invalidate_hashes();
  ASSERT_TRUE(serialization::dump_binary(tx, blob));
  ASSERT_EQ(7, blob.size()); // 5 bytes + 2 bytes vin[0] + 0 bytes extra + 0 bytes signatures
  ASSERT_TRUE(serialization::parse_binary(blob, tx1));
  ASSERT_EQ(tx, tx1);
  ASSERT_EQ(linearize_vector2(tx.signatures), linearize_vector2(tx1.signatures));

  // Miner tx with one signature
  tx.signatures[0].resize(1);
  ASSERT_FALSE(serialization::dump_binary(tx, blob));

  // Miner tx with 2 empty vectors
  tx.signatures.resize(2);
  tx.signatures[0].resize(0);
  tx.signatures[1].resize(0);
  tx.invalidate_hashes();
  ASSERT_FALSE(serialization::dump_binary(tx, blob));

  // Miner tx with 2 signatures
  tx.signatures[0].resize(1);
  tx.signatures[1].resize(1);
  tx.invalidate_hashes();
  ASSERT_FALSE(serialization::dump_binary(tx, blob));

  // Two txin_gen, no signatures
  tx.vin.push_back(txin_gen1);
  tx.signatures.resize(0);
  tx.invalidate_hashes();
  ASSERT_TRUE(serialization::dump_binary(tx, blob));
  ASSERT_EQ(9, blob.size()); // 5 bytes + 2 * 2 bytes vins + 0 bytes extra + 0 bytes signatures
  ASSERT_TRUE(serialization::parse_binary(blob, tx1));
  ASSERT_EQ(tx, tx1);
  ASSERT_EQ(linearize_vector2(tx.signatures), linearize_vector2(tx1.signatures));

  // Two txin_gen, signatures vector contains only one empty element
  tx.signatures.resize(1);
  tx.invalidate_hashes();
  ASSERT_FALSE(serialization::dump_binary(tx, blob));

  // Two txin_gen, signatures vector contains two empty elements
  tx.signatures.resize(2);
  tx.invalidate_hashes();
  ASSERT_TRUE(serialization::dump_binary(tx, blob));
  ASSERT_EQ(9, blob.size()); // 5 bytes + 2 * 2 bytes vins + 0 bytes extra + 0 bytes signatures
  ASSERT_TRUE(serialization::parse_binary(blob, tx1));
  ASSERT_EQ(tx, tx1);
  ASSERT_EQ(linearize_vector2(tx.signatures), linearize_vector2(tx1.signatures));

  // Two txin_gen, signatures vector contains three empty elements
  tx.signatures.resize(3);
  tx.invalidate_hashes();
  ASSERT_FALSE(serialization::dump_binary(tx, blob));

  // Two txin_gen, signatures vector contains two non empty elements
  tx.signatures.resize(2);
  tx.signatures[0].resize(1);
  tx.signatures[1].resize(1);
  tx.invalidate_hashes();
  ASSERT_FALSE(serialization::dump_binary(tx, blob));

  // A few bytes instead of signature
  tx.vin.clear();
  tx.vin.push_back(txin_gen1);
  tx.signatures.clear();
  tx.invalidate_hashes();
  ASSERT_TRUE(serialization::dump_binary(tx, blob));
  blob.append(std::string(sizeof(crypto::signature) / 2, 'x'));
  ASSERT_FALSE(serialization::parse_binary(blob, tx1));

  // blob contains one signature
  blob.append(std::string(sizeof(crypto::signature) / 2, 'y'));
  ASSERT_FALSE(serialization::parse_binary(blob, tx1));

  // Not enough signature vectors for all inputs
  txin_to_key txin_to_key1;
  txin_to_key1.amount = 1;
  memset(&txin_to_key1.k_image, 0x42, sizeof(crypto::key_image));
  txin_to_key1.key_offsets.push_back(12);
  txin_to_key1.key_offsets.push_back(3453);
  tx.vin.clear();
  tx.vin.push_back(txin_to_key1);
  tx.vin.push_back(txin_to_key1);
  tx.signatures.resize(1);
  tx.signatures[0].resize(2);
  tx.invalidate_hashes();
  ASSERT_FALSE(serialization::dump_binary(tx, blob));

  // Too much signatures for two inputs
  tx.signatures.resize(3);
  tx.signatures[0].resize(2);
  tx.signatures[1].resize(2);
  tx.signatures[2].resize(2);
  tx.invalidate_hashes();
  ASSERT_FALSE(serialization::dump_binary(tx, blob));

  // First signatures vector contains too little elements
  tx.signatures.resize(2);
  tx.signatures[0].resize(1);
  tx.signatures[1].resize(2);
  tx.invalidate_hashes();
  ASSERT_FALSE(serialization::dump_binary(tx, blob));

  // First signatures vector contains too much elements
  tx.signatures.resize(2);
  tx.signatures[0].resize(3);
  tx.signatures[1].resize(2);
  tx.invalidate_hashes();
  ASSERT_FALSE(serialization::dump_binary(tx, blob));

  // There are signatures for each input
  tx.signatures.resize(2);
  tx.signatures[0].resize(2);
  tx.signatures[1].resize(2);
  tx.invalidate_hashes();
  ASSERT_TRUE(serialization::dump_binary(tx, blob));
  ASSERT_TRUE(serialization::parse_binary(blob, tx1));
  ASSERT_EQ(tx, tx1);
  ASSERT_EQ(linearize_vector2(tx.signatures), linearize_vector2(tx1.signatures));

  // Blob doesn't contain enough data
  blob.resize(blob.size() - sizeof(crypto::signature) / 2);
  ASSERT_FALSE(serialization::parse_binary(blob, tx1));

  // Blob contains too much data
  blob.resize(blob.size() + sizeof(crypto::signature));
  ASSERT_FALSE(serialization::parse_binary(blob, tx1));

  // Blob contains one excess signature
  blob.resize(blob.size() + sizeof(crypto::signature) / 2);
  ASSERT_FALSE(serialization::parse_binary(blob, tx1));
}

static boost::optional<tools::password_container> password_prompter(const char *prompt, bool verify)
{
  tools::password_container pwd_container{"test"};
  return pwd_container;
}


static void serialize_wallet_test_init_vm(boost::program_options::variables_map &vm)
{
  static boost::filesystem::path dir = unit_test::data_dir / ".shared-ringdb-unittest";

  boost::program_options::options_description desc_params("Allowed options");
  tools::wallet::init_options(desc_params);
  const int argc = 4;
  const char* argv[] = {"wallet","--testnet","--password","","--shared-ringdb-dir", dir.string().c_str()};
  bool r = command_line::handle_error_helper(desc_params, [&]()
  {
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc_params), vm);
    boost::program_options::notify(vm);
    return true;
  });
}

TEST(Serialization, serialize_wallet)
{
  const cryptonote::network_type nettype = cryptonote::TESTNET;
  const boost::filesystem::path wallet_file = unit_test::data_dir / "wallet_9svHk1a";
  const boost::filesystem::path wallet_keys_file = unit_test::data_dir / "wallet_9svHk1a.keys";
  const boost::filesystem::path wallet_address_file = unit_test::data_dir / "wallet_9svHk1a.address.txt";
  std::remove(wallet_file.string().c_str());
  std::remove(wallet_keys_file.string().c_str());
  std::remove(wallet_address_file.string().c_str());
  const bool restricted = false;
  const bool deterministic = true;
  const string elecrum_seed = "vain nineteen possible tolerant debut pinched tell upcoming vapidly timber jargon spout idled lynx twice zodiac spying casket cement eavesdrop yacht utopia hijack hills";
  crypto::secret_key recovery_key = AUTO_VAL_INIT(recovery_key);
  string language = "English";
  boost::program_options::variables_map vm;
  serialize_wallet_test_init_vm(vm);

  //const string password = "test";
  ASSERT_TRUE(crypto::ElectrumWords::words_to_bytes(elecrum_seed, recovery_key, language));

  auto rc = tools::wallet::make_new(vm, password_prompter);
  std::unique_ptr<tools::wallet> wallet = std::move(rc.first);

  ASSERT_FALSE(!wallet);

  wallet->set_seed_language(language);

  crypto::secret_key recovery_val ;
  const epee::wipeable_string& password = "";

  ASSERT_NO_THROW(recovery_val = wallet->generate(wallet_file.string(), password, recovery_key, true, false, false));
  std::cout << "Generated wallet address: " <<  wallet->get_account().get_public_address_str(wallet->nettype()) << std::endl;
  std::cout << "View key: " << epee::string_tools::pod_to_hex(wallet->get_account().get_keys().m_view_secret_key) << std::endl;

  std::string electrum_words;
  crypto::ElectrumWords::bytes_to_words(recovery_val, electrum_words, language);
  std::cout << "electrum_words:" << electrum_words << std::endl;

  //<---------------- Key images -------------------------
  crypto::key_image ki[3];
  epee::string_tools::hex_to_pod("c5680d3735b90871ca5e3d90cd82d6483eed1151b9ab75c2c8c3a7d89e00a5a8", ki[0]);
  epee::string_tools::hex_to_pod("d54cbd435a8d636ad9b01b8d4f3eb13bd0cf1ce98eddf53ab1617f9b763e66c0", ki[1]);
  epee::string_tools::hex_to_pod("6c3cd6af97c4070a7aef9b1344e7463e29c7cd245076fdb65da447a34da3ca76", ki[2]);

  wallet->m_key_images[ki[0]] = 0;
  wallet->m_key_images[ki[1]] = 1;
  wallet->m_key_images[ki[2]] = 2;

  //<---------------- Payments ------------------
  std::pair<crypto::hash, ::tools::wallet::payment_details> payment_detail1, payment_detail2;
  epee::string_tools::hex_to_pod("0000000000000000000000000000000000000000000000000000000000000000", payment_detail1.first);
  epee::string_tools::hex_to_pod("0000000000000000000000000000000000000000000000000000000000000000", payment_detail2.first);

  epee::string_tools::hex_to_pod("15024343b38e77a1a9860dfed29921fa17e833fec837191a6b04fa7cb9605b8e", payment_detail1.second.m_tx_hash);
  epee::string_tools::hex_to_pod("ec34c9bb12b99af33d49691384eee5bed9171498ff04e59516505f35d1fc5efc", payment_detail2.second.m_tx_hash);

  payment_detail1.second.m_amount = 13400845012231;
  payment_detail2.second.m_amount = 1200000000000;

  payment_detail1.second.m_block_height = 818424;
  payment_detail2.second.m_block_height = 818522;

  payment_detail1.second.m_unlock_time = 818484;
  payment_detail2.second.m_unlock_time = 0;

  payment_detail1.second.m_timestamp = 1483263366;
  payment_detail2.second.m_timestamp = 1483272963;

  wallet->m_payments.insert(payment_detail1);
  wallet->m_payments.insert(payment_detail2);

  //<---------------- TX keys ------------------

  std::pair<crypto::hash, crypto::secret_key> tx_key_pair;

  epee::string_tools::hex_to_pod("b9aac8c020ab33859e0c0b6331f46a8780d349e7ac17b067116e2d87bf48daad", tx_key_pair.first);
  epee::string_tools::hex_to_pod("bf3614c6de1d06c09add5d92a5265d8c76af706f7bc6ac830d6b0d109aa87701", tx_key_pair.second);
  wallet->m_tx_keys.insert(tx_key_pair);

  epee::string_tools::hex_to_pod("6e7013684d35820f66c6679197ded9329bfe0e495effa47e7b25258799858dba", tx_key_pair.first);
  epee::string_tools::hex_to_pod("e556884246df5a787def6732c6ea38f1e092fa13e5ea98f732b99c07a6332003", tx_key_pair.second);
  wallet->m_tx_keys.insert(tx_key_pair);

  //<---------------- TX notes ------------------

  std::pair<crypto::hash, std::string> note;
  note.second = "sample note";
  epee::string_tools::hex_to_pod("15024343b38e77a1a9860dfed29921fa17e833fec837191a6b04fa7cb9605b8e", note.first);
  wallet->m_tx_notes.insert(note);

  note.second = "sample note 2";
  epee::string_tools::hex_to_pod("6e7013684d35820f66c6679197ded9329bfe0e495effa47e7b25258799858dba", note.first);
  wallet->m_tx_notes.insert(note);


  //<---------------- PUB keys ------------------
  std::pair<crypto::public_key, size_t> pub_key_pair;

  epee::string_tools::hex_to_pod("33f75f264574cb3a9ea5b24220a5312e183d36dc321c9091dfbb720922a4f7b0", pub_key_pair.first);
  pub_key_pair.second = 0;
  wallet->m_pub_keys.insert(pub_key_pair);

  epee::string_tools::hex_to_pod("5066ff2ce9861b1d131cf16eeaa01264933a49f28242b97b153e922ec7b4b3cb", pub_key_pair.first);
  pub_key_pair.second = 1;
  wallet->m_pub_keys.insert(pub_key_pair);

  epee::string_tools::hex_to_pod("0d8467e16e73d16510452b78823e082e05ee3a63788d40de577cf31eb555f0c8", pub_key_pair.first);
  pub_key_pair.second = 2;
  wallet->m_pub_keys.insert(pub_key_pair);

  //<---------------- Address book ------------------
  ::tools::wallet::address_book_row address_book_row;
  epee::string_tools::hex_to_pod("9bc53a6ff7b0831c9470f71b6b972dbe5ad1e8606f72682868b1dda64e119fb3", address_book_row.m_address.m_spend_public_key);
  epee::string_tools::hex_to_pod("49fece1ef97dc0c0f7a5e2106e75e96edd910f7e86b56e1e308cd0cf734df191", address_book_row.m_address.m_view_public_key);
  epee::string_tools::hex_to_pod("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", address_book_row.m_payment_id);
  address_book_row.m_description = "testnet wallet 9y52S6";

  wallet->m_address_book.push_back(address_book_row);


  wallet->store(); //<- Wallet must be explicitly stored because its not stored on stop or deinit.

  wallet->stop();
  wallet->deinit();
}

/// @warning In order for this test to work, Serialization.serialize_wallet must be called first to
///          generate wallet file.
TEST(Serialization, portability_wallet)
{
  const cryptonote::network_type nettype = cryptonote::TESTNET;
  const bool restricted = false;
  tools::wallet w(nettype, restricted);
  const boost::filesystem::path wallet_file = unit_test::data_dir / "wallet_9svHk1a";
  std::string password = "";

  ASSERT_NO_THROW(w.load(wallet_file.string(), password));

  /*
  fields of tools::wallet to be checked:
    std::vector<crypto::hash>                                       m_blockchain
    std::vector<transfer_details>                                   m_transfers               // TODO
    cryptonote::account_public_address                              m_account_public_address
    std::unordered_map<crypto::key_image, size_t>                   m_key_images
    std::unordered_map<crypto::hash, unconfirmed_transfer_details>  m_unconfirmed_txs
    std::unordered_multimap<crypto::hash, payment_details>          m_payments
    std::unordered_map<crypto::hash, crypto::secret_key>            m_tx_keys
    std::unordered_map<crypto::hash, confirmed_transfer_details>    m_confirmed_txs
    std::unordered_map<crypto::hash, std::string>                   m_tx_notes
    std::unordered_map<crypto::hash, payment_details>               m_unconfirmed_payments
    std::unordered_map<crypto::public_key, size_t>                  m_pub_keys
    std::vector<tools::wallet::address_book_row>                   m_address_book
  */

  // blockchain
  ASSERT_TRUE(w.m_blockchain.size() == 1);
  std::cout << " teeest " << epee::string_tools::pod_to_hex(w.m_blockchain[0]) << std::endl;
  ASSERT_TRUE(epee::string_tools::pod_to_hex(w.m_blockchain[0]) == "97954b8c49fc7ceada6d291e6d2c1a32cc747c095c6c45ab5e2eb914bd002dcb");
  // transfers (TODO)
  ASSERT_TRUE(w.m_transfers.size() == 0);
  // account public address
  ASSERT_TRUE(epee::string_tools::pod_to_hex(w.m_account_public_address.m_view_public_key) == "724084e052777f596b7e66785516a4263ee7f9d5586ef6e72fb00c066d45995e");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(w.m_account_public_address.m_spend_public_key) == "a65befd73dcc26a51f35848df2a7f33dc4ffa28d8ed0a153a1d718bc685cc016");

  // key images
  ASSERT_TRUE(w.m_key_images.size() == 3);
  {
   crypto::key_image ki[3];
   epee::string_tools::hex_to_pod("c5680d3735b90871ca5e3d90cd82d6483eed1151b9ab75c2c8c3a7d89e00a5a8", ki[0]);
   epee::string_tools::hex_to_pod("d54cbd435a8d636ad9b01b8d4f3eb13bd0cf1ce98eddf53ab1617f9b763e66c0", ki[1]);
   epee::string_tools::hex_to_pod("6c3cd6af97c4070a7aef9b1344e7463e29c7cd245076fdb65da447a34da3ca76", ki[2]);
   ASSERT_EQ_MAP(0, w.m_key_images, ki[0]);
   ASSERT_EQ_MAP(1, w.m_key_images, ki[1]);
   ASSERT_EQ_MAP(2, w.m_key_images, ki[2]);
  }
  // unconfirmed txs
  ASSERT_TRUE(w.m_unconfirmed_txs.size() == 0);

  // payments
  ASSERT_TRUE(w.m_payments.size() == 2);
  {
    auto pd0 = w.m_payments.begin();
    auto pd1 = pd0;
    ++pd1;
    ASSERT_TRUE(epee::string_tools::pod_to_hex(pd0->first) == "0000000000000000000000000000000000000000000000000000000000000000");
    ASSERT_TRUE(epee::string_tools::pod_to_hex(pd1->first) == "0000000000000000000000000000000000000000000000000000000000000000");
    if (epee::string_tools::pod_to_hex(pd0->second.m_tx_hash) == "ec34c9bb12b99af33d49691384eee5bed9171498ff04e59516505f35d1fc5efc")
      swap(pd0, pd1);
    ASSERT_TRUE(epee::string_tools::pod_to_hex(pd0->second.m_tx_hash) == "15024343b38e77a1a9860dfed29921fa17e833fec837191a6b04fa7cb9605b8e");
    ASSERT_TRUE(epee::string_tools::pod_to_hex(pd1->second.m_tx_hash) == "ec34c9bb12b99af33d49691384eee5bed9171498ff04e59516505f35d1fc5efc");
    ASSERT_TRUE(pd0->second.m_amount == 13400845012231);
    ASSERT_TRUE(pd1->second.m_amount == 1200000000000);
    ASSERT_TRUE(pd0->second.m_block_height == 818424);
    ASSERT_TRUE(pd1->second.m_block_height == 818522);
    ASSERT_TRUE(pd0->second.m_unlock_time == 818484);
    ASSERT_TRUE(pd1->second.m_unlock_time == 0);
    ASSERT_TRUE(pd0->second.m_timestamp == 1483263366);
    ASSERT_TRUE(pd1->second.m_timestamp == 1483272963);
  }

  // tx keys (TODO)
  ASSERT_TRUE(w.m_tx_keys.size() == 2);
  {
    const std::vector<std::pair<std::string, std::string>> txid_txkey =
    {
      {"b9aac8c020ab33859e0c0b6331f46a8780d349e7ac17b067116e2d87bf48daad", "bf3614c6de1d06c09add5d92a5265d8c76af706f7bc6ac830d6b0d109aa87701"},
      {"6e7013684d35820f66c6679197ded9329bfe0e495effa47e7b25258799858dba", "e556884246df5a787def6732c6ea38f1e092fa13e5ea98f732b99c07a6332003"},
    };
    for (size_t i = 0; i < txid_txkey.size(); ++i)
    {
      crypto::hash txid;
      crypto::secret_key txkey;
      epee::string_tools::hex_to_pod(txid_txkey[i].first, txid);
      epee::string_tools::hex_to_pod(txid_txkey[i].second, txkey);
      ASSERT_EQ_MAP(txkey, w.m_tx_keys, txid);
    }
  }
  // confirmed txs (TODO)
  ASSERT_TRUE(w.m_confirmed_txs.size() == 0);
  // tx notes
  ASSERT_TRUE(w.m_tx_notes.size() == 2);
  {
    crypto::hash h[2];
    epee::string_tools::hex_to_pod("15024343b38e77a1a9860dfed29921fa17e833fec837191a6b04fa7cb9605b8e", h[0]);
    epee::string_tools::hex_to_pod("6e7013684d35820f66c6679197ded9329bfe0e495effa47e7b25258799858dba", h[1]);
    ASSERT_EQ_MAP("sample note", w.m_tx_notes, h[0]);
    ASSERT_EQ_MAP("sample note 2", w.m_tx_notes, h[1]);
  }
  // unconfirmed payments
  ASSERT_TRUE(w.m_unconfirmed_payments.size() == 0);
  // pub keys
  ASSERT_TRUE(w.m_pub_keys.size() == 3);
  {
    crypto::public_key pubkey[3];
    epee::string_tools::hex_to_pod("33f75f264574cb3a9ea5b24220a5312e183d36dc321c9091dfbb720922a4f7b0", pubkey[0]);
    epee::string_tools::hex_to_pod("5066ff2ce9861b1d131cf16eeaa01264933a49f28242b97b153e922ec7b4b3cb", pubkey[1]);
    epee::string_tools::hex_to_pod("0d8467e16e73d16510452b78823e082e05ee3a63788d40de577cf31eb555f0c8", pubkey[2]);
    ASSERT_EQ_MAP(0, w.m_pub_keys, pubkey[0]);
    ASSERT_EQ_MAP(1, w.m_pub_keys, pubkey[1]);
    ASSERT_EQ_MAP(2, w.m_pub_keys, pubkey[2]);
  }
  // address book
  ASSERT_TRUE(w.m_address_book.size() == 1);
  {
    auto address_book_row = w.m_address_book.begin();
    ASSERT_TRUE(epee::string_tools::pod_to_hex(address_book_row->m_address.m_spend_public_key) == "9bc53a6ff7b0831c9470f71b6b972dbe5ad1e8606f72682868b1dda64e119fb3");
    ASSERT_TRUE(epee::string_tools::pod_to_hex(address_book_row->m_address.m_view_public_key) == "49fece1ef97dc0c0f7a5e2106e75e96edd910f7e86b56e1e308cd0cf734df191");
    ASSERT_TRUE(epee::string_tools::pod_to_hex(address_book_row->m_payment_id) == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    ASSERT_TRUE(address_book_row->m_description == "testnet wallet 9y52S6");
  }
}

#define OUTPUT_EXPORT_FILE_MAGIC "Safex output export\003"
namespace {
  /// Artifically generate outputs file.
  /// Procedure of serialization is identical as one in simple_wallet.
  void generate_outputs_file ()
  {
    //<------------------------ Generate output data ----------------------------
    ::tools::wallet::transfer_details out1, out2, out3;
    out1.m_block_height = 818424;
    out2.m_block_height = 818522;
    out3.m_block_height = 818522;

    epee::string_tools::hex_to_pod("15024343b38e77a1a9860dfed29921fa17e833fec837191a6b04fa7cb9605b8e", out1.m_txid);
    epee::string_tools::hex_to_pod("ec34c9bb12b99af33d49691384eee5bed9171498ff04e59516505f35d1fc5efc", out2.m_txid);
    epee::string_tools::hex_to_pod("6e7013684d35820f66c6679197ded9329bfe0e495effa47e7b25258799858dba", out3.m_txid);

    out1.m_internal_output_index = 0;
    out2.m_internal_output_index = 0;
    out3.m_internal_output_index = 1;

    out1.m_global_output_index = 19642;
    out2.m_global_output_index = 19757;
    out3.m_global_output_index = 19760;

    out1.m_spent = true;
    out2.m_spent = false;
    out3.m_spent = false;

    out1.m_spent_height = 0;
    out2.m_spent_height = 0;
    out3.m_spent_height = 0;

    epee::string_tools::hex_to_pod("c5680d3735b90871ca5e3d90cd82d6483eed1151b9ab75c2c8c3a7d89e00a5a8", out1.m_key_image);
    epee::string_tools::hex_to_pod("d54cbd435a8d636ad9b01b8d4f3eb13bd0cf1ce98eddf53ab1617f9b763e66c0", out2.m_key_image);
    epee::string_tools::hex_to_pod("6c3cd6af97c4070a7aef9b1344e7463e29c7cd245076fdb65da447a34da3ca76", out3.m_key_image);

    epee::string_tools::hex_to_pod("0100000000000000000000000000000000000000000000000000000000000000", out1.m_mask);
    epee::string_tools::hex_to_pod("d3997a7b27fa199a377643b88cbd3f20f447496746dabe92d288730ecaeda007", out2.m_mask);
    epee::string_tools::hex_to_pod("789bafff169ef206aa21219342c69ca52ce1d78d776c10b21d14bdd960fc7703", out3.m_mask);

    out1.m_rct = true;
    out2.m_rct = true;
    out3.m_rct = true;

    out1.m_key_image_known = true;
    out2.m_key_image_known = true;
    out3.m_key_image_known = true;

    out1.m_amount = 13400845012231;
    out2.m_amount = 1200000000000;
    out3.m_amount = 11066009260865;

    out1.m_pk_index = 0;
    out2.m_pk_index = 0;
    out3.m_pk_index = 0;

    std::vector<::tools::wallet::transfer_details> data_outputs;
    data_outputs.push_back(out1);
    data_outputs.push_back(out2);
    data_outputs.push_back(out3);

    //<------------------------------------- Encrypt --------------------------
    ::tools::wallet wallet;
    const boost::filesystem::path filename = unit_test::data_dir / "outputs";
    bool authenticated = true;
    std::stringstream oss;
    boost::archive::portable_binary_oarchive ar(oss); //< Output binary archive
    std::string magic(OUTPUT_EXPORT_FILE_MAGIC, strlen(OUTPUT_EXPORT_FILE_MAGIC)); //< magic string
    std::string header; //< Binary data of public keys stored as string
    std::string ciphertext; //< Encrypted data

    crypto::public_key p1, p2;
    epee::string_tools::hex_to_pod("13daa2af00ad26a372d317195de0bdd716f7a05d33bc4d7aff1664b6ee93c060" ,p1);
    epee::string_tools::hex_to_pod("e47d4b6df6ab7339539148c2a03ad3e2f3434e5ab2046848e1f21369a3937cad" ,p2);

    crypto::secret_key view_secret_key;
    epee::string_tools::hex_to_pod("339673bb1187e2f73ba7841ab6841c5553f96e9f13f8fe6612e69318db4e9d0a", view_secret_key);

    // Copied and (slightly modified) from simple_wallet


    ASSERT_NO_THROW(ar << data_outputs);

    header += std::string((const char *)&p1, sizeof(crypto::public_key));
    header += std::string((const char *)&p2, sizeof(crypto::public_key));

    ASSERT_NO_THROW(ciphertext = wallet.encrypt(header + oss.str(), view_secret_key, authenticated));
    ASSERT_TRUE(epee::file_io_utils::save_string_to_file(filename.string(), magic + ciphertext));

  }
}

TEST(Serialization, portability_outputs)
{
  generate_outputs_file();
  ::tools::wallet wallet;
  // read file
  const boost::filesystem::path filename = unit_test::data_dir / "outputs";
  std::string data;
  bool r = epee::file_io_utils::load_file_to_string(filename.string(), data);
  ASSERT_TRUE(r);

  const size_t magiclen = strlen(OUTPUT_EXPORT_FILE_MAGIC);
  ASSERT_FALSE(data.size() < magiclen || memcmp(data.data(), OUTPUT_EXPORT_FILE_MAGIC, magiclen));

  crypto::secret_key view_secret_key;
  epee::string_tools::hex_to_pod("339673bb1187e2f73ba7841ab6841c5553f96e9f13f8fe6612e69318db4e9d0a", view_secret_key);
  bool authenticated = true;

  ASSERT_NO_THROW(data = wallet.decrypt(std::string(data, magiclen), view_secret_key, authenticated));
  ASSERT_FALSE(data.empty());

  // check public view/spend keys
  const size_t headerlen = 2 * sizeof(crypto::public_key);
  ASSERT_FALSE(data.size() < headerlen);
  const crypto::public_key &public_spend_key = *(const crypto::public_key*)&data[0];
  const crypto::public_key &public_view_key = *(const crypto::public_key*)&data[sizeof(crypto::public_key)];

  ASSERT_TRUE(epee::string_tools::pod_to_hex(public_spend_key) == "13daa2af00ad26a372d317195de0bdd716f7a05d33bc4d7aff1664b6ee93c060");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(public_view_key) == "e47d4b6df6ab7339539148c2a03ad3e2f3434e5ab2046848e1f21369a3937cad");
  r = false;
  std::vector<tools::wallet::transfer_details> outputs;
  try
  {
    std::istringstream iss(std::string(data, headerlen));
    boost::archive::portable_binary_iarchive ar(iss);
    ar >> outputs;
    r = true;
  }
  catch (...)
  {}
  ASSERT_TRUE(r);
  /*
   * fields of tools::wallet::transfer_details to be checked:
   *   uint64_t                        m_block_height
   *   cryptonote::transaction_prefix  m_tx                        // TODO
   *   crypto::hash                    m_txid
   *   size_t                          m_internal_output_index
   *   uint64_t                        m_global_output_index
   *   bool                            m_spent
   *   uint64_t                        m_spent_height
   *   crypto::key_image               m_key_image
   *   rct::key                        m_mask
   *   uint64_t                        m_amount
   *   uint64_t                        m_token_amount
   *   bool                            m_rct
   *   bool                            m_key_image_known
   *   bool                            m_token_transfer
   *   size_t                          m_pk_index
   */
  ASSERT_TRUE(outputs.size() == 3);
  auto& td0 = outputs[0];
  auto& td1 = outputs[1];
  auto& td2 = outputs[2];
  ASSERT_TRUE(td0.m_block_height == 818424);
  ASSERT_TRUE(td1.m_block_height == 818522);
  ASSERT_TRUE(td2.m_block_height == 818522);
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td0.m_txid) == "15024343b38e77a1a9860dfed29921fa17e833fec837191a6b04fa7cb9605b8e");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td1.m_txid) == "ec34c9bb12b99af33d49691384eee5bed9171498ff04e59516505f35d1fc5efc");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td2.m_txid) == "6e7013684d35820f66c6679197ded9329bfe0e495effa47e7b25258799858dba");
  ASSERT_TRUE(td0.m_internal_output_index == 0);
  ASSERT_TRUE(td1.m_internal_output_index == 0);
  ASSERT_TRUE(td2.m_internal_output_index == 1);
  ASSERT_TRUE(td0.m_global_output_index == 19642);
  ASSERT_TRUE(td1.m_global_output_index == 19757);
  ASSERT_TRUE(td2.m_global_output_index == 19760);
  ASSERT_TRUE (td0.m_spent);
  ASSERT_FALSE(td1.m_spent);
  ASSERT_FALSE(td2.m_spent);
  ASSERT_TRUE(td0.m_spent_height == 0);
  ASSERT_TRUE(td1.m_spent_height == 0);
  ASSERT_TRUE(td2.m_spent_height == 0);
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td0.m_key_image) == "c5680d3735b90871ca5e3d90cd82d6483eed1151b9ab75c2c8c3a7d89e00a5a8");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td1.m_key_image) == "d54cbd435a8d636ad9b01b8d4f3eb13bd0cf1ce98eddf53ab1617f9b763e66c0");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td2.m_key_image) == "6c3cd6af97c4070a7aef9b1344e7463e29c7cd245076fdb65da447a34da3ca76");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td0.m_mask) == "0100000000000000000000000000000000000000000000000000000000000000");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td1.m_mask) == "d3997a7b27fa199a377643b88cbd3f20f447496746dabe92d288730ecaeda007");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td2.m_mask) == "789bafff169ef206aa21219342c69ca52ce1d78d776c10b21d14bdd960fc7703");
  ASSERT_TRUE(td0.m_amount == 13400845012231);
  ASSERT_TRUE(td1.m_amount == 1200000000000);
  ASSERT_TRUE(td2.m_amount == 11066009260865);
  ASSERT_TRUE(td0.m_rct);
  ASSERT_TRUE(td1.m_rct);
  ASSERT_TRUE(td2.m_rct);
  ASSERT_TRUE(td0.m_key_image_known);
  ASSERT_TRUE(td1.m_key_image_known);
  ASSERT_TRUE(td2.m_key_image_known);
  ASSERT_TRUE(td0.m_pk_index == 0);
  ASSERT_TRUE(td1.m_pk_index == 0);
  ASSERT_TRUE(td2.m_pk_index == 0);
}

// Its 004, because its representing version. From 004 version output is encrypted.
// according to simple wallet.
#define UNSIGNED_TX_PREFIX "Safex unsigned tx set\004"

namespace {
  void generate_unsigned_safex_tx_file()
  {
    // Generate data
    const cryptonote::network_type nettype = cryptonote::TESTNET;
    tools::wallet::unsigned_tx_set exported_txs;
    exported_txs.txes.emplace_back();
    auto& tcd = exported_txs.txes[0];
    tcd.sources.emplace_back();
    auto& tse = tcd.sources[0];
    // tcd.sources[0].outputs
    tse.outputs.resize(5);
    auto& out0 = tse.outputs[0];
    auto& out1 = tse.outputs[1];
    auto& out2 = tse.outputs[2];
    auto& out3 = tse.outputs[3];
    auto& out4 = tse.outputs[4];
    out0.first = 6295;
    out1.first = 14302;
    out2.first = 17598;
    out3.first = 18671;
    out4.first = 19760;
    epee::string_tools::hex_to_pod("e7272cb589954ddeedd20de9411ed57265f154d41f33cec9ff69e5d642e09814096490b0ac85308342acf436cc0270d53abef9dc04c6202f2459e879bfd40ce6", out0.second);
    epee::string_tools::hex_to_pod("c3a9f49d1fe75939cc3feb39871ce0a7366c2879a63faa1a5cf34e65723b120a272ff0c7d84ab8b6ee3528d196450b0e28b3fed276bc2597a2b5b17afb9354ab", out1.second);
    epee::string_tools::hex_to_pod("176e239c8c39000c2275e2f63ed7d55c55e0843524091522bbd3d3b869044969021fad70fc1244115449d4754829ae7c47346342ee5d52a2cdd47dfc351d0ab0", out2.second);
    epee::string_tools::hex_to_pod("ef12d7946302fb064f2ba9df1a73d72233ac74664ed3b370580fa3bdc377542ad93f64898bd95851d6efe0d7bf2dbbea9b7c6b3c57e2c807e7b17d55b4622259", out3.second);
    epee::string_tools::hex_to_pod("0d8467e16e73d16510452b78823e082e05ee3a63788d40de577cf31eb555f0c8525096cbc88d00a841eed66f3cdb6f0a018e6ce9fb9433ed61afba15cbbebd04", out4.second);
    // tcd.sources[0].{real_output, real_out_tx_key, real_output_in_tx_index, amount, rct, mask}
    tse.real_output = 4;
    epee::string_tools::hex_to_pod("4d86c7ba1c285fe4bc1cd7b54ba894fa89fa02fc6b0bbeea67d53251acd14a05", tse.real_out_tx_key);
    tse.real_output_in_tx_index = 1;
    tse.amount = 11066009260865;

    // tcd.change_dts
    tcd.change_dts.amount = 9631208773403;

    cryptonote::address_parse_info temp;
    cryptonote::get_account_address_from_str(
      temp,
      nettype,
      "SFXtzUpLfKDTSBG1KEydRqTmac2vvvpXZU6yx4Yct1dHUSPJ6AJqCj1Umne7mznPpjV7Bz9PgjavTVSbLB1Ngn2BVmzgCdUvvDW"
    );
    tcd.change_dts.addr = temp.address;
    // tcd.splitted_dsts

    tcd.splitted_dsts.resize(2);
    auto& splitted_dst0 = tcd.splitted_dsts[0];
    auto& splitted_dst1 = tcd.splitted_dsts[1];
    splitted_dst0.amount = 1400000000000;
    splitted_dst1.amount = 9631208773403;

    cryptonote::get_account_address_from_str(
      temp,
      nettype,
      "SFXtzTk5BUjLQj1RPmzcMdLk8MT1TwoTMM5XhUd9tzZ5MadiX3gpnCfMv34YfNmyJPNFSQaH4jAQ7NaqkbtkgMVqNvF6dZ95naL"
    );
    splitted_dst0.addr = temp.address;

    cryptonote::get_account_address_from_str(
      temp,
      nettype,
      "SFXtzUJgugKQ69ojAMTiSbQRZ9kn3QuYKQkxVnPjN6e3R6Mqp1RKHjmRRmBqd7GUqVRmAXsEoDfwDS6ZstrVAs2wSRyDvUMwfap"
    );
    splitted_dst1.addr = temp.address;

    // tcd.selected_transfers
    tcd.selected_transfers.push_back(2);
    // tcd.extra
    tcd.extra.resize(68);
    // tcd.{unlock_time, use_rct}
    tcd.unlock_time = 0;
    tcd.use_rct = true;
    // tcd.dests
    tcd.dests.emplace_back();
    auto& dest = tcd.dests[0];
    dest.amount = 1400000000000;

    cryptonote::get_account_address_from_str(
      temp,
      nettype,
      "SFXtzUJgugKQ69ojAMTiSbQRZ9kn3QuYKQkxVnPjN6e3R6Mqp1RKHjmRRmBqd7GUqVRmAXsEoDfwDS6ZstrVAs2wSRyDvUMwfap"
    );
    dest.addr = temp.address;

    // transfers
    exported_txs.transfers.resize(3);
    auto& td0 = exported_txs.transfers[0];
    auto& td1 = exported_txs.transfers[1];
    auto& td2 = exported_txs.transfers[2];
    td0.m_block_height = 818424;
    td1.m_block_height = 818522;
    td2.m_block_height = 818522;
    epee::string_tools::hex_to_pod("15024343b38e77a1a9860dfed29921fa17e833fec837191a6b04fa7cb9605b8e", td0.m_txid);
    epee::string_tools::hex_to_pod("ec34c9bb12b99af33d49691384eee5bed9171498ff04e59516505f35d1fc5efc", td1.m_txid);
    epee::string_tools::hex_to_pod("6e7013684d35820f66c6679197ded9329bfe0e495effa47e7b25258799858dba", td2.m_txid);
    td0.m_internal_output_index = 0;
    td1.m_internal_output_index = 0;
    td2.m_internal_output_index = 1;
    td0.m_global_output_index = 19642;
    td1.m_global_output_index = 19757;
    td2.m_global_output_index = 19760;
    td0.m_spent = true;
    td1.m_spent = false;
    td2.m_spent = false;
    td0.m_spent_height = 0;
    td1.m_spent_height = 0;
    td2.m_spent_height = 0;
    epee::string_tools::hex_to_pod("c5680d3735b90871ca5e3d90cd82d6483eed1151b9ab75c2c8c3a7d89e00a5a8", td0.m_key_image);
    epee::string_tools::hex_to_pod("d54cbd435a8d636ad9b01b8d4f3eb13bd0cf1ce98eddf53ab1617f9b763e66c0", td1.m_key_image);
    epee::string_tools::hex_to_pod("6c3cd6af97c4070a7aef9b1344e7463e29c7cd245076fdb65da447a34da3ca76", td2.m_key_image);
    epee::string_tools::hex_to_pod("0100000000000000000000000000000000000000000000000000000000000000", td0.m_mask);
    epee::string_tools::hex_to_pod("d3997a7b27fa199a377643b88cbd3f20f447496746dabe92d288730ecaeda007", td1.m_mask);
    epee::string_tools::hex_to_pod("789bafff169ef206aa21219342c69ca52ce1d78d776c10b21d14bdd960fc7703", td2.m_mask);
    td0.m_amount = 13400845012231;
    td1.m_amount = 1200000000000;
    td2.m_amount = 11066009260865;
    td0.m_rct = true;
    td1.m_rct = true;
    td2.m_rct = true;
    td0.m_key_image_known = true;
    td1.m_key_image_known = true;
    td2.m_key_image_known = true;
    td0.m_pk_index = 0;
    td1.m_pk_index = 0;
    td2.m_pk_index = 0;

    //<--------------------- Encrypt -----------------------------
    ::tools::wallet wallet;
    crypto::secret_key view_secret_key;
    std::ostringstream oss;
    const boost::filesystem::path filename = unit_test::data_dir / "unsigned_safex_tx";
    std::string ciphertext = "";
    std::string magic(UNSIGNED_TX_PREFIX);
    bool authenticated = true;
    boost::archive::portable_binary_oarchive ar(oss);

    epee::string_tools::hex_to_pod("339673bb1187e2f73ba7841ab6841c5553f96e9f13f8fe6612e69318db4e9d0a", view_secret_key);
    ASSERT_NO_THROW(ar << exported_txs);
    ASSERT_NO_THROW(ciphertext = wallet.encrypt(oss.str(), view_secret_key, authenticated));
    ASSERT_NO_THROW(epee::file_io_utils::save_string_to_file(filename.string(), magic + ciphertext));
  }
}

TEST(Serialization, portability_unsigned_tx)
{

  generate_unsigned_safex_tx_file();
  const boost::filesystem::path filename = unit_test::data_dir / "unsigned_safex_tx";
  std::string s;
  const cryptonote::network_type nettype = cryptonote::TESTNET;
  bool r = epee::file_io_utils::load_file_to_string(filename.string(), s);
  ASSERT_TRUE(r);
  const size_t magiclen = strlen(UNSIGNED_TX_PREFIX);
  ASSERT_FALSE(strncmp(s.c_str(), UNSIGNED_TX_PREFIX, magiclen));
  tools::wallet::unsigned_tx_set exported_txs;
  s = s.substr(magiclen);
  ::tools::wallet wallet;
  crypto::secret_key view_secret_key;
  epee::string_tools::hex_to_pod("339673bb1187e2f73ba7841ab6841c5553f96e9f13f8fe6612e69318db4e9d0a", view_secret_key);
  s = wallet.decrypt(s, view_secret_key, true);
  r = false;
  try
  {
    std::istringstream iss(s);
    boost::archive::portable_binary_iarchive ar(iss);
    ar >> exported_txs;
    r = true;
  }
  catch (...)
  {}
  ASSERT_TRUE(r);
  /*
   * fields of tools::wallet::unsigned_tx_set to be checked:
   *   std::vector<tx_construction_data> txes
   *   std::vector<wallet::transfer_details> m_transfers
   * fields of toolw::wallet::tx_construction_data to be checked:
   *   std::vector<cryptonote::tx_source_entry>      sources
   *   cryptonote::tx_destination_entry              change_dts
   *   std::vector<cryptonote::tx_destination_entry> splitted_dsts
   *   std::list<size_t>                             selected_transfers
   *   std::vector<uint8_t>                          extra
   *   uint64_t                                      unlock_time
   *   bool                                          use_rct
   *   std::vector<cryptonote::tx_destination_entry> dests
   *
   * fields of cryptonote::tx_source_entry to be checked:
   *   std::vector<std::pair<uint64_t, rct::ctkey>>  outputs
   *   size_t                                        real_output
   *   crypto::public_key                            real_out_tx_key
   *   size_t                                        real_output_in_tx_index
   *   uint64_t                                      amount
   *   bool                                          rct
   *   rct::key                                      mask
   *
   * fields of cryptonote::tx_destination_entry to be checked:
   *   uint64_t                amount
   *   account_public_address  addr
   */
  // txes
  ASSERT_TRUE(exported_txs.txes.size() == 1);
  auto& tcd = exported_txs.txes[0];
  // tcd.sources
  ASSERT_TRUE(tcd.sources.size() == 1);
  auto& tse = tcd.sources[0];
  // tcd.sources[0].outputs
  ASSERT_TRUE(tse.outputs.size() == 5);
  auto& out0 = tse.outputs[0];
  auto& out1 = tse.outputs[1];
  auto& out2 = tse.outputs[2];
  auto& out3 = tse.outputs[3];
  auto& out4 = tse.outputs[4];
  ASSERT_TRUE(out0.first == 6295);
  ASSERT_TRUE(out1.first == 14302);
  ASSERT_TRUE(out2.first == 17598);
  ASSERT_TRUE(out3.first == 18671);
  ASSERT_TRUE(out4.first == 19760);
  ASSERT_TRUE(epee::string_tools::pod_to_hex(out0.second) == "e7272cb589954ddeedd20de9411ed57265f154d41f33cec9ff69e5d642e09814096490b0ac85308342acf436cc0270d53abef9dc04c6202f2459e879bfd40ce6");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(out1.second) == "c3a9f49d1fe75939cc3feb39871ce0a7366c2879a63faa1a5cf34e65723b120a272ff0c7d84ab8b6ee3528d196450b0e28b3fed276bc2597a2b5b17afb9354ab");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(out2.second) == "176e239c8c39000c2275e2f63ed7d55c55e0843524091522bbd3d3b869044969021fad70fc1244115449d4754829ae7c47346342ee5d52a2cdd47dfc351d0ab0");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(out3.second) == "ef12d7946302fb064f2ba9df1a73d72233ac74664ed3b370580fa3bdc377542ad93f64898bd95851d6efe0d7bf2dbbea9b7c6b3c57e2c807e7b17d55b4622259");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(out4.second) == "0d8467e16e73d16510452b78823e082e05ee3a63788d40de577cf31eb555f0c8525096cbc88d00a841eed66f3cdb6f0a018e6ce9fb9433ed61afba15cbbebd04");
  // tcd.sources[0].{real_output, real_out_tx_key, real_output_in_tx_index, amount, rct, mask}
  ASSERT_TRUE(tse.real_output == 4);
  ASSERT_TRUE(epee::string_tools::pod_to_hex(tse.real_out_tx_key) == "4d86c7ba1c285fe4bc1cd7b54ba894fa89fa02fc6b0bbeea67d53251acd14a05");
  ASSERT_TRUE(tse.real_output_in_tx_index == 1);
  ASSERT_TRUE(tse.amount == 11066009260865);
  // tcd.change_dts
  ASSERT_TRUE(tcd.change_dts.amount == 9631208773403);
  ASSERT_TRUE(cryptonote::get_account_address_as_str(nettype, false, tcd.change_dts.addr) == "SFXtzUpLfKDTSBG1KEydRqTmac2vvvpXZU6yx4Yct1dHUSPJ6AJqCj1Umne7mznPpjV7Bz9PgjavTVSbLB1Ngn2BVmzgCdUvvDW");
  // tcd.splitted_dsts
  ASSERT_TRUE(tcd.splitted_dsts.size() == 2);
  auto& splitted_dst0 = tcd.splitted_dsts[0];
  auto& splitted_dst1 = tcd.splitted_dsts[1];
  ASSERT_TRUE(splitted_dst0.amount == 1400000000000);
  ASSERT_TRUE(splitted_dst1.amount == 9631208773403);
  ASSERT_TRUE(cryptonote::get_account_address_as_str(nettype, false, splitted_dst0.addr) == "SFXtzTk5BUjLQj1RPmzcMdLk8MT1TwoTMM5XhUd9tzZ5MadiX3gpnCfMv34YfNmyJPNFSQaH4jAQ7NaqkbtkgMVqNvF6dZ95naL");
  ASSERT_TRUE(cryptonote::get_account_address_as_str(nettype, false, splitted_dst1.addr) == "SFXtzUJgugKQ69ojAMTiSbQRZ9kn3QuYKQkxVnPjN6e3R6Mqp1RKHjmRRmBqd7GUqVRmAXsEoDfwDS6ZstrVAs2wSRyDvUMwfap");
  // tcd.selected_transfers
  ASSERT_TRUE(tcd.selected_transfers.size() == 1);
  ASSERT_TRUE(tcd.selected_transfers.front() == 2);
  // tcd.extra
  ASSERT_TRUE(tcd.extra.size() == 68);
  // tcd.{unlock_time, use_rct}
  ASSERT_TRUE(tcd.unlock_time == 0);
  ASSERT_TRUE(tcd.use_rct);
  // tcd.dests
  ASSERT_TRUE(tcd.dests.size() == 1);
  auto& dest = tcd.dests[0];
  ASSERT_TRUE(dest.amount == 1400000000000);
  ASSERT_TRUE(cryptonote::get_account_address_as_str(nettype, false, dest.addr) == "SFXtzUJgugKQ69ojAMTiSbQRZ9kn3QuYKQkxVnPjN6e3R6Mqp1RKHjmRRmBqd7GUqVRmAXsEoDfwDS6ZstrVAs2wSRyDvUMwfap");
  // transfers
  ASSERT_TRUE(exported_txs.transfers.size() == 3);
  auto& td0 = exported_txs.transfers[0];
  auto& td1 = exported_txs.transfers[1];
  auto& td2 = exported_txs.transfers[2];
  ASSERT_TRUE(td0.m_block_height == 818424);
  ASSERT_TRUE(td1.m_block_height == 818522);
  ASSERT_TRUE(td2.m_block_height == 818522);
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td0.m_txid) == "15024343b38e77a1a9860dfed29921fa17e833fec837191a6b04fa7cb9605b8e");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td1.m_txid) == "ec34c9bb12b99af33d49691384eee5bed9171498ff04e59516505f35d1fc5efc");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td2.m_txid) == "6e7013684d35820f66c6679197ded9329bfe0e495effa47e7b25258799858dba");
  ASSERT_TRUE(td0.m_internal_output_index == 0);
  ASSERT_TRUE(td1.m_internal_output_index == 0);
  ASSERT_TRUE(td2.m_internal_output_index == 1);
  ASSERT_TRUE(td0.m_global_output_index == 19642);
  ASSERT_TRUE(td1.m_global_output_index == 19757);
  ASSERT_TRUE(td2.m_global_output_index == 19760);
  ASSERT_TRUE (td0.m_spent);
  ASSERT_FALSE(td1.m_spent);
  ASSERT_FALSE(td2.m_spent);
  ASSERT_TRUE(td0.m_spent_height == 0);
  ASSERT_TRUE(td1.m_spent_height == 0);
  ASSERT_TRUE(td2.m_spent_height == 0);
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td0.m_key_image) == "c5680d3735b90871ca5e3d90cd82d6483eed1151b9ab75c2c8c3a7d89e00a5a8");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td1.m_key_image) == "d54cbd435a8d636ad9b01b8d4f3eb13bd0cf1ce98eddf53ab1617f9b763e66c0");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td2.m_key_image) == "6c3cd6af97c4070a7aef9b1344e7463e29c7cd245076fdb65da447a34da3ca76");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td0.m_mask) == "0100000000000000000000000000000000000000000000000000000000000000");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td1.m_mask) == "d3997a7b27fa199a377643b88cbd3f20f447496746dabe92d288730ecaeda007");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td2.m_mask) == "789bafff169ef206aa21219342c69ca52ce1d78d776c10b21d14bdd960fc7703");
  ASSERT_TRUE(td0.m_amount == 13400845012231);
  ASSERT_TRUE(td1.m_amount == 1200000000000);
  ASSERT_TRUE(td2.m_amount == 11066009260865);
  ASSERT_TRUE(td0.m_rct);
  ASSERT_TRUE(td1.m_rct);
  ASSERT_TRUE(td2.m_rct);
  ASSERT_TRUE(td0.m_key_image_known);
  ASSERT_TRUE(td1.m_key_image_known);
  ASSERT_TRUE(td2.m_key_image_known);
  ASSERT_TRUE(td0.m_pk_index == 0);
  ASSERT_TRUE(td1.m_pk_index == 0);
  ASSERT_TRUE(td2.m_pk_index == 0);
}

#define SIGNED_TX_PREFIX "Safex signed tx set\003"
namespace {
  void generate_signed_safex_tx_file()
  {
    ::tools::wallet::signed_tx_set exported_txs;
    const cryptonote::network_type nettype = cryptonote::TESTNET;

    exported_txs.ptx.emplace_back();
    auto& ptx = exported_txs.ptx[0];
    // ptx.{dust, fee, dust_added_to_fee}
    ptx.dust = 0;
    ptx.fee = 34800487462;
    ptx.dust_added_to_fee = false;
    // ptx.change.{amount, addr}
    ptx.change_dts.amount = 9631208773403;

    cryptonote::address_parse_info temp;
    cryptonote::get_account_address_from_str(
      temp,
      nettype,
      "SFXtzUpLfKDTSBG1KEydRqTmac2vvvpXZU6yx4Yct1dHUSPJ6AJqCj1Umne7mznPpjV7Bz9PgjavTVSbLB1Ngn2BVmzgCdUvvDW"
    );
    ptx.change_dts.addr = temp.address;

    // ptx.selected_transfers
    ptx.selected_transfers.push_back(2);
    // ptx.{key_images, tx_key}
    ptx.key_images = "<6c3cd6af97c4070a7aef9b1344e7463e29c7cd245076fdb65da447a34da3ca76> ";
    epee::string_tools::hex_to_pod("0100000000000000000000000000000000000000000000000000000000000000", ptx.tx_key);
    // ptx.dests
    ptx.dests.emplace_back();
    ptx.dests[0].amount = 1400000000000;
    cryptonote::get_account_address_from_str(
      temp,
      nettype,
      "SFXtzUpLfKDTSBG1KEydRqTmac2vvvpXZU6yx4Yct1dHUSPJ6AJqCj1Umne7mznPpjV7Bz9PgjavTVSbLB1Ngn2BVmzgCdUvvDW"
    );
    ptx.dests[0].addr = temp.address;

    // ptx.construction_data
    auto& tcd = ptx.construction_data;
    tcd.sources.emplace_back();
    auto& tse = tcd.sources[0];
    // ptx.construction_data.sources[0].outputs
    tse.outputs.resize(5);
    auto& out0 = tse.outputs[0];
    auto& out1 = tse.outputs[1];
    auto& out2 = tse.outputs[2];
    auto& out3 = tse.outputs[3];
    auto& out4 = tse.outputs[4];
    out0.first = 6295;
    out1.first = 14302;
    out2.first = 17598;
    out3.first = 18671;
    out4.first = 19760;
    epee::string_tools::hex_to_pod(
      "e7272cb589954ddeedd20de9411ed57265f154d41f33cec9ff69e5d642e09814096490b0ac85308342acf436cc0270d53abef9dc04c6202f2459e879bfd40ce6",
      out0.second
      );
    epee::string_tools::hex_to_pod(
      "c3a9f49d1fe75939cc3feb39871ce0a7366c2879a63faa1a5cf34e65723b120a272ff0c7d84ab8b6ee3528d196450b0e28b3fed276bc2597a2b5b17afb9354ab",
      out1.second
    );
    epee::string_tools::hex_to_pod(
      "176e239c8c39000c2275e2f63ed7d55c55e0843524091522bbd3d3b869044969021fad70fc1244115449d4754829ae7c47346342ee5d52a2cdd47dfc351d0ab0",
      out2.second
    );
    epee::string_tools::hex_to_pod(
      "ef12d7946302fb064f2ba9df1a73d72233ac74664ed3b370580fa3bdc377542ad93f64898bd95851d6efe0d7bf2dbbea9b7c6b3c57e2c807e7b17d55b4622259",
      out3.second
    );
    epee::string_tools::hex_to_pod(
      "0d8467e16e73d16510452b78823e082e05ee3a63788d40de577cf31eb555f0c8525096cbc88d00a841eed66f3cdb6f0a018e6ce9fb9433ed61afba15cbbebd04",
      out4.second
    );
    // ptx.construction_data.sources[0].{real_output, real_out_tx_key, real_output_in_tx_index, amount, rct, mask}
    tse.real_output = 4;
    epee::string_tools::hex_to_pod("4d86c7ba1c285fe4bc1cd7b54ba894fa89fa02fc6b0bbeea67d53251acd14a05", tse.real_out_tx_key);
    tse.real_output_in_tx_index = 1;
    tse.amount = 11066009260865;
    // ptx.construction_data.change_dts
    tcd.change_dts.amount = 9631208773403;

    cryptonote::get_account_address_from_str(
      temp,
      nettype,
      "SFXtzUpLfKDTSBG1KEydRqTmac2vvvpXZU6yx4Yct1dHUSPJ6AJqCj1Umne7mznPpjV7Bz9PgjavTVSbLB1Ngn2BVmzgCdUvvDW"
    );
    tcd.change_dts.addr = temp.address;
    // ptx.construction_data.splitted_dsts

    tcd.splitted_dsts.resize(2);
    auto& splitted_dst0 = tcd.splitted_dsts[0];
    auto& splitted_dst1 = tcd.splitted_dsts[1];
    splitted_dst0.amount = 1400000000000;
    splitted_dst1.amount = 9631208773403;
    cryptonote::get_account_address_from_str(
      temp,
      nettype,
      "SFXtzTk5BUjLQj1RPmzcMdLk8MT1TwoTMM5XhUd9tzZ5MadiX3gpnCfMv34YfNmyJPNFSQaH4jAQ7NaqkbtkgMVqNvF6dZ95naL"
    );
    splitted_dst0.addr = temp.address;

    cryptonote::get_account_address_from_str(
      temp,
      nettype,
      "SFXtzUJgugKQ69ojAMTiSbQRZ9kn3QuYKQkxVnPjN6e3R6Mqp1RKHjmRRmBqd7GUqVRmAXsEoDfwDS6ZstrVAs2wSRyDvUMwfap"
    );
    splitted_dst1.addr = temp.address;
    // ptx.construction_data.selected_transfers
    tcd.selected_transfers.push_back(2);
    // ptx.construction_data.extra
    tcd.extra.resize(68);
    // ptx.construction_data.{unlock_time, use_rct}
    tcd.unlock_time = 0;
    tcd.use_rct = true;
    // ptx.construction_data.dests
    tcd.dests.emplace_back();
    auto& dest = tcd.dests[0];
    dest.amount = 1400000000000;
    cryptonote::get_account_address_from_str(
      temp,
      nettype,
      "SFXtzUJgugKQ69ojAMTiSbQRZ9kn3QuYKQkxVnPjN6e3R6Mqp1RKHjmRRmBqd7GUqVRmAXsEoDfwDS6ZstrVAs2wSRyDvUMwfap"
    );
    dest.addr = temp.address;

    // key_images
    exported_txs.key_images.resize(3);
    auto& ki0 = exported_txs.key_images[0];
    auto& ki1 = exported_txs.key_images[1];
    auto& ki2 = exported_txs.key_images[2];
    epee::string_tools::hex_to_pod("c5680d3735b90871ca5e3d90cd82d6483eed1151b9ab75c2c8c3a7d89e00a5a8", ki0);
    epee::string_tools::hex_to_pod("d54cbd435a8d636ad9b01b8d4f3eb13bd0cf1ce98eddf53ab1617f9b763e66c0", ki1);
    epee::string_tools::hex_to_pod("6c3cd6af97c4070a7aef9b1344e7463e29c7cd245076fdb65da447a34da3ca76", ki2);

    //<--------------------- Encrypt -----------------------------
    ::tools::wallet wallet;
    crypto::secret_key view_secret_key;
    std::ostringstream oss;
    const boost::filesystem::path filename = unit_test::data_dir / "signed_safex_tx";
    std::string ciphertext = "";
    std::string magic(SIGNED_TX_PREFIX);
    bool authenticated = true;
    boost::archive::portable_binary_oarchive ar(oss);

    epee::string_tools::hex_to_pod("339673bb1187e2f73ba7841ab6841c5553f96e9f13f8fe6612e69318db4e9d0a", view_secret_key);
    ASSERT_NO_THROW(ar << exported_txs);
    ASSERT_NO_THROW(ciphertext = wallet.encrypt(oss.str(), view_secret_key, authenticated));
    ASSERT_NO_THROW(epee::file_io_utils::save_string_to_file(filename.string(), magic + ciphertext));
  }
}

TEST(Serialization, portability_signed_tx)
{
  generate_signed_safex_tx_file();
  ::tools::wallet wallet;
  const boost::filesystem::path filename = unit_test::data_dir / "signed_safex_tx";
  const cryptonote::network_type nettype = cryptonote::TESTNET;
  std::string s;
  bool r = epee::file_io_utils::load_file_to_string(filename.string(), s);
  ASSERT_TRUE(r);
  const size_t magiclen = strlen(SIGNED_TX_PREFIX);
  ASSERT_FALSE(strncmp(s.c_str(), SIGNED_TX_PREFIX, magiclen));
  tools::wallet::signed_tx_set exported_txs;

  crypto::secret_key view_secret_key;
  epee::string_tools::hex_to_pod("339673bb1187e2f73ba7841ab6841c5553f96e9f13f8fe6612e69318db4e9d0a", view_secret_key);

  s = s.substr(magiclen);
  ASSERT_NO_THROW(s = wallet.decrypt(s, view_secret_key, true));
  r = false;
  try
  {
    std::istringstream iss(s);
    boost::archive::portable_binary_iarchive ar(iss);
    ar >> exported_txs;
    r = true;
  }
  catch (...)
  {}
  ASSERT_TRUE(r);
  /*
   * fields of tools::wallet::signed_tx_set to be checked:
   *   std::vector<pending_tx>         ptx
   *   std::vector<crypto::key_image>  key_images
   *
   * fields of tools::walllet2::pending_tx to be checked:
   *   cryptonote::transaction                       tx                  // TODO
   *   uint64_t                                      dust
   *   uint64_t                                      fee
   *   bool                                          dust_added_to_fee
   *   cryptonote::tx_destination_entry              change_dts
   *   std::list<size_t>                             selected_transfers
   *   std::string                                   key_images
   *   crypto::secret_key                            tx_key
   *   std::vector<cryptonote::tx_destination_entry> dests
   *   tx_construction_data                          construction_data
   */
  // ptx
  ASSERT_TRUE(exported_txs.ptx.size() == 1);
  auto& ptx = exported_txs.ptx[0];
  // ptx.{dust, fee, dust_added_to_fee}
  ASSERT_TRUE (ptx.dust == 0);
  ASSERT_TRUE (ptx.fee == 34800487462);
  ASSERT_FALSE(ptx.dust_added_to_fee);
  // ptx.change.{amount, addr}
  ASSERT_TRUE(ptx.change_dts.amount == 9631208773403);
  ASSERT_TRUE(cryptonote::get_account_address_as_str(nettype, false, ptx.change_dts.addr) == "SFXtzUpLfKDTSBG1KEydRqTmac2vvvpXZU6yx4Yct1dHUSPJ6AJqCj1Umne7mznPpjV7Bz9PgjavTVSbLB1Ngn2BVmzgCdUvvDW");
  // ptx.selected_transfers
  ASSERT_TRUE(ptx.selected_transfers.size() == 1);
  ASSERT_TRUE(ptx.selected_transfers.front() == 2);
  // ptx.{key_images, tx_key}
  ASSERT_TRUE(ptx.key_images == "<6c3cd6af97c4070a7aef9b1344e7463e29c7cd245076fdb65da447a34da3ca76> ");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(ptx.tx_key) == "0100000000000000000000000000000000000000000000000000000000000000");
  // ptx.dests
  ASSERT_TRUE(ptx.dests.size() == 1);
  ASSERT_TRUE(ptx.dests[0].amount == 1400000000000);
  ASSERT_TRUE(cryptonote::get_account_address_as_str(nettype, false, ptx.dests[0].addr) == "SFXtzUpLfKDTSBG1KEydRqTmac2vvvpXZU6yx4Yct1dHUSPJ6AJqCj1Umne7mznPpjV7Bz9PgjavTVSbLB1Ngn2BVmzgCdUvvDW");
  // ptx.construction_data
  auto& tcd = ptx.construction_data;
  ASSERT_TRUE(tcd.sources.size() == 1);
  auto& tse = tcd.sources[0];
  // ptx.construction_data.sources[0].outputs
  ASSERT_TRUE(tse.outputs.size() == 5);
  auto& out0 = tse.outputs[0];
  auto& out1 = tse.outputs[1];
  auto& out2 = tse.outputs[2];
  auto& out3 = tse.outputs[3];
  auto& out4 = tse.outputs[4];
  ASSERT_TRUE(out0.first == 6295);
  ASSERT_TRUE(out1.first == 14302);
  ASSERT_TRUE(out2.first == 17598);
  ASSERT_TRUE(out3.first == 18671);
  ASSERT_TRUE(out4.first == 19760);
  ASSERT_TRUE(epee::string_tools::pod_to_hex(out0.second) == "e7272cb589954ddeedd20de9411ed57265f154d41f33cec9ff69e5d642e09814096490b0ac85308342acf436cc0270d53abef9dc04c6202f2459e879bfd40ce6");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(out1.second) == "c3a9f49d1fe75939cc3feb39871ce0a7366c2879a63faa1a5cf34e65723b120a272ff0c7d84ab8b6ee3528d196450b0e28b3fed276bc2597a2b5b17afb9354ab");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(out2.second) == "176e239c8c39000c2275e2f63ed7d55c55e0843524091522bbd3d3b869044969021fad70fc1244115449d4754829ae7c47346342ee5d52a2cdd47dfc351d0ab0");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(out3.second) == "ef12d7946302fb064f2ba9df1a73d72233ac74664ed3b370580fa3bdc377542ad93f64898bd95851d6efe0d7bf2dbbea9b7c6b3c57e2c807e7b17d55b4622259");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(out4.second) == "0d8467e16e73d16510452b78823e082e05ee3a63788d40de577cf31eb555f0c8525096cbc88d00a841eed66f3cdb6f0a018e6ce9fb9433ed61afba15cbbebd04");
  // ptx.construction_data.sources[0].{real_output, real_out_tx_key, real_output_in_tx_index, amount, rct, mask}
  ASSERT_TRUE(tse.real_output == 4);
  ASSERT_TRUE(epee::string_tools::pod_to_hex(tse.real_out_tx_key) == "4d86c7ba1c285fe4bc1cd7b54ba894fa89fa02fc6b0bbeea67d53251acd14a05");
  ASSERT_TRUE(tse.real_output_in_tx_index == 1);
  ASSERT_TRUE(tse.amount == 11066009260865);
  // ptx.construction_data.change_dts
  ASSERT_TRUE(tcd.change_dts.amount == 9631208773403);
  ASSERT_TRUE(cryptonote::get_account_address_as_str(nettype, false, tcd.change_dts.addr) == "SFXtzUpLfKDTSBG1KEydRqTmac2vvvpXZU6yx4Yct1dHUSPJ6AJqCj1Umne7mznPpjV7Bz9PgjavTVSbLB1Ngn2BVmzgCdUvvDW");
  // ptx.construction_data.splitted_dsts
  ASSERT_TRUE(tcd.splitted_dsts.size() == 2);
  auto& splitted_dst0 = tcd.splitted_dsts[0];
  auto& splitted_dst1 = tcd.splitted_dsts[1];
  ASSERT_TRUE(splitted_dst0.amount == 1400000000000);
  ASSERT_TRUE(splitted_dst1.amount == 9631208773403);
  ASSERT_TRUE(cryptonote::get_account_address_as_str(nettype, false, splitted_dst0.addr) == "SFXtzTk5BUjLQj1RPmzcMdLk8MT1TwoTMM5XhUd9tzZ5MadiX3gpnCfMv34YfNmyJPNFSQaH4jAQ7NaqkbtkgMVqNvF6dZ95naL");
  ASSERT_TRUE(cryptonote::get_account_address_as_str(nettype, false, splitted_dst1.addr) == "SFXtzUJgugKQ69ojAMTiSbQRZ9kn3QuYKQkxVnPjN6e3R6Mqp1RKHjmRRmBqd7GUqVRmAXsEoDfwDS6ZstrVAs2wSRyDvUMwfap");
  // ptx.construction_data.selected_transfers
  ASSERT_TRUE(tcd.selected_transfers.size() == 1);
  ASSERT_TRUE(tcd.selected_transfers.front() == 2);
  // ptx.construction_data.extra
  ASSERT_TRUE(tcd.extra.size() == 68);
  // ptx.construction_data.{unlock_time, use_rct}
  ASSERT_TRUE(tcd.unlock_time == 0);
  ASSERT_TRUE(tcd.use_rct);
  // ptx.construction_data.dests
  ASSERT_TRUE(tcd.dests.size() == 1);
  auto& dest = tcd.dests[0];
  ASSERT_TRUE(dest.amount == 1400000000000);
  ASSERT_TRUE(cryptonote::get_account_address_as_str(nettype, false, dest.addr) == "SFXtzUJgugKQ69ojAMTiSbQRZ9kn3QuYKQkxVnPjN6e3R6Mqp1RKHjmRRmBqd7GUqVRmAXsEoDfwDS6ZstrVAs2wSRyDvUMwfap");
  // key_images
  ASSERT_TRUE(exported_txs.key_images.size() == 3);
  auto& ki0 = exported_txs.key_images[0];
  auto& ki1 = exported_txs.key_images[1];
  auto& ki2 = exported_txs.key_images[2];
  ASSERT_TRUE(epee::string_tools::pod_to_hex(ki0) == "c5680d3735b90871ca5e3d90cd82d6483eed1151b9ab75c2c8c3a7d89e00a5a8");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(ki1) == "d54cbd435a8d636ad9b01b8d4f3eb13bd0cf1ce98eddf53ab1617f9b763e66c0");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(ki2) == "6c3cd6af97c4070a7aef9b1344e7463e29c7cd245076fdb65da447a34da3ca76");
}
