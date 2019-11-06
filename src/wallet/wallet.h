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

#include <memory>

#include <boost/program_options/options_description.hpp>
#include <utility>
#include <boost/program_options/variables_map.hpp>
#include <boost/serialization/list.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/deque.hpp>
#include <atomic>

#include "include_base_utils.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/account_boost_serialization.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "net/http_client.h"
#include "storages/http_abstract_invoke.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "common/unordered_containers_boost_serialization.h"
#include "crypto/chacha.h"
#include "crypto/hash.h"
#include "ringct/rctTypes.h"
#include "ringct/rctOps.h"
#include "checkpoints/checkpoints.h"
#include "safex/safex_core.h"
#include "safex/safex_account.h"
#include "common/command_line.h"
#include "safex/safex_offer.h"

#include "wallet_errors.h"
#include "common/password.h"
#include "node_rpc_proxy.h"


#undef SAFEX_DEFAULT_LOG_CATEGORY
#define SAFEX_DEFAULT_LOG_CATEGORY "wallet.wallet"

class Serialization_portability_wallet_Test;
class Serialization_serialize_wallet_Test;

namespace tools
{
  class ringdb;

  class i_wallet_callback
  {
  public:
    // Full wallet callbacks
    virtual void on_new_block(uint64_t height, const cryptonote::block& block) {}
    virtual void on_money_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t amount, const cryptonote::subaddress_index& subaddr_index) {}
    virtual void on_tokens_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t token_amount, const cryptonote::subaddress_index& subaddr_index) {}
    virtual void on_advanced_output_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, const cryptonote::txout_to_script &txout, const cryptonote::subaddress_index& subaddr_index){}
    virtual void on_unconfirmed_money_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t amount, const cryptonote::subaddress_index& subaddr_index) {}
    virtual void on_unconfirmed_tokens_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t token_amount, const cryptonote::subaddress_index& subaddr_index) {}
    virtual void on_money_spent(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& in_tx, uint64_t amount, const cryptonote::transaction& spend_tx, const cryptonote::subaddress_index& subaddr_index) {}
    virtual void on_tokens_spent(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& in_tx, uint64_t token_amount, const cryptonote::transaction& spend_tx, const cryptonote::subaddress_index& subaddr_index) {}
    virtual void on_skip_transaction(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx) {}
    // Light wallet callbacks
    virtual void on_lw_new_block(uint64_t height) {}
    virtual void on_lw_money_received(uint64_t height, const crypto::hash &txid, uint64_t amount) {}
    virtual void on_lw_token_received(uint64_t height, const crypto::hash &txid, uint64_t amount) {}
    virtual void on_lw_unconfirmed_money_received(uint64_t height, const crypto::hash &txid, uint64_t amount) {}
    virtual void on_lw_unconfirmed_token_received(uint64_t height, const crypto::hash &txid, uint64_t amount) {}
    virtual void on_lw_money_spent(uint64_t height, const crypto::hash &txid, uint64_t amount) {}
    virtual void on_lw_token_spent(uint64_t height, const crypto::hash &txid, uint64_t amount) {}
    // Common callbacks
    virtual void on_pool_tx_removed(const crypto::hash &txid) {}
    virtual ~i_wallet_callback() {}
  };

  struct tx_dust_policy
  {
    uint64_t dust_threshold;
    uint64_t token_dust_threshold;
    bool add_to_fee;
    cryptonote::account_public_address addr_for_dust;

    tx_dust_policy(uint64_t a_dust_threshold = 0, uint64_t a_token_dust_threshold = 0, bool an_add_to_fee = true, cryptonote::account_public_address an_addr_for_dust = cryptonote::account_public_address())
      : dust_threshold(a_dust_threshold)
      , token_dust_threshold(a_token_dust_threshold)
      , add_to_fee(an_add_to_fee)
      , addr_for_dust(an_addr_for_dust)
    {
    }
  };

  class hashchain
  {
  public:
    hashchain(): m_genesis(crypto::null_hash), m_offset(0) {}

    size_t size() const { return m_blockchain.size() + m_offset; }
    size_t offset() const { return m_offset; }
    const crypto::hash &genesis() const { return m_genesis; }
    void push_back(const crypto::hash &hash) { if (m_offset == 0 && m_blockchain.empty()) m_genesis = hash; m_blockchain.push_back(hash); }
    bool is_in_bounds(size_t idx) const { return idx >= m_offset && idx < size(); }
    const crypto::hash &operator[](size_t idx) const { return m_blockchain[idx - m_offset]; }
    crypto::hash &operator[](size_t idx) { return m_blockchain[idx - m_offset]; }
    void crop(size_t height) { m_blockchain.resize(height - m_offset); }
    void clear() { m_offset = 0; m_blockchain.clear(); }
    bool empty() const { return m_blockchain.empty() && m_offset == 0; }
    void trim(size_t height) { while (height > m_offset && m_blockchain.size() > 1) { m_blockchain.pop_front(); ++m_offset; } m_blockchain.shrink_to_fit(); }
    void refill(const crypto::hash &hash) { m_blockchain.push_back(hash); --m_offset; }

    template <class t_archive>
    inline void serialize(t_archive &a, const unsigned int ver)
    {
      a & m_offset;
      a & m_genesis;
      a & m_blockchain;
    }

  private:
    size_t m_offset;
    crypto::hash m_genesis;
    std::deque<crypto::hash> m_blockchain;
  };

  class wallet
  {
    friend class ::Serialization_portability_wallet_Test;
    friend class ::Serialization_serialize_wallet_Test;
  public:
    static constexpr const std::chrono::seconds rpc_timeout = std::chrono::minutes(3) + std::chrono::seconds(30);

    enum RefreshType {
      RefreshFull,
      RefreshOptimizeCoinbase,
      RefreshNoCoinbase,
      RefreshDefault = RefreshOptimizeCoinbase,
    };

    static const char* tr(const char* str);

    static bool has_testnet_option(const boost::program_options::variables_map& vm);
    static bool has_stagenet_option(const boost::program_options::variables_map& vm);
    static void init_options(boost::program_options::options_description& desc_params);

    //! Uses stdin and stdout. Returns a wallet if no errors.
    static std::unique_ptr<wallet> make_from_json(const boost::program_options::variables_map& vm, const std::string& json_file, const std::function<boost::optional<password_container>(const char *, bool)> &password_prompter);

    //! Uses stdin and stdout. Returns a wallet and password for `wallet_file` if no errors.
    static std::pair<std::unique_ptr<wallet>, password_container>
      make_from_file(const boost::program_options::variables_map& vm, const std::string& wallet_file, const std::function<boost::optional<password_container>(const char *, bool)> &password_prompter);

    //! Uses stdin and stdout. Returns a wallet and password for wallet with no file if no errors.
    static std::pair<std::unique_ptr<wallet>, password_container> make_new(const boost::program_options::variables_map& vm, const std::function<boost::optional<password_container>(const char *, bool)> &password_prompter);

    //! Just parses variables.
    static std::unique_ptr<wallet> make_dummy(const boost::program_options::variables_map& vm, const std::function<boost::optional<password_container>(const char *, bool)> &password_prompter);

    static bool verify_password(const std::string& keys_file_name, const epee::wipeable_string& password, bool no_spend_key, hw::device &hwdev);

    wallet(cryptonote::network_type nettype = cryptonote::MAINNET, bool restricted = false);
    ~wallet();

    struct multisig_info
    {
      struct LR
      {
        rct::key m_L;
        rct::key m_R;

        BEGIN_SERIALIZE_OBJECT()
          FIELD(m_L)
          FIELD(m_R)
        END_SERIALIZE()
      };

      crypto::public_key m_signer;
      std::vector<LR> m_LR;
      std::vector<crypto::key_image> m_partial_key_images; // one per key the participant has

      BEGIN_SERIALIZE_OBJECT()
        FIELD(m_signer)
        FIELD(m_LR)
        FIELD(m_partial_key_images)
      END_SERIALIZE()
    };

    struct tx_scan_info_t
    {
      cryptonote::keypair in_ephemeral;
      crypto::key_image ki;
      rct::key mask;
      uint64_t amount;
      uint64_t token_amount;
      uint64_t money_transfered;
      uint64_t token_transfered;
      bool error;
      bool token_transfer;
      boost::optional<cryptonote::subaddress_receive_info> received;
      cryptonote::tx_out_type output_type;

      tx_scan_info_t(): in_ephemeral(AUTO_VAL_INIT(in_ephemeral)), ki(AUTO_VAL_INIT(ki)), mask(AUTO_VAL_INIT(mask)), amount(0), token_amount(0),
                        money_transfered(0), token_transfered(0),  error(true), token_transfer(false), output_type(cryptonote::tx_out_type::out_invalid) {}
    };

    struct transfer_details
    {
      uint64_t m_block_height;
      cryptonote::transaction_prefix m_tx = AUTO_VAL_INIT(m_tx);
      crypto::hash m_txid = AUTO_VAL_INIT(m_txid);
      size_t m_internal_output_index;
      uint64_t m_global_output_index;
      bool m_spent;
      uint64_t m_spent_height;
      crypto::key_image m_key_image; //TODO: key_image stored twice :(
      rct::key m_mask;
      uint64_t m_amount = 0;
      uint64_t m_token_amount = 0;
      bool m_rct = false;
      bool m_key_image_known;
      bool m_token_transfer = false;
      size_t m_pk_index;
      cryptonote::subaddress_index m_subaddr_index;
      bool m_key_image_partial;
      std::vector<rct::key> m_multisig_k;
      std::vector<multisig_info> m_multisig_info; // one per other participant
      cryptonote::tx_out_type m_output_type = cryptonote::tx_out_type::out_cash; //cash outputs by default

      bool is_rct() const { return m_rct; }
      cryptonote::tx_out_type get_out_type() const { return m_output_type;}
      uint64_t amount() const { return m_amount; }
      uint64_t token_amount() const { return m_token_amount;}
      const crypto::public_key &get_public_key() const
      {
        return *boost::apply_visitor(cryptonote::destination_public_key_visitor(), m_tx.vout[m_internal_output_index].target);
      }

      BEGIN_SERIALIZE_OBJECT()
        FIELD(m_block_height)
        FIELD(m_tx)
        FIELD(m_txid)
        FIELD(m_internal_output_index)
        FIELD(m_global_output_index)
        FIELD(m_spent)
        FIELD(m_spent_height)
        FIELD(m_key_image)
        FIELD(m_mask)
        FIELD(m_amount)
        FIELD(m_token_amount)
        FIELD(m_rct)
        FIELD(m_key_image_known)
        FIELD(m_token_transfer)
        FIELD(m_pk_index)
        FIELD(m_subaddr_index)
        FIELD(m_key_image_partial)
        FIELD(m_multisig_k)
        FIELD(m_multisig_info)
        FIELD(m_output_type)
      END_SERIALIZE()
    };

    struct payment_details
    {
      crypto::hash m_tx_hash;
      uint64_t m_amount = 0;
      uint64_t m_token_amount = 0;
      uint64_t m_fee;
      uint64_t m_block_height;
      uint64_t m_unlock_time;
      uint64_t m_timestamp;
      cryptonote::subaddress_index m_subaddr_index;
      bool m_token_transaction = false;
      cryptonote::tx_out_type m_output_type = cryptonote::tx_out_type::out_invalid;
    };

    struct address_tx : payment_details
    {
      bool m_coinbase;
      bool m_mempool;
      bool m_incoming;
    };

    struct pool_payment_details
    {
      payment_details m_pd;
      bool m_double_spend_seen;
    };

    struct unconfirmed_transfer_details
    {
      cryptonote::transaction_prefix m_tx;
      uint64_t m_amount_in = 0;
      uint64_t m_amount_out = 0;
      uint64_t m_change = 0;
      uint64_t m_token_amount_in = 0;
      uint64_t m_token_amount_out = 0;
      uint64_t m_token_change = 0;
      time_t m_sent_time;
      std::vector<cryptonote::tx_destination_entry> m_dests;
      crypto::hash m_payment_id;
      enum { pending, pending_not_in_pool, failed } m_state;
      uint64_t m_timestamp;
      uint32_t m_subaddr_account;   // subaddress account of your wallet to be used in this transfer
      std::set<uint32_t> m_subaddr_indices;  // set of address indices used as inputs in this transfer
      std::vector<std::pair<crypto::key_image, std::vector<uint64_t>>> m_rings; // relative
      cryptonote::tx_out_type m_output_type = cryptonote::tx_out_type::out_invalid;
    };

    struct confirmed_transfer_details
    {
      uint64_t m_amount_in;
      uint64_t m_amount_out;
      uint64_t m_change;
      uint64_t m_token_amount_in;
      uint64_t m_token_amount_out;
      uint64_t m_token_change;
      uint64_t m_block_height;
      std::vector<cryptonote::tx_destination_entry> m_dests;
      crypto::hash m_payment_id;
      uint64_t m_timestamp;
      uint64_t m_unlock_time;
      uint32_t m_subaddr_account;   // subaddress account of your wallet to be used in this transfer
      std::set<uint32_t> m_subaddr_indices;  // set of address indices used as inputs in this transfer
      std::vector<std::pair<crypto::key_image, std::vector<uint64_t>>> m_rings; // relative
      cryptonote::tx_out_type m_output_type = cryptonote::tx_out_type::out_invalid;

      confirmed_transfer_details(): m_amount_in(0), m_amount_out(0), m_change((uint64_t)-1), m_token_amount_in(0), m_token_amount_out(0),  m_token_change((uint64_t)-1), m_block_height(0),
          m_payment_id(crypto::null_hash), m_timestamp(0), m_unlock_time(0), m_subaddr_account((uint32_t)-1) {}
      confirmed_transfer_details(const unconfirmed_transfer_details &utd, uint64_t height):
        m_amount_in(utd.m_amount_in), m_amount_out(utd.m_amount_out), m_change(utd.m_change), m_token_amount_in(utd.m_token_amount_in), m_token_amount_out(utd.m_token_amount_out),
        m_token_change(utd.m_token_change), m_block_height(height), m_dests(utd.m_dests), m_payment_id(utd.m_payment_id), m_timestamp(utd.m_timestamp), m_unlock_time(utd.m_tx.unlock_time),
        m_subaddr_account(utd.m_subaddr_account), m_subaddr_indices(utd.m_subaddr_indices), m_rings(utd.m_rings) {}
    };

    struct tx_construction_data
    {
      std::vector<cryptonote::tx_source_entry> sources;
      cryptonote::tx_destination_entry change_dts;
      std::vector<cryptonote::tx_destination_entry> splitted_dsts; // split, includes change
      std::vector<size_t> selected_transfers;
      std::vector<uint8_t> extra;
      uint64_t unlock_time;
      bool use_rct;
      std::vector<cryptonote::tx_destination_entry> dests; // original setup, does not include change
      uint32_t subaddr_account;   // subaddress account of your wallet to be used in this transfer
      std::set<uint32_t> subaddr_indices;  // set of address indices used as inputs in this transfer

      BEGIN_SERIALIZE_OBJECT()
        FIELD(sources)
        FIELD(change_dts)
        FIELD(splitted_dsts)
        FIELD(selected_transfers)
        FIELD(extra)
        FIELD(unlock_time)
        FIELD(use_rct)
        FIELD(dests)
        FIELD(subaddr_account)
        FIELD(subaddr_indices)
      END_SERIALIZE()
    };

    typedef std::vector<transfer_details> transfer_container;
    typedef std::unordered_multimap<crypto::hash, payment_details> payment_container;

    struct multisig_sig
    {
      rct::rctSig sigs;
      crypto::public_key ignore;
      std::unordered_set<rct::key> used_L;
      std::unordered_set<crypto::public_key> signing_keys;
      rct::multisig_out msout;
    };

    // The convention for destinations is:
    // dests does not include change
    // splitted_dsts (in construction_data) does
    struct pending_tx
    {
      cryptonote::transaction tx;
      uint64_t dust;
      uint64_t fee;
      bool dust_added_to_fee;
      cryptonote::tx_destination_entry change_dts;
      cryptonote::tx_destination_entry change_token_dts;
      std::vector<size_t> selected_transfers;
      std::string key_images;
      crypto::secret_key tx_key;
      std::vector<crypto::secret_key> additional_tx_keys;
      std::vector<cryptonote::tx_destination_entry> dests;
      std::vector<multisig_sig> multisig_sigs;
      tx_construction_data construction_data;

      BEGIN_SERIALIZE_OBJECT()
        FIELD(tx)
        FIELD(dust)
        FIELD(fee)
        FIELD(dust_added_to_fee)
        FIELD(change_dts)
        FIELD(change_token_dts)
        FIELD(selected_transfers)
        FIELD(key_images)
        FIELD(tx_key)
        FIELD(additional_tx_keys)
        FIELD(dests)
        FIELD(construction_data)
        FIELD(multisig_sigs)
      END_SERIALIZE()
    };

    // The term "Unsigned tx" is not really a tx since it's not signed yet.
    // It doesnt have tx hash, key and the integrated address is not separated into addr + payment id.
    struct unsigned_tx_set
    {
      std::vector<tx_construction_data> txes;
      wallet::transfer_container transfers;
    };

    struct signed_tx_set
    {
      std::vector<pending_tx> ptx;
      std::vector<crypto::key_image> key_images;
    };

    struct multisig_tx_set
    {
      std::vector<pending_tx> m_ptx;
      std::unordered_set<crypto::public_key> m_signers;

      BEGIN_SERIALIZE_OBJECT()
        FIELD(m_ptx)
        FIELD(m_signers)
      END_SERIALIZE()
    };

    struct keys_file_data
    {
      crypto::chacha_iv iv;
      std::string account_data;

      BEGIN_SERIALIZE_OBJECT()
        FIELD(iv)
        FIELD(account_data)
      END_SERIALIZE()
    };

    struct cache_file_data
    {
      crypto::chacha_iv iv;
      std::string cache_data;

      BEGIN_SERIALIZE_OBJECT()
        FIELD(iv)
        FIELD(cache_data)
      END_SERIALIZE()
    };

    // GUI Address book
    struct address_book_row
    {
      cryptonote::account_public_address m_address;
      crypto::hash m_payment_id;
      std::string m_description;
      bool m_is_subaddress;
    };

    struct reserve_proof_entry
    {
      crypto::hash txid;
      uint64_t index_in_tx;
      crypto::public_key shared_secret;
      crypto::key_image key_image;
      crypto::signature shared_secret_sig;
      crypto::signature key_image_sig;
    };

    typedef std::tuple<uint64_t, crypto::public_key, rct::key> get_outs_entry;

    /*!
     * \brief  Generates a wallet or restores one.
     * \param  wallet_              Name of wallet file
     * \param  password             Password of wallet file
     * \param  multisig_data        The multisig restore info and keys
     * \param  create_address_file  Whether to create an address file
     */
    void generate(const std::string& wallet_, const epee::wipeable_string& password,
      const std::string& multisig_data, bool create_address_file = false);

    /*!
     * \brief Generates a wallet or restores one.
     * \param  wallet_              Name of wallet file
     * \param  password             Password of wallet file
     * \param  recovery_param       If it is a restore, the recovery key
     * \param  recover              Whether it is a restore
     * \param  two_random           Whether it is a non-deterministic wallet
     * \param  create_address_file  Whether to create an address file
     * \return                      The secret key of the generated wallet
     */
    crypto::secret_key generate(const std::string& wallet, const epee::wipeable_string& password,
      const crypto::secret_key& recovery_param = crypto::secret_key(), bool recover = false,
      bool two_random = false, bool create_address_file = false);
    /*!
     * \brief Creates a wallet from a public address and a spend/view secret key pair.
     * \param  wallet_              Name of wallet file
     * \param  password             Password of wallet file
     * \param  viewkey              view secret key
     * \param  spendkey             spend secret key
     * \param  create_address_file  Whether to create an address file
     */
    void generate(const std::string& wallet, const epee::wipeable_string& password,
      const cryptonote::account_public_address &account_public_address,
      const crypto::secret_key& spendkey, const crypto::secret_key& viewkey, bool create_address_file = false);
    /*!
     * \brief Creates a watch only wallet from a public address and a view secret key.
     * \param  wallet_              Name of wallet file
     * \param  password             Password of wallet file
     * \param  viewkey              view secret key
     * \param  create_address_file  Whether to create an address file
     */
    void generate(const std::string& wallet, const epee::wipeable_string& password,
      const cryptonote::account_public_address &account_public_address,
      const crypto::secret_key& viewkey = crypto::secret_key(), bool create_address_file = false);
    /*!
     * \brief Restore a wallet hold by an HW.
     * \param  wallet_        Name of wallet file
     * \param  password       Password of wallet file
     * \param  device_name    name of HW to use
     */
    void restore(const std::string& wallet_, const epee::wipeable_string& password, const std::string &device_name);

    /*!
     * \brief Rewrites to the wallet file for wallet upgrade (doesn't generate key, assumes it's already there)
     * \param wallet_name Name of wallet file (should exist)
     * \param password    Password for wallet file
     */
    void rewrite(const std::string& wallet_name, const epee::wipeable_string& password);
    void write_watch_only_wallet(const std::string& wallet_name, const epee::wipeable_string& password, std::string &new_keys_filename);
    void load(const std::string& wallet, const epee::wipeable_string& password);
    void store();
    /*!
     * \brief store_to - stores wallet to another file(s), deleting old ones
     * \param path     - path to the wallet file (keys and address filenames will be generated based on this filename)
     * \param password - password to protect new wallet (TODO: probably better save the password in the wallet object?)
     */
    void store_to(const std::string &path, const epee::wipeable_string &password);

    void set_vm(boost::program_options::variables_map vm){ m_vm = std::move(vm);}

    std::string path() const;

    /*!
     * \brief verifies given password is correct for default wallet keys file
     */
    bool verify_password(const epee::wipeable_string& password) const;
    cryptonote::account_base& get_account(){return m_account;}
    const cryptonote::account_base& get_account()const{return m_account;}

    void set_refresh_from_block_height(uint64_t height) {m_refresh_from_block_height = height;}
    uint64_t get_refresh_from_block_height() const {return m_refresh_from_block_height;}

    void explicit_refresh_from_block_height(bool expl) {m_explicit_refresh_from_block_height = expl;}
    bool explicit_refresh_from_block_height() const {return m_explicit_refresh_from_block_height;}

    // upper_transaction_size_limit as defined below is set to
    // approximately 125% of the fixed minimum allowable penalty
    // free block size. TODO: fix this so that it actually takes
    // into account the current median block size rather than
    // the minimum block size.
    bool deinit();
    bool init(std::string daemon_address = "http://localhost:8080",
      boost::optional<epee::net_utils::http::login> daemon_login = boost::none, uint64_t upper_transaction_size_limit = 0, bool ssl = false);

    void stop() { m_run.store(false, std::memory_order_relaxed); }

    i_wallet_callback* callback() const { return m_callback; }
    void callback(i_wallet_callback* callback) { m_callback = callback; }

    /*!
     * \brief Checks if deterministic wallet
     */
    bool is_deterministic() const;
    bool get_seed(std::string& electrum_words, const epee::wipeable_string &passphrase = epee::wipeable_string()) const;

    /*!
    * \brief Checks if light wallet. A light wallet sends view key to a server where the blockchain is scanned.
    */
    bool light_wallet() const { return m_light_wallet; }
    void set_light_wallet(bool light_wallet) { m_light_wallet = light_wallet; }
    uint64_t get_light_wallet_scanned_block_height() const { return m_light_wallet_scanned_block_height; }
    uint64_t get_light_wallet_blockchain_height() const { return m_light_wallet_blockchain_height; }

    /*!
     * \brief Gets the seed language
     */
    const std::string &get_seed_language() const;
    /*!
     * \brief Sets the seed language
     */
    void set_seed_language(const std::string &language);

    // Subaddress scheme
    cryptonote::account_public_address get_subaddress(const cryptonote::subaddress_index& index) const;
    cryptonote::account_public_address get_address() const { return get_subaddress({0,0}); }
    crypto::public_key get_subaddress_spend_public_key(const cryptonote::subaddress_index& index) const;
    std::vector<crypto::public_key> get_subaddress_spend_public_keys(uint32_t account, uint32_t begin, uint32_t end) const;
    std::string get_subaddress_as_str(const cryptonote::subaddress_index& index) const;
    std::string get_address_as_str() const { return get_subaddress_as_str({0, 0}); }
    std::string get_integrated_address_as_str(const crypto::hash8& payment_id) const;
    void add_subaddress_account(const std::string& label);
    size_t get_num_subaddress_accounts() const { return m_subaddress_labels.size(); }
    size_t get_num_subaddresses(uint32_t index_major) const { return index_major < m_subaddress_labels.size() ? m_subaddress_labels[index_major].size() : 0; }
    void add_subaddress(uint32_t index_major, const std::string& label); // throws when index is out of bound
    void expand_subaddresses(const cryptonote::subaddress_index& index);
    std::string get_subaddress_label(const cryptonote::subaddress_index& index) const;
    void set_subaddress_label(const cryptonote::subaddress_index &index, const std::string &label);
    void set_subaddress_lookahead(size_t major, size_t minor);
    std::pair<size_t, size_t> get_subaddress_lookahead() const { return {m_subaddress_lookahead_major, m_subaddress_lookahead_minor}; }
    /*!
     * \brief Tells if the wallet file is deprecated.
     */
    bool is_deprecated() const;
    void refresh();
    void refresh(uint64_t start_height, uint64_t & blocks_fetched);
    void refresh(uint64_t start_height, uint64_t & blocks_fetched, bool& received_money);
    bool refresh(uint64_t & blocks_fetched, bool& received_money, bool& ok);

    void set_refresh_type(RefreshType refresh_type) { m_refresh_type = refresh_type; }
    RefreshType get_refresh_type() const { return m_refresh_type; }

    cryptonote::network_type nettype() const { return m_nettype; }
    bool restricted() const { return m_restricted; }
    bool watch_only() const { return m_watch_only; }
    bool multisig(bool *ready = NULL, uint32_t *threshold = NULL, uint32_t *total = NULL) const;
    bool key_on_device() const { return m_key_on_device; }

    // locked & unlocked balance of given or current subaddress account
    uint64_t balance(uint32_t subaddr_index_major) const;
    uint64_t unlocked_balance(uint32_t subaddr_index_major) const;
    uint64_t token_balance(uint32_t subaddr_index_major) const;
    uint64_t unlocked_token_balance(uint32_t subaddr_index_major) const;


    uint64_t staked_token_balance(uint32_t subaddr_index_major) const;
    std::map<uint32_t, uint64_t> staked_token_balance_per_subaddress(uint32_t subaddr_index_major) const;
    

    uint64_t unlocked_staked_token_balance(uint32_t subaddr_index_major) const;
    std::map<uint32_t, uint64_t> unlocked_staked_token_balance_per_subaddress(uint32_t subaddr_index_major) const;

    // locked & unlocked balance per subaddress of given or current subaddress account
    std::map<uint32_t, uint64_t> balance_per_subaddress(uint32_t subaddr_index_major) const;
    std::map<uint32_t, uint64_t> unlocked_balance_per_subaddress(uint32_t subaddr_index_major) const;
    // all locked & unlocked balances of all subaddress accounts
    std::map<uint32_t, uint64_t> token_balance_per_subaddress(uint32_t subaddr_index_major) const;
    std::map<uint32_t, uint64_t> unlocked_token_balance_per_subaddress(uint32_t subaddr_index_major) const;

    uint64_t staked_token_balance_all() const;
    uint64_t unlocked_staked_token_balance_all() const;

    uint64_t balance_all() const;
    uint64_t unlocked_balance_all() const;
    uint64_t token_balance_all() const;
    uint64_t unlocked_token_balance_all() const;
    template<typename T>
    void transfer(const std::vector<cryptonote::tx_destination_entry>& dsts, const size_t fake_outputs_count, const std::vector<size_t> &unused_transfers_indices, uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra, T destination_split_strategy, const tx_dust_policy& dust_policy, bool trusted_daemon);
    template<typename T>
    void transfer(const std::vector<cryptonote::tx_destination_entry>& dsts, const size_t fake_outputs_count, const std::vector<size_t> &unused_transfers_indices, uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra, T destination_split_strategy, const tx_dust_policy& dust_policy, cryptonote::transaction& tx, pending_tx& ptx, bool trusted_daemon);
    void transfer(const std::vector<cryptonote::tx_destination_entry>& dsts, const size_t fake_outputs_count, const std::vector<size_t> &unused_transfers_indices, uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra, bool trusted_daemon);
    void transfer(const std::vector<cryptonote::tx_destination_entry>& dsts, const size_t fake_outputs_count, const std::vector<size_t> &unused_transfers_indices, uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra, cryptonote::transaction& tx, pending_tx& ptx, bool trusted_daemon);
    void transfer_migration(const std::vector<cryptonote::tx_destination_entry>& dsts, crypto::hash bitcoin_transaction_hash, size_t fake_outputs_count, const std::vector<size_t> &unused_transfers_indices, uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra, cryptonote::transaction& tx, pending_tx& ptx, bool trusted_daemon);
    template<typename T, const cryptonote::tx_out_type OUT_TYPE = cryptonote::tx_out_type::out_cash>
    void transfer_selected(const std::vector<cryptonote::tx_destination_entry>& dsts, const std::vector<size_t>& selected_transfers, size_t fake_outputs_count,
      std::vector<std::vector<tools::wallet::get_outs_entry>> &outs,
      uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra, T destination_split_strategy, const tx_dust_policy& dust_policy, cryptonote::transaction& tx, pending_tx &ptx);

    template<typename T>
    void transfer_advanced(safex::command_t command_type, const std::vector<cryptonote::tx_destination_entry>& dsts, const std::vector<size_t>& selected_transfers,
                                   size_t fake_outputs_count, std::vector<std::vector<tools::wallet::get_outs_entry>> &outs,
                                   uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra, T destination_split_strategy, const tx_dust_policy& dust_policy,
                                   cryptonote::transaction& tx, pending_tx &ptx, const safex::safex_account &safexacc = safex::safex_account{});

    void commit_tx(pending_tx& ptx_vector);
    void commit_tx(std::vector<pending_tx>& ptx_vector);
    bool save_tx(const std::vector<pending_tx>& ptx_vector, const std::string &filename) const;

    // load unsigned tx from file and sign it. Takes confirmation callback as argument. Used by the cli wallet
    bool sign_tx(const std::string &unsigned_filename, const std::string &signed_filename, std::vector<wallet::pending_tx> &ptx, std::function<bool(const unsigned_tx_set&)> accept_func = NULL, bool export_raw = false);
    // sign unsigned tx. Takes unsigned_tx_set as argument. Used by GUI
    bool sign_tx(unsigned_tx_set &exported_txs, const std::string &signed_filename, std::vector<wallet::pending_tx> &ptx, bool export_raw = false);
    // load unsigned_tx_set from file.
    bool load_unsigned_tx(const std::string &unsigned_filename, unsigned_tx_set &exported_txs) const;
    bool load_tx(const std::string &signed_filename, std::vector<tools::wallet::pending_tx> &ptx, std::function<bool(const signed_tx_set&)> accept_func = NULL);
    std::vector<pending_tx> create_transactions(std::vector<cryptonote::tx_destination_entry> dsts, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra, bool trusted_daemon);
    std::vector<wallet::pending_tx> create_transactions_2(std::vector<cryptonote::tx_destination_entry> dsts, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra, uint32_t subaddr_account, std::set<uint32_t> subaddr_indices, bool trusted_daemon);     // pass subaddr_indices by value on purpose
    std::vector<wallet::pending_tx> create_transactions_token(std::vector<cryptonote::tx_destination_entry> dsts, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra, uint32_t subaddr_account, std::set<uint32_t> subaddr_indices, bool trusted_daemon);
    std::vector<wallet::pending_tx> create_transactions_all(uint64_t below, const cryptonote::account_public_address &address, bool is_subaddress, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra, uint32_t subaddr_account, std::set<uint32_t> subaddr_indices, bool trusted_daemon);
    std::vector<wallet::pending_tx> create_transactions_single(const crypto::key_image &ki, const cryptonote::account_public_address &address, bool is_subaddress, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra, bool trusted_daemon);
    std::vector<wallet::pending_tx> create_transactions_from(const cryptonote::account_public_address &address, bool is_subaddress, std::vector<size_t> unused_transfers_indices, std::vector<size_t> unused_dust_indices, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra, bool trusted_daemon);
    std::vector<wallet::pending_tx> create_transactions_token_from(const cryptonote::account_public_address &address, bool is_subaddress, std::vector<size_t> unused_token_transfers_indices, std::vector<size_t> unused_token_dust_indices,
                                                                       std::vector<size_t> unused_transfers_indices, std::vector<size_t> unused_dust_indices, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority,
                                                                       const std::vector<uint8_t> &extra, bool trusted_daemon);
    std::vector<wallet::pending_tx> create_transactions_migration(std::vector<cryptonote::tx_destination_entry> dsts, crypto::hash bitcoin_transaction_hash, uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra, bool trusted_daemon, bool mark_as_spent=false);
    std::vector<wallet::pending_tx> create_transactions_advanced(safex::command_t command_type, std::vector<cryptonote::tx_destination_entry> dsts, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra, uint32_t subaddr_account, std::set<uint32_t> subaddr_indices, bool trusted_daemon, const safex::safex_account &sfx_acc = safex::safex_account{});
    std::vector<pending_tx> create_unmixable_sweep_transactions(bool trusted_daemon, cryptonote::tx_out_type out_type);
    bool check_connection(uint32_t *version = NULL, uint32_t timeout = 200000);
    void get_transfers(wallet::transfer_container& incoming_transfers) const;
    void get_payments(const crypto::hash& payment_id, std::list<wallet::payment_details>& payments, uint64_t min_height = 0, const boost::optional<uint32_t>& subaddr_account = boost::none, const std::set<uint32_t>& subaddr_indices = {}) const;
    void get_payments(std::list<std::pair<crypto::hash,wallet::payment_details>>& payments, uint64_t min_height, uint64_t max_height = (uint64_t)-1, const boost::optional<uint32_t>& subaddr_account = boost::none, const std::set<uint32_t>& subaddr_indices = {}) const;
    void get_payments_out(std::list<std::pair<crypto::hash,wallet::confirmed_transfer_details>>& confirmed_payments,
      uint64_t min_height, uint64_t max_height = (uint64_t)-1, const boost::optional<uint32_t>& subaddr_account = boost::none, const std::set<uint32_t>& subaddr_indices = {}) const;
    void get_unconfirmed_payments_out(std::list<std::pair<crypto::hash,wallet::unconfirmed_transfer_details>>& unconfirmed_payments, const boost::optional<uint32_t>& subaddr_account = boost::none, const std::set<uint32_t>& subaddr_indices = {}) const;
    void get_unconfirmed_payments(std::list<std::pair<crypto::hash,wallet::pool_payment_details>>& unconfirmed_payments, const boost::optional<uint32_t>& subaddr_account = boost::none, const std::set<uint32_t>& subaddr_indices = {}) const;

    uint64_t get_blockchain_current_height() const { return m_local_bc_height; }
    void rescan_spent();
    void rescan_blockchain(bool refresh = true);
    bool is_transfer_unlocked(const transfer_details& td) const;
    bool is_transfer_unlocked(uint64_t unlock_time, uint64_t block_height) const;
    bool is_token_transfer_unlocked(const transfer_details& td) const;
    bool is_token_transfer_unlocked(uint64_t unlock_time, uint64_t block_height) const;
    template <class t_archive>
    inline void serialize(t_archive &a, const unsigned int ver)
    {
      uint64_t dummy_refresh_height = 0; // moved to keys file
      a & m_blockchain;
      a & m_transfers;
      a & m_account_public_address;
      a & m_key_images;
      a & m_unconfirmed_txs;
      a & m_payments;
      a & m_tx_keys;
      a & m_confirmed_txs;
      a & dummy_refresh_height;
      a & m_tx_notes;
      a & m_pub_keys;
      a & m_address_book;
      a & m_scanned_pool_txs[0];
      a & m_scanned_pool_txs[1];
      a & m_subaddresses;
      std::unordered_map<cryptonote::subaddress_index, crypto::public_key> dummy_subaddresses_inv;
      a & dummy_subaddresses_inv;
      a & m_subaddress_labels;
      a & m_additional_tx_keys;
      a & m_attributes;
      a & m_unconfirmed_payments;
      a & m_account_tags;
      a & m_ring_history_saved;

      if (ver < 1) return;

      a & m_safex_accounts;
      a & m_safex_accounts_keys;



    }

      static std::string get_default_ringdb_path()
      {
          boost::filesystem::path dir = tools::get_default_data_dir();
          // remove .bitsafex, replace with .shared-ringdb
          dir = dir.remove_filename();
          dir /= ".shared-ringdb";
          return dir.string();
      }

      // Create on-demand to prevent static initialization order fiasco issues.
      struct options {
          const command_line::arg_descriptor<std::string> daemon_address = {"daemon-address", tools::wallet::tr("Use daemon instance at <host>:<port>"), ""};
          const command_line::arg_descriptor<std::string> daemon_host = {"daemon-host", tools::wallet::tr("Use daemon instance at host <arg> instead of localhost"), ""};
          const command_line::arg_descriptor<std::string> password = {"password", tools::wallet::tr("Wallet password (escape/quote as needed)"), "", true};
          const command_line::arg_descriptor<std::string> password_file = {"password-file", tools::wallet::tr("Wallet password file"), "", true};
          const command_line::arg_descriptor<int> daemon_port = {"daemon-port", tools::wallet::tr("Use daemon instance at port <arg> instead of 18081"), 0};
          const command_line::arg_descriptor<std::string> daemon_login = {"daemon-login", tools::wallet::tr("Specify username[:password] for daemon RPC client"), "", true};
          const command_line::arg_descriptor<bool> testnet = {"testnet", tools::wallet::tr("For testnet. Daemon must also be launched with --testnet flag"), false};
          const command_line::arg_descriptor<bool> stagenet = {"stagenet", tools::wallet::tr("For stagenet. Daemon must also be launched with --stagenet flag"), false};
          const command_line::arg_descriptor<bool> restricted = {"restricted-rpc", tools::wallet::tr("Restricts to view-only commands"), false};
          const command_line::arg_descriptor<std::string, false, true> shared_ringdb_dir = {
                  "shared-ringdb-dir", tools::wallet::tr("Set shared ring database path"),
                  get_default_ringdb_path(),
                  testnet,
                  [](bool _testnet, bool defaulted, std::string val)->std::string {
                      if (_testnet)
                          return (boost::filesystem::path(val) / "testnet").string();
                      return val;
                  }
          };
      };

    /*!
     * \brief  Check if wallet keys and bin files exist
     * \param  file_path           Wallet file path
     * \param  keys_file_exists    Whether keys file exists
     * \param  wallet_file_exists  Whether bin file exists
     */
    static void wallet_exists(const std::string& file_path, bool& keys_file_exists, bool& wallet_file_exists);
    /*!
     * \brief  Check if wallet file path is valid format
     * \param  file_path      Wallet file path
     * \return                Whether path is valid format
     */
    static bool wallet_valid_path_format(const std::string& file_path);
    static bool parse_long_payment_id(const std::string& payment_id_str, crypto::hash& payment_id);
    static bool parse_short_payment_id(const std::string& payment_id_str, crypto::hash8& payment_id);
    static bool parse_payment_id(const std::string& payment_id_str, crypto::hash& payment_id);

    bool always_confirm_transfers() const { return m_always_confirm_transfers; }
    void always_confirm_transfers(bool always) { m_always_confirm_transfers = always; }
    bool print_ring_members() const { return m_print_ring_members; }
    void print_ring_members(bool value) { m_print_ring_members = value; }
    bool store_tx_info() const { return m_store_tx_info; }
    void store_tx_info(bool store) { m_store_tx_info = store; }
    uint32_t default_mixin() const { return m_default_mixin; }
    void default_mixin(uint32_t m) { m_default_mixin = m; }
    uint32_t get_default_priority() const { return m_default_priority; }
    void set_default_priority(uint32_t p) { m_default_priority = p; }
    bool auto_refresh() const { return m_auto_refresh; }
    void auto_refresh(bool r) { m_auto_refresh = r; }
    bool confirm_missing_payment_id() const { return m_confirm_missing_payment_id; }
    void confirm_missing_payment_id(bool always) { m_confirm_missing_payment_id = always; }
    bool ask_password() const { return m_ask_password; }
    void ask_password(bool always) { m_ask_password = always; }
    void set_min_output_count(uint32_t count) { m_min_output_count = count; }
    uint32_t get_min_output_count() const { return m_min_output_count; }
    void set_min_output_value(uint64_t value) { m_min_output_value = value; }
    uint64_t get_min_output_value() const { return m_min_output_value; }
    void merge_destinations(bool merge) { m_merge_destinations = merge; }
    bool merge_destinations() const { return m_merge_destinations; }
    bool confirm_backlog() const { return m_confirm_backlog; }
    void confirm_backlog(bool always) { m_confirm_backlog = always; }
    void set_confirm_backlog_threshold(uint32_t threshold) { m_confirm_backlog_threshold = threshold; };
    uint32_t get_confirm_backlog_threshold() const { return m_confirm_backlog_threshold; };
    bool confirm_export_overwrite() const { return m_confirm_export_overwrite; }
    void confirm_export_overwrite(bool always) { m_confirm_export_overwrite = always; }
    bool auto_low_priority() const { return m_auto_low_priority; }
    void auto_low_priority(bool value) { m_auto_low_priority = value; }
    bool segregate_pre_fork_outputs() const { return m_segregate_pre_fork_outputs; }
    void segregate_pre_fork_outputs(bool value) { m_segregate_pre_fork_outputs = value; }
    bool key_reuse_mitigation2() const { return m_key_reuse_mitigation2; }
    void key_reuse_mitigation2(bool value) { m_key_reuse_mitigation2 = value; }
    uint64_t segregation_height() const { return m_segregation_height; }
    void segregation_height(uint64_t height) { m_segregation_height = height; }
    bool confirm_non_default_ring_size() const { return m_confirm_non_default_ring_size; }
    void confirm_non_default_ring_size(bool always) { m_confirm_non_default_ring_size = always; }

    bool get_tx_key(const crypto::hash &txid, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys) const;
    void check_tx_key(const crypto::hash &txid, const crypto::secret_key &tx_key, const std::vector<crypto::secret_key> &additional_tx_keys, const cryptonote::account_public_address &address, uint64_t &received, uint64_t &received_token, bool &in_pool, uint64_t &confirmations);
    void check_tx_key_helper(const crypto::hash &txid, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, const cryptonote::account_public_address &address, uint64_t &received, uint64_t &received_token, bool &in_pool, uint64_t &confirmations);
    std::string get_tx_proof(const crypto::hash &txid, const cryptonote::account_public_address &address, bool is_subaddress, const std::string &message);
    bool check_tx_proof(const crypto::hash &txid, const cryptonote::account_public_address &address, bool is_subaddress, const std::string &message, const std::string &sig_str, uint64_t &received, uint64_t &received_token, bool &in_pool, uint64_t &confirmations);

    std::string get_spend_proof(const crypto::hash &txid, const std::string &message);
    bool check_spend_proof(const crypto::hash &txid, const std::string &message, const std::string &sig_str);

    /*!
     * \brief  Generates a proof that proves the reserve of unspent funds
     * \param  account_minreserve       When specified, collect outputs only belonging to the given account and prove the smallest reserve above the given amount
     *                                  When unspecified, proves for all unspent outputs across all accounts
     * \param  message                  Arbitrary challenge message to be signed together
     * \param  token                    Indicator if reserving token amount.
     * \return                          Signature string
     */
    std::string get_reserve_proof(const boost::optional<std::pair<uint32_t, uint64_t>> &account_minreserve, const std::string &message, bool token = false);
    /*!
     * \brief  Verifies a proof of reserve
     * \param  address                  The signer's address
     * \param  message                  Challenge message used for signing
     * \param  sig_str                  Signature string
     * \param  total                    [OUT] the sum of funds included in the signature
     * \param  spent                    [OUT] the sum of spent funds included in the signature
     * \param  token_total              [OUT] the sum of token funds included in the signature
     * \param  token_spent              [OUT] the sum of token spent funds included in the signature
     * \return                          true if the signature verifies correctly
     */
    bool check_reserve_proof(const cryptonote::account_public_address &address, const std::string &message, const std::string &sig_str, uint64_t &total, uint64_t &spent, uint64_t& token_total, uint64_t& token_spent);

   /*!
    * \brief GUI Address book get/store
    */
    std::vector<address_book_row> get_address_book() const { return m_address_book; }
    bool add_address_book_row(const cryptonote::account_public_address &address, const crypto::hash &payment_id, const std::string &description, bool is_subaddress);
    bool delete_address_book_row(std::size_t row_id);

    uint64_t get_num_rct_outputs();
    size_t get_num_transfer_details() const { return m_transfers.size(); }
    const transfer_details &get_transfer_details(size_t idx) const;

    void get_hard_fork_info(uint8_t version, uint64_t &earliest_height) const;
    bool use_fork_rules(uint8_t version, int64_t early_blocks = 0) const;
    int get_fee_algorithm() const;

    std::string get_wallet_file() const;
    std::string get_keys_file() const;
    std::string get_daemon_address() const;
    const boost::optional<epee::net_utils::http::login>& get_daemon_login() const { return m_daemon_login; }
    uint64_t get_daemon_blockchain_height(std::string& err) const;
    uint64_t get_daemon_blockchain_target_height(std::string& err);
   /*!
    * \brief Calculates the approximate blockchain height from current date/time.
    */
    uint64_t get_approximate_blockchain_height() const;
    uint64_t estimate_blockchain_height();
    std::vector<size_t> select_available_outputs_from_histogram(uint64_t count, bool atleast, bool unlocked, bool allow_rct, bool trusted_daemon, cryptonote::tx_out_type out_type);
    std::vector<size_t> select_available_outputs(const std::function<bool(const transfer_details &td)> &f) const;
    std::vector<size_t> select_available_unmixable_outputs(bool trusted_daemon, cryptonote::tx_out_type out_type);
    std::vector<size_t> select_available_mixable_outputs(bool trusted_daemon, cryptonote::tx_out_type out_type);

    size_t pop_best_value_from(const transfer_container &transfers, std::vector<size_t> &unused_dust_indices, const std::vector<size_t>& selected_transfers, bool smallest = false, const cryptonote::tx_out_type out_type = cryptonote::tx_out_type::out_cash) const;
    size_t pop_ideal_value_from(const transfer_container &transfers, std::vector<size_t> &unused_indices, const std::vector<size_t>& selected_transfers, const cryptonote::tx_out_type out_type, const uint64_t cash_amount, const uint64_t token_amount) const;
    size_t pop_advanced_output_from(const transfer_container &transfers, const std::vector<size_t>& selected_transfers, const std::string &acc_username,  const cryptonote::tx_out_type out_type) const;
    size_t pop_best_value(std::vector<size_t> &unused_dust_indices, const std::vector<size_t>& selected_transfers, bool smallest = false, const cryptonote::tx_out_type out_type = cryptonote::tx_out_type::out_cash) const;
    size_t pop_ideal_value(std::vector<size_t> &unused_indices, const std::vector<size_t>& selected_transfers, const cryptonote::tx_out_type out_type, const uint64_t cash_amount, const uint64_t token_amount) const;
    size_t pop_advanced_output(const std::vector<size_t>& selected_transfers, const std::vector<uint8_t> &acc_username, const cryptonote::tx_out_type out_type) const;

    void set_tx_note(const crypto::hash &txid, const std::string &note);
    std::string get_tx_note(const crypto::hash &txid) const;

    void set_description(const std::string &description);
    std::string get_description() const;

    /*!
     * \brief  Get the list of registered account tags.
     * \return first.Key=(tag's name), first.Value=(tag's label), second[i]=(i-th account's tag)
     */
    const std::pair<std::map<std::string, std::string>, std::vector<std::string>>& get_account_tags();
    /*!
     * \brief  Set a tag to the given accounts.
     * \param  account_indices  Indices of accounts.
     * \param  tag              Tag's name. If empty, the accounts become untagged.
     */
    void set_account_tag(const std::set<uint32_t> account_indices, const std::string& tag);
    /*!
     * \brief  Set the label of the given tag.
     * \param  tag            Tag's name (which must be non-empty).
     * \param  label          Tag's description.
     */
    void set_account_tag_description(const std::string& tag, const std::string& description);

    std::string sign(const std::string &data) const;
    bool verify(const std::string &data, const cryptonote::account_public_address &address, const std::string &signature) const;

    // Import/Export wallet data
    std::vector<tools::wallet::transfer_details> export_outputs() const;
    size_t import_outputs(const std::vector<tools::wallet::transfer_details> &outputs);
    payment_container export_payments() const;
    void import_payments(const payment_container &payments);
    void import_payments_out(const std::list<std::pair<crypto::hash,wallet::confirmed_transfer_details>> &confirmed_payments);
    std::tuple<size_t, crypto::hash, std::vector<crypto::hash>> export_blockchain() const;
    void import_blockchain(const std::tuple<size_t, crypto::hash, std::vector<crypto::hash>> &bc);
    bool export_key_images(const std::string &filename) const;
    std::vector<std::pair<crypto::key_image, crypto::signature>> export_key_images() const;
    uint64_t import_key_images(const std::vector<std::pair<crypto::key_image, crypto::signature>> &signed_key_images, uint64_t &spent, uint64_t &unspent, bool check_spent = true);
    uint64_t import_key_images(const std::string &filename, uint64_t &spent, uint64_t &unspent);

    void update_pool_state(bool refreshed = false);
    void remove_obsolete_pool_txs(const std::vector<crypto::hash> &tx_hashes);

    std::string encrypt(const std::string &plaintext, const crypto::secret_key &skey, bool authenticated = true) const;
    std::string encrypt_with_view_secret_key(const std::string &plaintext, bool authenticated = true) const;
    std::string decrypt(const std::string &ciphertext, const crypto::secret_key &skey, bool authenticated = true) const;
    std::string decrypt_with_view_secret_key(const std::string &ciphertext, bool authenticated = true) const;

    std::string make_uri(const std::string &address, const std::string &payment_id, uint64_t amount, uint64_t token_amount, const std::string &tx_description, const std::string &recipient_name, std::string &error) const;
    bool parse_uri(const std::string &uri, std::string &address, std::string &payment_id, uint64_t &amount, uint64_t& token_amount, std::string &tx_description, std::string &recipient_name, std::vector<std::string> &unknown_parameters, std::string &error);

    uint64_t get_blockchain_height_by_date(uint16_t year, uint8_t month, uint8_t day);    // 1<=month<=12, 1<=day<=31

    bool is_synced() const;

    std::vector<std::pair<uint64_t, uint64_t>> estimate_backlog(const std::vector<std::pair<double, double>> &fee_levels);
    std::vector<std::pair<uint64_t, uint64_t>> estimate_backlog(uint64_t min_blob_size, uint64_t max_blob_size, const std::vector<uint64_t> &fees);

    uint64_t get_fee_multiplier(uint32_t priority, int fee_algorithm = -1) const;
    uint64_t get_per_kb_fee() const;
    uint64_t adjust_mixin(uint64_t mixin) const;
    uint32_t adjust_priority(uint32_t priority);

    // Light wallet specific functions
    // fetch unspent outs from lw node and store in m_transfers
    void light_wallet_get_unspent_outs();
    // fetch txs and store in m_payments
    void light_wallet_get_address_txs();
    // get_address_info
    bool light_wallet_get_address_info(cryptonote::COMMAND_RPC_GET_ADDRESS_INFO::response &response);
    // Login. new_address is true if address hasn't been used on lw node before.
    bool light_wallet_login(bool &new_address);
    // Send an import request to lw node. returns info about import fee, address and payment_id
    bool light_wallet_import_wallet_request(cryptonote::COMMAND_RPC_IMPORT_WALLET_REQUEST::response &response);
    // get random outputs from light wallet server
    void light_wallet_get_outs(std::vector<std::vector<get_outs_entry>> &outs, const std::vector<size_t> &selected_transfers, size_t fake_outputs_count);
    // Parse rct string
    bool light_wallet_parse_rct_str(const std::string& rct_string, const crypto::public_key& tx_pub_key, uint64_t internal_output_index, rct::key& decrypted_mask, rct::key& rct_commit, bool decrypt) const;
    // check if key image is ours
    bool light_wallet_key_image_is_ours(const crypto::key_image& key_image, const crypto::public_key& tx_public_key, uint64_t out_index);

    /*
     * "attributes" are a mechanism to store an arbitrary number of string values
     * on the level of the wallet as a whole, identified by keys. Their introduction,
     * technically the unordered map m_attributes stored as part of a wallet file,
     * led to a new wallet file version, but now new singular pieces of info may be added
     * without the need for a new version.
     *
     * The first and so far only value stored as such an attribute is the description.
     * It's stored under the standard key ATTRIBUTE_DESCRIPTION (see method set_description).
     *
     * The mechanism is open to all clients and allows them to use it for storing basically any
     * single string values in a wallet. To avoid the problem that different clients possibly
     * overwrite or misunderstand each other's attributes, a two-part key scheme is
     * proposed: <client name>.<value name>
     */
    const char* const ATTRIBUTE_DESCRIPTION = "wallet.description";
    void set_attribute(const std::string &key, const std::string &value);
    std::string get_attribute(const std::string &key) const;

    template<class t_request, class t_response>
    inline bool invoke_http_json(const boost::string_ref uri, const t_request& req, t_response& res, std::chrono::milliseconds timeout = std::chrono::seconds(15), const boost::string_ref http_method = "GET")
    {
      boost::lock_guard<boost::mutex> lock(m_daemon_rpc_mutex);
      return epee::net_utils::invoke_http_json(uri, req, res, m_http_client, timeout, http_method);
    }
    template<class t_request, class t_response>
    inline bool invoke_http_bin(const boost::string_ref uri, const t_request& req, t_response& res, std::chrono::milliseconds timeout = std::chrono::seconds(15), const boost::string_ref http_method = "GET")
    {
      boost::lock_guard<boost::mutex> lock(m_daemon_rpc_mutex);
      return epee::net_utils::invoke_http_bin(uri, req, res, m_http_client, timeout, http_method);
    }
    template<class t_request, class t_response>
    inline bool invoke_http_json_rpc(const boost::string_ref uri, const std::string& method_name, const t_request& req, t_response& res, std::chrono::milliseconds timeout = std::chrono::seconds(15), const boost::string_ref http_method = "GET", const std::string& req_id = "0")
    {
      boost::lock_guard<boost::mutex> lock(m_daemon_rpc_mutex);
      return epee::net_utils::invoke_http_json_rpc(uri, method_name, req, res, m_http_client, timeout, http_method, req_id);
    }

    bool set_ring_database(const std::string &filename);
    const std::string get_ring_database() const { return m_ring_database; }
    bool get_ring(const crypto::key_image &key_image, std::vector<uint64_t> &outs);
    bool get_rings(const crypto::hash &txid, std::vector<std::pair<crypto::key_image, std::vector<uint64_t>>> &outs);
    bool set_ring(const crypto::key_image &key_image, const std::vector<uint64_t> &outs, bool relative);
    bool find_and_save_rings(bool force = true);

    bool blackball_output(const crypto::public_key &output);
    bool set_blackballed_outputs(const std::vector<crypto::public_key> &outputs, bool add = false);
    bool unblackball_output(const crypto::public_key &output);
    bool is_output_blackballed(const crypto::public_key &output) const;


    uint64_t get_interest_for_transfer(const transfer_details& td);
    uint64_t get_current_interest(std::vector<std::pair<uint64_t, uint64_t>>& interest_per_output);

    bool generate_safex_account(const std::string &username, const std::vector<uint8_t> &account_data);
    bool remove_safex_account(const std::string &username);
    bool get_safex_account(const std::string &username, safex::safex_account &acc);
    bool get_safex_account_keys(const std::string &username, safex::safex_account_keys &acckeys);
    std::vector<safex::safex_account> get_safex_accounts();
    bool recover_safex_account(const std::string &username, const crypto::secret_key &secret_key);
    bool update_safex_account_data(const std::string &username, const std::vector<uint8_t> accdata);

    bool add_safex_offer(const safex::safex_offer& offer);
    bool update_safex_offer(const safex::safex_offer& offer);
    bool close_safex_offer(const crypto::hash &offer_id);

    std::vector<safex::safex_offer> get_safex_offers();
  private:
    /*!
     * \brief  Stores wallet information to wallet file.
     * \param  keys_file_name Name of wallet file
     * \param  password       Password of wallet file
     * \param  watch_only     true to save only view key, false to save both spend and view keys
     * \return                Whether it was successful.
     */
    bool store_keys(const std::string& keys_file_name, const epee::wipeable_string& password, bool watch_only = false);

    bool store_safex_keys(const std::string& safex_keys_file_name, const epee::wipeable_string& password);
    /*!
     * \brief Load wallet information from wallet file.
     * \param keys_file_name Name of wallet file
     * \param password       Password of wallet file
     */
    bool load_keys(const std::string& keys_file_name, const epee::wipeable_string& password);
    bool load_safex_keys(const std::string& safex_keys_file_name, const epee::wipeable_string& password);
    void process_new_transaction(const crypto::hash &txid, const cryptonote::transaction& tx, const std::vector<uint64_t> &o_indices, uint64_t height, uint64_t ts, bool miner_tx, bool pool, bool double_spend_seen);
    void process_new_blockchain_entry(const cryptonote::block& b, const cryptonote::block_complete_entry& bche, const crypto::hash& bl_id, uint64_t height, const cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::block_output_indices &o_indices);
    void detach_blockchain(uint64_t height);
    void get_short_chain_history(std::list<crypto::hash>& ids) const;
    bool is_tx_spendtime_unlocked(uint64_t unlock_time, uint64_t block_height) const;
    bool clear();
    void pull_blocks(uint64_t start_height, uint64_t& blocks_start_height, const std::list<crypto::hash> &short_chain_history, std::list<cryptonote::block_complete_entry> &blocks, std::vector<cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::block_output_indices> &o_indices);
    void pull_hashes(uint64_t start_height, uint64_t& blocks_start_height, const std::list<crypto::hash> &short_chain_history, std::list<crypto::hash> &hashes);
    void fast_refresh(uint64_t stop_height, uint64_t &blocks_start_height, std::list<crypto::hash> &short_chain_history);
    void pull_next_blocks(uint64_t start_height, uint64_t &blocks_start_height, std::list<crypto::hash> &short_chain_history, const std::list<cryptonote::block_complete_entry> &prev_blocks, std::list<cryptonote::block_complete_entry> &blocks, std::vector<cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::block_output_indices> &o_indices, bool &error);
    void process_blocks(uint64_t start_height, const std::list<cryptonote::block_complete_entry> &blocks, const std::vector<cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::block_output_indices> &o_indices, uint64_t& blocks_added);
    uint64_t select_transfers(uint64_t needed_money, std::vector<size_t> unused_transfers_indices, std::vector<size_t>& selected_transfers, bool trusted_daemon) const;
    bool prepare_file_names(const std::string& file_path);
    void process_unconfirmed(const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t height);
    void process_outgoing(const crypto::hash &txid, const cryptonote::transaction &tx, uint64_t height, uint64_t ts, uint64_t spent, uint64_t tokens_spent, uint64_t received, uint64_t tokens_received, uint32_t subaddr_account, const std::set<uint32_t>& subaddr_indices);
    void add_unconfirmed_tx(const cryptonote::transaction &tx, uint64_t amount_in, uint64_t token_amount_in, const std::vector<cryptonote::tx_destination_entry> &dests, const crypto::hash &payment_id, uint64_t change_amount,
                                uint64_t token_change_amount, uint32_t subaddr_account, const std::set<uint32_t> &subaddr_indices);
    void generate_genesis(cryptonote::block& b) const;
    void check_genesis(const crypto::hash& genesis_hash) const; //throws
    bool generate_chacha_key_from_secret_keys(crypto::chacha_key &key) const;
    crypto::hash get_payment_id(const pending_tx &ptx) const;
    void check_acc_out_precomp(const cryptonote::tx_out &o, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, size_t i, tx_scan_info_t &tx_scan_info) const;
    void parse_block_round(const cryptonote::blobdata &blob, cryptonote::block &bl, crypto::hash &bl_id, bool &error) const;
    uint64_t get_upper_transaction_size_limit() const;
    std::vector<uint64_t> get_unspent_amounts_vector() const;
    uint64_t get_dynamic_per_kb_fee_estimate() const;
    float get_output_relatedness(const transfer_details &td0, const transfer_details &td1) const;
    std::vector<size_t> pick_preferred_rct_inputs(uint64_t needed_money, uint32_t subaddr_account, const std::set<uint32_t> &subaddr_indices) const;
    void set_spent(size_t idx, uint64_t height);
    void set_unspent(size_t idx);
    void get_outs(std::vector<std::vector<get_outs_entry>> &outs, const std::vector<size_t> &selected_transfers, size_t fake_outputs_count, cryptonote::tx_out_type out_type);
    bool tx_add_fake_output(std::vector<std::vector<tools::wallet::get_outs_entry>> &outs, uint64_t global_index, const crypto::public_key& tx_public_key, const rct::key& mask, uint64_t real_index, bool unlocked) const;
    crypto::public_key get_tx_pub_key_from_received_outs(const tools::wallet::transfer_details &td) const;
    bool should_pick_a_second_output(bool use_rct, size_t n_transfers, const std::vector<size_t> &unused_transfers_indices, const std::vector<size_t> &unused_dust_indices) const;
    std::vector<size_t> get_only_rct(const std::vector<size_t> &unused_dust_indices, const std::vector<size_t> &unused_transfers_indices) const;
    void scan_output(const cryptonote::transaction &tx, const crypto::public_key &tx_pub_key, size_t i, tx_scan_info_t &tx_scan_info, int &num_vouts_received,
        std::unordered_map<cryptonote::subaddress_index, uint64_t> &tx_money_got_in_outs, std::unordered_map<cryptonote::subaddress_index, uint64_t> &tx_token_got_in_outs, std::vector<size_t> &outs) const;
    void trim_hashchain();
    bool add_rings(const crypto::chacha_key &key, const cryptonote::transaction_prefix &tx);
    bool add_rings(const cryptonote::transaction_prefix &tx);
    bool remove_rings(const cryptonote::transaction_prefix &tx);
    bool get_ring(const crypto::chacha_key &key, const crypto::key_image &key_image, std::vector<uint64_t> &outs);

    bool get_output_distribution(uint64_t &start_height, std::vector<uint64_t> &distribution);

    crypto::public_key get_migration_verification_public_key() const;

    uint64_t get_segregation_fork_height() const;

    /*************************** SAFEX MARKETPLACE FUNCTIONALITIES ******************************************/
    
    std::vector<wallet::pending_tx> create_lock_transaction(std::vector<cryptonote::tx_destination_entry> dsts, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra, uint32_t subaddr_account, std::set<uint32_t> subaddr_indices, bool trusted_daemon);     // pass subaddr_indices by value on purpose
    std::vector<wallet::pending_tx> create_unlock_transaction(std::vector<cryptonote::tx_destination_entry> dsts, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra, uint32_t subaddr_account, std::set<uint32_t> subaddr_indices, bool trusted_daemon);     // pass subaddr_indices by value on purpose
    std::vector<wallet::pending_tx> create_donation_transaction(std::vector<cryptonote::tx_destination_entry> dsts, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra, uint32_t subaddr_account, std::set<uint32_t> subaddr_indices, bool trusted_daemon);     // pass subaddr_indices by value on purpose

    /********************************************************************************************************/

    cryptonote::account_base m_account;
    boost::optional<epee::net_utils::http::login> m_daemon_login;
    std::string m_daemon_address;
    std::string m_wallet_file;
    std::string m_keys_file;
    std::string m_safex_keys_file;
    epee::net_utils::http::http_simple_client m_http_client;
    hashchain m_blockchain;
    std::atomic<uint64_t> m_local_bc_height; //temporary workaround
    std::unordered_map<crypto::hash, unconfirmed_transfer_details> m_unconfirmed_txs;
    std::unordered_map<crypto::hash, confirmed_transfer_details> m_confirmed_txs;
    std::unordered_multimap<crypto::hash, pool_payment_details> m_unconfirmed_payments;
    std::unordered_map<crypto::hash, crypto::secret_key> m_tx_keys;
    cryptonote::checkpoints m_checkpoints;
    std::unordered_map<crypto::hash, std::vector<crypto::secret_key>> m_additional_tx_keys;

    transfer_container m_transfers;
    payment_container m_payments;
    std::unordered_map<crypto::key_image, size_t> m_key_images;
    std::unordered_map<crypto::public_key, size_t> m_pub_keys;
    cryptonote::account_public_address m_account_public_address;
    std::unordered_map<crypto::public_key, cryptonote::subaddress_index> m_subaddresses;
    std::vector<std::vector<std::string>> m_subaddress_labels;
    std::unordered_map<crypto::hash, std::string> m_tx_notes;
    std::unordered_map<std::string, std::string> m_attributes;
    std::vector<tools::wallet::address_book_row> m_address_book;
    std::pair<std::map<std::string, std::string>, std::vector<std::string>> m_account_tags;
    uint64_t m_upper_transaction_size_limit; //TODO: auto-calc this value or request from daemon, now use some fixed value
    const std::vector<std::vector<tools::wallet::multisig_info>> *m_multisig_rescan_info;
    const std::vector<std::vector<rct::key>> *m_multisig_rescan_k;

    std::atomic<bool> m_run;

    boost::mutex m_daemon_rpc_mutex;

    i_wallet_callback* m_callback;
    bool m_key_on_device;
    cryptonote::network_type m_nettype;
    bool m_restricted;
    std::string seed_language; /*!< Language of the mnemonics (seed). */
    bool is_old_file_format; /*!< Whether the wallet file is of an old file format */
    bool m_watch_only; /*!< no spend key */
    bool m_multisig = false; /*!< if > 1 spend secret key will not match spend public key */
    uint32_t m_multisig_threshold = 0;
    std::vector<crypto::public_key> m_multisig_signers;
    bool m_always_confirm_transfers;
    bool m_print_ring_members;
    bool m_store_tx_info; /*!< request txkey to be returned in RPC, and store in the wallet cache file */
    uint32_t m_default_mixin;
    uint32_t m_default_priority;
    RefreshType m_refresh_type;
    bool m_auto_refresh;
    uint64_t m_refresh_from_block_height;
    // If m_refresh_from_block_height is explicitly set to zero we need this to differentiate it from the case that
    // m_refresh_from_block_height was defaulted to zero.*/
    bool m_explicit_refresh_from_block_height;
    bool m_confirm_missing_payment_id;
    bool m_confirm_non_default_ring_size;
    bool m_ask_password;
    uint32_t m_min_output_count;
    uint64_t m_min_output_value;
    bool m_merge_destinations;
    bool m_confirm_backlog;
    uint32_t m_confirm_backlog_threshold;
    bool m_confirm_export_overwrite;
    bool m_auto_low_priority;
    bool m_segregate_pre_fork_outputs;
    bool m_key_reuse_mitigation2;
    uint64_t m_segregation_height;
    bool m_is_initialized;
    NodeRPCProxy m_node_rpc_proxy;
    std::unordered_set<crypto::hash> m_scanned_pool_txs[2];
    size_t m_subaddress_lookahead_major, m_subaddress_lookahead_minor;

    // Light wallet
    bool m_light_wallet; /* sends view key to daemon for scanning */
    uint64_t m_light_wallet_scanned_block_height;
    uint64_t m_light_wallet_blockchain_height;
    uint64_t m_light_wallet_per_kb_fee = FEE_PER_KB;
    bool m_light_wallet_connected;
    uint64_t m_light_wallet_balance;
    uint64_t m_light_wallet_unlocked_balance;
    uint64_t m_light_wallet_token_balance;
    uint64_t m_light_wallet_unlocked_token_balance;
    // Light wallet info needed to populate m_payment requires 2 separate api calls (get_address_txs and get_unspent_outs)
    // We save the info from the first call in m_light_wallet_address_txs for easier lookup.
    std::unordered_map<crypto::hash, address_tx> m_light_wallet_address_txs;
    // store calculated key image for faster lookup
    std::unordered_map<crypto::public_key, std::map<uint64_t, crypto::key_image> > m_key_image_cache;

    std::string m_ring_database;
    bool m_ring_history_saved;
    std::unique_ptr<ringdb> m_ringdb;

    boost::program_options::variables_map m_vm;

    std::vector<safex::safex_account> m_safex_accounts;
    std::vector<safex::safex_account_keys> m_safex_accounts_keys;

    std::vector<safex::safex_offer> m_safex_offers;
  };
}
BOOST_CLASS_VERSION(tools::wallet, 1)
BOOST_CLASS_VERSION(tools::wallet::transfer_details, 1)
BOOST_CLASS_VERSION(tools::wallet::multisig_info, 0)
BOOST_CLASS_VERSION(tools::wallet::multisig_info::LR, 0)
BOOST_CLASS_VERSION(tools::wallet::multisig_tx_set, 0)
BOOST_CLASS_VERSION(tools::wallet::payment_details, 1)
BOOST_CLASS_VERSION(tools::wallet::pool_payment_details, 0)
BOOST_CLASS_VERSION(tools::wallet::unconfirmed_transfer_details, 1)
BOOST_CLASS_VERSION(tools::wallet::confirmed_transfer_details, 1)
BOOST_CLASS_VERSION(tools::wallet::address_book_row, 0)
BOOST_CLASS_VERSION(tools::wallet::reserve_proof_entry, 0)
BOOST_CLASS_VERSION(tools::wallet::unsigned_tx_set, 0)
BOOST_CLASS_VERSION(tools::wallet::signed_tx_set, 0)
BOOST_CLASS_VERSION(tools::wallet::tx_construction_data, 0)
BOOST_CLASS_VERSION(tools::wallet::pending_tx, 0)
BOOST_CLASS_VERSION(tools::wallet::multisig_sig, 0)
BOOST_CLASS_VERSION(safex::safex_account, 0)
BOOST_CLASS_VERSION(safex::safex_account_keys, 0)
BOOST_CLASS_VERSION(safex::safex_account_key_handler, 0)

namespace boost
{
  namespace serialization
  {
    template <class Archive>
    inline typename std::enable_if<!Archive::is_loading::value, void>::type initialize_transfer_details(Archive &a, tools::wallet::transfer_details &x, const boost::serialization::version_type ver)
    {
    }
    template <class Archive>
    inline typename std::enable_if<Archive::is_loading::value, void>::type initialize_transfer_details(Archive &a, tools::wallet::transfer_details &x, const boost::serialization::version_type ver)
    {
    }

    template <class Archive>
    inline void serialize(Archive &a, tools::wallet::transfer_details &x, const boost::serialization::version_type ver)
    {
      a & x.m_block_height;
      a & x.m_global_output_index;
      a & x.m_internal_output_index;
      a & x.m_tx;
      a & x.m_spent;
      a & x.m_key_image;
      a & x.m_mask;
      a & x.m_amount;
      a & x.m_token_amount;
      a & x.m_spent_height;
      a & x.m_txid;
      a & x.m_rct;
      a & x.m_key_image_known;
      a & x.m_token_transfer;
      a & x.m_pk_index;
      a & x.m_subaddr_index;
      a & x.m_multisig_info;
      a & x.m_multisig_k;
      a & x.m_key_image_partial;

      if (ver < 1) return;

      a & x.m_output_type;
    }

    template <class Archive>
    inline void serialize(Archive &a, tools::wallet::multisig_info::LR &x, const boost::serialization::version_type ver)
    {
      a & x.m_L;
      a & x.m_R;
    }

    template <class Archive>
    inline void serialize(Archive &a, tools::wallet::multisig_info &x, const boost::serialization::version_type ver)
    {
      a & x.m_signer;
      a & x.m_LR;
      a & x.m_partial_key_images;
    }

    template <class Archive>
    inline void serialize(Archive &a, tools::wallet::multisig_tx_set &x, const boost::serialization::version_type ver)
    {
      a & x.m_ptx;
      a & x.m_signers;
    }

    template <class Archive>
    inline void serialize(Archive &a, tools::wallet::unconfirmed_transfer_details &x, const boost::serialization::version_type ver)
    {
      a & x.m_tx;
      a & x.m_amount_in;
      a & x.m_amount_out;
      a & x.m_change;
      a & x.m_token_amount_in;
      a & x.m_token_amount_out;
      a & x.m_token_change;
      a & x.m_sent_time;
      a & x.m_dests;
      a & x.m_payment_id;
      a & x.m_state;
      a & x.m_timestamp;
      a & x.m_subaddr_account;
      a & x.m_subaddr_indices;
      a & x.m_rings;
      if (ver < 1) return;
      a & x.m_output_type;
    }

    template <class Archive>
    inline void serialize(Archive &a, tools::wallet::confirmed_transfer_details &x, const boost::serialization::version_type ver)
    {
      a & x.m_amount_in;
      a & x.m_amount_out;
      a & x.m_change;
      a & x.m_token_amount_in;
      a & x.m_token_amount_out;
      a & x.m_token_change;
      a & x.m_block_height;
      a & x.m_dests;
      a & x.m_payment_id;
      a & x.m_timestamp;
      a & x.m_unlock_time;
      a & x.m_subaddr_account;
      a & x.m_subaddr_indices;
      a & x.m_rings;
      if (ver < 1) return;
      a & x.m_output_type;
    }

    template <class Archive>
    inline void serialize(Archive& a, tools::wallet::payment_details& x, const boost::serialization::version_type ver)
    {
      a & x.m_tx_hash;
      a & x.m_amount;
      a & x.m_token_amount;
      a & x.m_fee;
      a & x.m_block_height;
      a & x.m_unlock_time;
      a & x.m_timestamp;
      a & x.m_subaddr_index;
      a & x.m_token_transaction;
      if (ver < 1) return;
      a & x.m_output_type;
    }

    template <class Archive>
    inline void serialize(Archive& a, tools::wallet::pool_payment_details& x, const boost::serialization::version_type ver)
    {
      a & x.m_pd;
      a & x.m_double_spend_seen;
    }

    template <class Archive>
    inline void serialize(Archive& a, tools::wallet::address_book_row& x, const boost::serialization::version_type ver)
    {
      a & x.m_address;
      a & x.m_payment_id;
      a & x.m_description;
      a & x.m_is_subaddress;
    }

    template <class Archive>
    inline void serialize(Archive& a, tools::wallet::reserve_proof_entry& x, const boost::serialization::version_type ver)
    {
      a & x.txid;
      a & x.index_in_tx;
      a & x.shared_secret;
      a & x.key_image;
      a & x.shared_secret_sig;
      a & x.key_image_sig;
    }

    template <class Archive>
    inline void serialize(Archive &a, tools::wallet::unsigned_tx_set &x, const boost::serialization::version_type ver)
    {
      a & x.txes;
      a & x.transfers;
    }

    template <class Archive>
    inline void serialize(Archive &a, tools::wallet::signed_tx_set &x, const boost::serialization::version_type ver)
    {
      a & x.ptx;
      a & x.key_images;
    }

    template <class Archive>
    inline void serialize(Archive &a, tools::wallet::tx_construction_data &x, const boost::serialization::version_type ver)
    {
      a & x.sources;
      a & x.change_dts;
      a & x.splitted_dsts;
      a & x.extra;
      a & x.unlock_time;
      a & x.use_rct;
      a & x.dests;
      a & x.subaddr_account;
      a & x.subaddr_indices;
      a & x.selected_transfers;
    }

    template <class Archive>
    inline void serialize(Archive &a, tools::wallet::multisig_sig &x, const boost::serialization::version_type ver)
    {
      a & x.sigs;
      a & x.ignore;
      a & x.used_L;
      a & x.signing_keys;
      a & x.msout;
    }

    template <class Archive>
    inline void serialize(Archive &a, tools::wallet::pending_tx &x, const boost::serialization::version_type ver)
    {
      a & x.tx;
      a & x.dust;
      a & x.fee;
      a & x.dust_added_to_fee;
      a & x.change_dts;
      a & x.change_token_dts;
      a & x.selected_transfers;
      a & x.key_images;
      a & x.tx_key;
      a & x.additional_tx_keys;
      a & x.dests;
      a & x.construction_data;
      a & x.multisig_sigs;
    }

  }
}

namespace tools
{

  namespace detail
  {
    //----------------------------------------------------------------------------------------------------

    typedef void (*split_strategy_function)(const std::vector<cryptonote::tx_destination_entry>& dsts,
          const cryptonote::tx_destination_entry& change_dst, const cryptonote::tx_destination_entry& change_token_dst, uint64_t dust_threshold,
          std::vector<cryptonote::tx_destination_entry>& splitted_dsts, std::vector<cryptonote::tx_destination_entry> &dust_dsts);

    inline void digit_split_strategy(const std::vector<cryptonote::tx_destination_entry>& dsts,
      const cryptonote::tx_destination_entry& change_dst, const cryptonote::tx_destination_entry& change_token_dst, uint64_t dust_threshold,
      std::vector<cryptonote::tx_destination_entry>& splitted_dsts, std::vector<cryptonote::tx_destination_entry> &dust_dsts)
    {
      splitted_dsts.clear();
      dust_dsts.clear();

      for(auto& de: dsts)
      {
          if (de.output_type == cryptonote::tx_out_type::out_token)
          {
            cryptonote::decompose_amount_into_digits(de.token_amount, 0,
                                                     [&](uint64_t chunk)
                                                     { splitted_dsts.push_back(cryptonote::tx_destination_entry(chunk, de.addr, de.is_subaddress, cryptonote::tx_out_type::out_token)); },
                                                     [&](uint64_t a_dust)
                                                     { splitted_dsts.push_back(cryptonote::tx_destination_entry(a_dust, de.addr, de.is_subaddress, cryptonote::tx_out_type::out_token)); });

          }
          else if (de.output_type == cryptonote::tx_out_type::out_cash)
          {
            cryptonote::decompose_amount_into_digits(de.amount, 0,
                                                     [&](uint64_t chunk)
                                                     { splitted_dsts.push_back(cryptonote::tx_destination_entry(chunk, de.addr, de.is_subaddress, cryptonote::tx_out_type::out_cash)); },
                                                     [&](uint64_t a_dust)
                                                     { splitted_dsts.push_back(cryptonote::tx_destination_entry(a_dust, de.addr, de.is_subaddress, cryptonote::tx_out_type::out_cash)); });
          }
          else {
            //do nothing
            splitted_dsts.push_back(de);
          }

      }

      //for cash
      cryptonote::decompose_amount_into_digits(change_dst.amount, 0,
        [&](uint64_t chunk) {
          if (chunk <= dust_threshold)
            dust_dsts.push_back(cryptonote::tx_destination_entry(chunk, change_dst.addr, false, cryptonote::tx_out_type::out_cash));
          else
            splitted_dsts.push_back(cryptonote::tx_destination_entry(chunk, change_dst.addr, false, cryptonote::tx_out_type::out_cash));
        },
        [&](uint64_t a_dust) { dust_dsts.push_back(cryptonote::tx_destination_entry(a_dust, change_dst.addr, false)); } );

      //for tokens
      cryptonote::decompose_amount_into_digits(change_token_dst.token_amount, 0,
        [&](uint64_t token_chunk) {
          if (token_chunk <= dust_threshold)
            dust_dsts.push_back(cryptonote::tx_destination_entry(token_chunk, change_token_dst.addr, false, cryptonote::tx_out_type::out_token));
          else
            splitted_dsts.push_back(cryptonote::tx_destination_entry(token_chunk, change_token_dst.addr, false, cryptonote::tx_out_type::out_token));
        },
        [&](uint64_t a_token_dust) { dust_dsts.push_back(cryptonote::tx_destination_entry(a_token_dust, change_token_dst.addr, false, cryptonote::tx_out_type::out_token)); } );
    }
    //----------------------------------------------------------------------------------------------------
    inline void null_split_strategy(const std::vector<cryptonote::tx_destination_entry>& dsts,
      const cryptonote::tx_destination_entry& change_dst, const cryptonote::tx_destination_entry& change_token_dst, uint64_t dust_threshold,
      std::vector<cryptonote::tx_destination_entry>& splitted_dsts, std::vector<cryptonote::tx_destination_entry> &dust_dsts)
    {
      splitted_dsts = dsts;

      dust_dsts.clear();
      uint64_t change = change_dst.amount;
      uint64_t token_change = change_token_dst.token_amount;

      if (0 != change)
      {
        splitted_dsts.push_back(cryptonote::tx_destination_entry(change, change_dst.addr, false));
      }

      if (0 != token_change)
      {
        splitted_dsts.push_back(cryptonote::tx_destination_entry(token_change, change_token_dst.addr, false, cryptonote::tx_out_type::out_token));
      }
    }
    //----------------------------------------------------------------------------------------------------
    inline void print_source_entry(const cryptonote::tx_source_entry& src)
    {
      std::string indexes;
      std::for_each(src.outputs.begin(), src.outputs.end(), [&](const cryptonote::tx_source_entry::output_entry& s_e) { indexes += boost::to_string(s_e.first) + " "; });
      LOG_PRINT_L0("source referenced type=" << static_cast<int>(src.referenced_output_type) << ", command=" << static_cast<int>(src.command_type)
              << ", amount=" << cryptonote::print_money(src.amount) << ", token_amount=" << cryptonote::print_money(src.token_amount) <<
              ", real_output=" <<src.real_output << ", real_output_in_tx_index=" << src.real_output_in_tx_index << ", indexes: " << indexes);
    }
    //----------------------------------------------------------------------------------------------------
    inline void print_token_source_entry(const cryptonote::tx_source_entry& src)
    {
      std::string indexes;
      std::for_each(src.outputs.begin(), src.outputs.end(), [&](const cryptonote::tx_source_entry::output_entry& s_e) { indexes += boost::to_string(s_e.first) + " "; });
      LOG_PRINT_L0("token amount=" << cryptonote::print_money(src.token_amount) << ", real_output=" <<src.real_output << ", real_output_in_tx_index=" << src.real_output_in_tx_index << ", indexes: " << indexes);
    }
    //----------------------------------------------------------------------------------------------------
  }
  //----------------------------------------------------------------------------------------------------
  template<typename T>
  void wallet::transfer(const std::vector<cryptonote::tx_destination_entry>& dsts, const size_t fake_outs_count, const std::vector<size_t> &unused_transfers_indices,
    uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra, T destination_split_strategy, const tx_dust_policy& dust_policy, bool trusted_daemon)
  {
    pending_tx ptx;
    cryptonote::transaction tx;
    transfer(dsts, fake_outs_count, unused_transfers_indices, unlock_time, fee, extra, destination_split_strategy, dust_policy, tx, ptx, trusted_daemon);
  }

  template<typename T>
  void wallet::transfer(const std::vector<cryptonote::tx_destination_entry>& dsts, const size_t fake_outputs_count, const std::vector<size_t> &unused_transfers_indices,
    uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra, T destination_split_strategy, const tx_dust_policy& dust_policy, cryptonote::transaction& tx, pending_tx &ptx, bool trusted_daemon)
  {
    using namespace cryptonote;
    // throw if attempting a transaction with no destinations
    THROW_WALLET_EXCEPTION_IF(dsts.empty(), error::zero_destination);

    THROW_WALLET_EXCEPTION_IF(m_multisig, error::wallet_internal_error, "Multisig wallets cannot spend non rct outputs");

    uint64_t upper_transaction_size_limit = get_upper_transaction_size_limit();
    uint64_t needed_money = fee;

    // calculate total amount being sent to all destinations
    // throw if total amount overflows uint64_t
    for(auto& dt: dsts)
    {
      THROW_WALLET_EXCEPTION_IF(0 == dt.amount, error::zero_destination);
      needed_money += dt.amount;
      THROW_WALLET_EXCEPTION_IF(needed_money < dt.amount, error::tx_sum_overflow, dsts, fee, m_nettype);
    }

    // randomly select inputs for transaction
    // throw if requested send amount is greater than (unlocked) amount available to send
    std::vector<size_t> selected_transfers;
    uint64_t found_money = select_transfers(needed_money, unused_transfers_indices, selected_transfers, trusted_daemon);
    THROW_WALLET_EXCEPTION_IF(found_money < needed_money, error::not_enough_unlocked_cash, found_money, needed_money - fee, fee);

    uint32_t subaddr_account = m_transfers[*selected_transfers.begin()].m_subaddr_index.major;
    for (auto i = ++selected_transfers.begin(); i != selected_transfers.end(); ++i)
      THROW_WALLET_EXCEPTION_IF(subaddr_account != *i, error::wallet_internal_error, "the tx uses funds from multiple accounts");

    typedef COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::out_entry out_entry;
    typedef cryptonote::tx_source_entry::output_entry tx_output_entry;

    COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response daemon_resp = AUTO_VAL_INIT(daemon_resp);
    if(fake_outputs_count)
    {
      COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::request req = AUTO_VAL_INIT(req);
      req.outs_count = fake_outputs_count + 1;// add one to make possible (if need) to skip real output key
      for(size_t idx: selected_transfers)
      {
        const transfer_container::const_iterator it = m_transfers.begin() + idx;
        THROW_WALLET_EXCEPTION_IF(it->m_tx.vout.size() <= it->m_internal_output_index, error::wallet_internal_error,
          "m_internal_output_index = " + std::to_string(it->m_internal_output_index) +
          " is greater or equal to outputs count = " + std::to_string(it->m_tx.vout.size()));
        req.amounts.push_back(it->amount());
      }

      m_daemon_rpc_mutex.lock();
      bool r = epee::net_utils::invoke_http_bin("/getrandom_outs.bin", req, daemon_resp, m_http_client, rpc_timeout);
      m_daemon_rpc_mutex.unlock();
      THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "getrandom_outs.bin");
      THROW_WALLET_EXCEPTION_IF(daemon_resp.status == CORE_RPC_STATUS_BUSY, error::daemon_busy, "getrandom_outs.bin");
      THROW_WALLET_EXCEPTION_IF(daemon_resp.status != CORE_RPC_STATUS_OK, error::get_random_outs_error, daemon_resp.status);
      THROW_WALLET_EXCEPTION_IF(daemon_resp.outs.size() != selected_transfers.size(), error::wallet_internal_error,
        "daemon returned wrong response for getrandom_outs.bin, wrong amounts count = " +
        std::to_string(daemon_resp.outs.size()) + ", expected " +  std::to_string(selected_transfers.size()));

      std::unordered_map<uint64_t, uint64_t> scanty_outs;
      for(COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount& amount_outs: daemon_resp.outs)
      {
        if (amount_outs.outs.size() < fake_outputs_count)
        {
          scanty_outs[amount_outs.amount] = amount_outs.outs.size();
        }
      }
      THROW_WALLET_EXCEPTION_IF(!scanty_outs.empty(), error::not_enough_outs_to_mix, scanty_outs, fake_outputs_count);
    }

    //prepare inputs
    size_t i = 0;
    std::vector<cryptonote::tx_source_entry> sources;
    for(size_t idx: selected_transfers)
    {
      sources.resize(sources.size()+1);
      cryptonote::tx_source_entry& src = sources.back();
      const transfer_details& td = m_transfers[idx];
      src.amount = td.amount();
      //paste mixin transaction
      if(daemon_resp.outs.size())
      {
        daemon_resp.outs[i].outs.sort([](const out_entry& a, const out_entry& b){return a.global_amount_index < b.global_amount_index;});
        for(out_entry& daemon_oe: daemon_resp.outs[i].outs)
        {
          if(td.m_global_output_index == daemon_oe.global_amount_index)
            continue;
          tx_output_entry oe;
          oe.first = daemon_oe.global_amount_index;
          oe.second.dest = rct::pk2rct(daemon_oe.out_key);
          oe.second.mask = rct::identity();
          src.outputs.push_back(oe);
          if(src.outputs.size() >= fake_outputs_count)
            break;
        }
      }

      //paste real transaction to the random index
      auto it_to_insert = std::find_if(src.outputs.begin(), src.outputs.end(), [&](const tx_output_entry& a)
      {
        return a.first >= td.m_global_output_index;
      });
      //size_t real_index = src.outputs.size() ? (rand() % src.outputs.size() ):0;
      tx_output_entry real_oe;
      real_oe.first = td.m_global_output_index;
      real_oe.second.dest = rct::pk2rct(boost::get<txout_to_key>(td.m_tx.vout[td.m_internal_output_index].target).key);
      real_oe.second.mask = rct::identity();
      auto interted_it = src.outputs.insert(it_to_insert, real_oe);
      src.real_out_tx_key = get_tx_pub_key_from_extra(td.m_tx);
      src.real_output = interted_it - src.outputs.begin();
      src.real_output_in_tx_index = td.m_internal_output_index;
      detail::print_source_entry(src);
      ++i;
    }

    cryptonote::tx_destination_entry change_dts = AUTO_VAL_INIT(change_dts);
    cryptonote::tx_destination_entry change_token_dts = AUTO_VAL_INIT(change_token_dts);
    if (needed_money < found_money)
    {
      change_dts.addr = get_subaddress({subaddr_account, 0});
      change_dts.amount = found_money - needed_money;
    }

    std::vector<cryptonote::tx_destination_entry> splitted_dsts, dust_dsts;
    uint64_t dust = 0, token_dust = 0;
    destination_split_strategy(dsts, change_dts, change_token_dts, dust_policy.dust_threshold, splitted_dsts, dust_dsts);
    for(auto& d: dust_dsts) {
      THROW_WALLET_EXCEPTION_IF(dust_policy.dust_threshold < d.amount, error::wallet_internal_error, "invalid dust value: dust = " +
        std::to_string(d.amount) + ", dust_threshold = " + std::to_string(dust_policy.dust_threshold));
      THROW_WALLET_EXCEPTION_IF(dust_policy.dust_threshold < d.token_amount, error::wallet_internal_error, "invalid token dust value: dust = " +
          std::to_string(d.token_amount) + ", dust_threshold = " + std::to_string(dust_policy.dust_threshold));
    }
    for(auto& d: dust_dsts) {
      if ((!dust_policy.add_to_fee) && (!d.token_transaction))
        splitted_dsts.push_back(cryptonote::tx_destination_entry(d.amount, dust_policy.addr_for_dust, d.is_subaddress));

      if (d.token_transaction)
        splitted_dsts.push_back(cryptonote::tx_destination_entry(d.token_amount, dust_policy.addr_for_dust, d.is_subaddress, cryptonote::tx_out_type::out_token));

      dust += d.amount;
      token_dust += d.token_amount;
    }

    crypto::secret_key tx_key = AUTO_VAL_INIT(tx_key);
    std::vector<crypto::secret_key> additional_tx_keys;
    bool r = cryptonote::construct_tx_and_get_tx_key(m_account.get_keys(), m_subaddresses, sources, splitted_dsts, change_dts.addr, extra, tx, unlock_time, tx_key, additional_tx_keys);
    THROW_WALLET_EXCEPTION_IF(!r, error::tx_not_constructed, sources, splitted_dsts, unlock_time, m_nettype);
    THROW_WALLET_EXCEPTION_IF(upper_transaction_size_limit <= get_object_blobsize(tx), error::tx_too_big, tx, upper_transaction_size_limit);

    std::string key_images;
    bool all_are_txin_to_key = std::all_of(tx.vin.begin(), tx.vin.end(), [&](const txin_v& s_e) -> bool
    {
      CHECKED_GET_SPECIFIC_VARIANT(s_e, const txin_to_key, in, false);
      key_images += boost::to_string(in.k_image) + " ";
      return true;
    });
    THROW_WALLET_EXCEPTION_IF(!all_are_txin_to_key, error::unexpected_txin_type, tx);

    bool dust_sent_elsewhere = (dust_policy.addr_for_dust.m_view_public_key != change_dts.addr.m_view_public_key
                                || dust_policy.addr_for_dust.m_spend_public_key != change_dts.addr.m_spend_public_key);

    if (dust_policy.add_to_fee || dust_sent_elsewhere) change_dts.amount -= dust;

    ptx.key_images = key_images;
    ptx.fee = (dust_policy.add_to_fee ? fee+dust : fee);
    ptx.dust = ((dust_policy.add_to_fee || dust_sent_elsewhere) ? dust : 0);
    ptx.dust_added_to_fee = dust_policy.add_to_fee;
    ptx.tx = tx;
    ptx.change_dts = change_dts;
    ptx.selected_transfers = selected_transfers;
    ptx.tx_key = tx_key;
    ptx.additional_tx_keys = additional_tx_keys;
    ptx.dests = dsts;
    ptx.construction_data.sources = sources;
    ptx.construction_data.change_dts = change_dts;
    ptx.construction_data.splitted_dsts = splitted_dsts;
    ptx.construction_data.selected_transfers = selected_transfers;
    ptx.construction_data.extra = tx.extra;
    ptx.construction_data.unlock_time = unlock_time;
    ptx.construction_data.use_rct = false;
    ptx.construction_data.dests = dsts;
    // record which subaddress indices are being used as inputs
    ptx.construction_data.subaddr_account = subaddr_account;
    ptx.construction_data.subaddr_indices.clear();
    for (size_t idx: selected_transfers)
      ptx.construction_data.subaddr_indices.insert(m_transfers[idx].m_subaddr_index.minor);
  }

}
