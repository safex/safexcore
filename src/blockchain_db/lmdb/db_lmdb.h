// Copyright (c) 2018, The Safex Project
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
// Parts of this file are originally copyright (c) 2014-2018 The Monero Project
#pragma once

#include <atomic>

#include "blockchain_db/blockchain_db.h"
#include "cryptonote_basic/blobdatatype.h" // for type blobdata
#include "ringct/rctTypes.h"
#include <boost/thread/tss.hpp>

#include <lmdb.h>
#include <safex/safex_account.h>
#include <safex/safex_offer.h>
#include <safex/safex_purchase.h>
#include <safex/safex_feedback.h>
#include <safex/command.h>

#define ENABLE_AUTO_RESIZE

namespace cryptonote
{

typedef struct mdb_txn_cursors
{
  MDB_cursor *m_txc_blocks;
  MDB_cursor *m_txc_block_heights;
  MDB_cursor *m_txc_block_info;

  MDB_cursor *m_txc_output_txs;
  MDB_cursor *m_txc_output_amounts;
  MDB_cursor *m_txc_output_token_amounts;

  MDB_cursor *m_txc_txs;
  MDB_cursor *m_txc_tx_indices;
  MDB_cursor *m_txc_tx_outputs;

  MDB_cursor *m_txc_spent_keys;

  MDB_cursor *m_txc_txpool_meta;
  MDB_cursor *m_txc_txpool_blob;

  MDB_cursor *m_txc_hf_versions;

  MDB_cursor *m_txc_output_advanced;
  MDB_cursor *m_txc_output_advanced_type;
  MDB_cursor *m_txc_token_locked_sum;
  MDB_cursor *m_txc_token_locked_sum_total;
  MDB_cursor *m_txc_network_fee_sum;
  MDB_cursor *m_txc_token_lock_expiry;
  MDB_cursor *m_txc_safex_account;
  MDB_cursor *m_txc_safex_offer;
  MDB_cursor *m_txc_safex_feedback;
  MDB_cursor *m_txc_safex_price_peg;

} mdb_txn_cursors;

#define m_cur_blocks	m_cursors->m_txc_blocks
#define m_cur_block_heights	m_cursors->m_txc_block_heights
#define m_cur_block_info	m_cursors->m_txc_block_info
#define m_cur_output_txs	m_cursors->m_txc_output_txs
#define m_cur_output_amounts	m_cursors->m_txc_output_amounts
#define m_cur_output_token_amounts    m_cursors->m_txc_output_token_amounts
#define m_cur_txs	m_cursors->m_txc_txs
#define m_cur_tx_indices	m_cursors->m_txc_tx_indices
#define m_cur_tx_outputs	m_cursors->m_txc_tx_outputs
#define m_cur_spent_keys	m_cursors->m_txc_spent_keys
#define m_cur_txpool_meta	m_cursors->m_txc_txpool_meta
#define m_cur_txpool_blob	m_cursors->m_txc_txpool_blob
#define m_cur_hf_versions	m_cursors->m_txc_hf_versions
#define m_cur_output_advanced	m_cursors->m_txc_output_advanced
#define m_cur_output_advanced_type	m_cursors->m_txc_output_advanced_type
#define m_cur_token_staked_sum	m_cursors->m_txc_token_locked_sum
#define m_cur_token_staked_sum_total	m_cursors->m_txc_token_locked_sum_total
#define m_cur_network_fee_sum	m_cursors->m_txc_network_fee_sum
#define m_cur_token_lock_expiry	m_cursors->m_txc_token_lock_expiry
#define m_cur_safex_account	m_cursors->m_txc_safex_account
#define m_cur_safex_offer	m_cursors->m_txc_safex_offer
#define m_cur_safex_feedback	m_cursors->m_txc_safex_feedback
#define m_cur_safex_price_peg	m_cursors->m_txc_safex_price_peg

typedef struct mdb_rflags
{
  bool m_rf_txn;
  bool m_rf_blocks;
  bool m_rf_block_heights;
  bool m_rf_block_info;
  bool m_rf_output_txs;
  bool m_rf_output_amounts;
  bool m_rf_output_token_amounts;
  bool m_rf_txs;
  bool m_rf_tx_indices;
  bool m_rf_tx_outputs;
  bool m_rf_spent_keys;
  bool m_rf_txpool_meta;
  bool m_rf_txpool_blob;
  bool m_rf_hf_versions;
  bool m_rf_output_advanced;
  bool m_rf_output_advanced_type;
  bool m_rf_token_staked_sum;
  bool m_rf_token_staked_sum_total;
  bool m_rf_network_fee_sum;
  bool m_rf_token_lock_expiry;
  bool m_rf_safex_account;
  bool m_rf_safex_offer;
  bool m_rf_safex_feedback;
  bool m_rf_safex_price_peg;
} mdb_rflags;

typedef struct mdb_threadinfo
{
  MDB_txn *m_ti_rtxn;	// per-thread read txn
  mdb_txn_cursors m_ti_rcursors;	// per-thread read cursors
  mdb_rflags m_ti_rflags;	// per-thread read state

  ~mdb_threadinfo();
} mdb_threadinfo;

struct mdb_txn_safe
{
  mdb_txn_safe(const bool check=true);
  ~mdb_txn_safe();

  void commit(std::string message = "");

  // This should only be needed for batch transaction which must be ensured to
  // be aborted before mdb_env_close, not after. So we can't rely on
  // BlockchainLMDB destructor to call mdb_txn_safe destructor, as that's too late
  // to properly abort, since mdb_env_close would have been called earlier.
  void abort();
  void uncheck();

  operator MDB_txn*()
  {
    return m_txn;
  }

  operator MDB_txn**()
  {
    return &m_txn;
  }

  uint64_t num_active_tx() const;

  static void prevent_new_txns();
  static void wait_no_active_txns();
  static void allow_new_txns();

  mdb_threadinfo* m_tinfo;
  MDB_txn* m_txn;
  bool m_batch_txn = false;
  bool m_check;
  static std::atomic<uint64_t> num_active_txns;

  // could use a mutex here, but this should be sufficient.
  static std::atomic_flag creation_gate;
};


// If m_batch_active is set, a batch transaction exists beyond this class, such
// as a batch import with verification enabled, or possibly (later) a batch
// network sync.
//
// For some of the lookup methods, such as get_block_timestamp(), tx_exists(),
// and get_tx(), when m_batch_active is set, the lookup uses the batch
// transaction. This isn't only because the transaction is available, but it's
// necessary so that lookups include the database updates only present in the
// current batch write.
//
// A regular network sync without batch writes is expected to open a new read
// transaction, as those lookups are part of the validation done prior to the
// write for block and tx data, so no write transaction is open at the time.
class BlockchainLMDB : public BlockchainDB
{
public:
  BlockchainLMDB(bool batch_transactions=false, cryptonote::network_type nettype = cryptonote::network_type::MAINNET);
  ~BlockchainLMDB();

  virtual void open(const std::string& filename, const int mdb_flags=0) override;

  virtual void close() override;

  virtual void sync() override;

  virtual void safesyncmode(const bool onoff) override;

  virtual void reset() override;

  virtual std::vector<std::string> get_filenames() const override;

  virtual std::string get_db_name() const override;

  virtual bool lock() override;

  virtual void unlock() override;

  virtual bool block_exists(const crypto::hash& h, uint64_t *height = NULL) const override;

  virtual uint64_t get_block_height(const crypto::hash& h) const override;

  virtual block_header get_block_header(const crypto::hash& h) const override;

  virtual cryptonote::blobdata get_block_blob(const crypto::hash& h) const override;

  virtual cryptonote::blobdata get_block_blob_from_height(const uint64_t& height) const override;

  virtual uint64_t get_block_timestamp(const uint64_t& height) const override;

  virtual uint64_t get_top_block_timestamp() const override;

  virtual size_t get_block_size(const uint64_t& height) const override;

  virtual difficulty_type get_block_cumulative_difficulty(const uint64_t& height) const override;

  virtual difficulty_type get_block_difficulty(const uint64_t& height) const override;

  virtual uint64_t get_block_already_generated_coins(const uint64_t& height) const override;

  virtual uint64_t get_block_already_migrated_tokens(const uint64_t& height) const override;

  virtual crypto::hash get_block_hash_from_height(const uint64_t& height) const override;

  virtual std::vector<block> get_blocks_range(const uint64_t& h1, const uint64_t& h2) const override;

  virtual std::vector<crypto::hash> get_hashes_range(const uint64_t& h1, const uint64_t& h2) const override;

  virtual crypto::hash top_block_hash() const override;

  virtual block get_top_block() const override;

  virtual uint64_t height() const override;

  virtual bool getpwned(output_data_t& dat) const;

  virtual bool tx_exists(const crypto::hash& h) const override;
  virtual bool tx_exists(const crypto::hash& h, uint64_t& tx_index) const override;

  virtual uint64_t get_tx_unlock_time(const crypto::hash& h) const override;

  virtual bool get_tx_blob(const crypto::hash& h, cryptonote::blobdata &tx) const override;

  virtual uint64_t get_tx_count() const override;

  virtual std::vector<transaction> get_tx_list(const std::vector<crypto::hash>& hlist) const override;

  virtual uint64_t get_tx_block_height(const crypto::hash& h) const override;

  virtual uint64_t get_num_outputs(const uint64_t& amount, const tx_out_type output_type) const override;
  virtual uint64_t get_num_outputs(const tx_out_type output_type) const override;

  virtual output_data_t get_output_key(const uint64_t& amount, const uint64_t& index, const tx_out_type output_type) const override;
  virtual void get_amount_output_key(const uint64_t &amount, const std::vector<uint64_t> &offsets,
                                     std::vector<output_data_t> &outputs, const tx_out_type output_type,
                                     bool allow_partial = false) const override;

  virtual void get_advanced_output_key(const std::vector<uint64_t> &output_indexes,
                                         std::vector<output_advanced_data_t> &outputs, const tx_out_type output_type,
                                         bool allow_partial = false) const override;

  virtual output_advanced_data_t get_output_advanced_data(const tx_out_type output_type, const uint64_t output_index) const override;
  virtual bool get_output_id(const tx_out_type output_type, const uint64_t output_index, uint64_t& output_id) const override;

  virtual tx_out_index get_output_tx_and_index_from_global(const uint64_t& output_id) const override;
  virtual void get_output_tx_and_index_from_global(const std::vector<uint64_t> &global_indices,
      std::vector<tx_out_index> &tx_out_indices) const;

  virtual tx_out_index get_output_tx_and_index(const uint64_t& amount, const uint64_t& index, const tx_out_type output_type) const override;
  virtual void get_output_tx_and_index(const uint64_t& amount, const std::vector<uint64_t> &offsets, std::vector<tx_out_index> &indices, const tx_out_type output_type) const override;


  virtual std::vector<uint64_t> get_tx_amount_output_indices(const uint64_t tx_id) const override;

  virtual bool has_key_image(const crypto::key_image& img) const override;

  virtual void add_txpool_tx(const transaction &tx, const txpool_tx_meta_t& meta) override;
  virtual void update_txpool_tx(const crypto::hash &txid, const txpool_tx_meta_t& meta) override;
  virtual uint64_t get_txpool_tx_count(bool include_unrelayed_txes = true) const override;
  virtual bool txpool_has_tx(const crypto::hash &txid) const override;
  virtual void remove_txpool_tx(const crypto::hash& txid) override;
  virtual bool get_txpool_tx_meta(const crypto::hash& txid, txpool_tx_meta_t &meta) const override;
  virtual bool get_txpool_tx_blob(const crypto::hash& txid, cryptonote::blobdata &bd) const override;
  virtual cryptonote::blobdata get_txpool_tx_blob(const crypto::hash& txid) const override;
  virtual bool for_all_txpool_txes(std::function<bool(const crypto::hash&, const txpool_tx_meta_t&, const cryptonote::blobdata*)> f, bool include_blob = false, bool include_unrelayed_txes = true) const override;

  virtual bool for_all_key_images(std::function<bool(const crypto::key_image&)>) const override;
  virtual bool for_blocks_range(const uint64_t& h1, const uint64_t& h2, std::function<bool(uint64_t, const crypto::hash&, const cryptonote::block&)>) const override;
  virtual bool for_all_transactions(std::function<bool(const crypto::hash&, const cryptonote::transaction&)>) const override;
  virtual bool for_all_outputs(std::function<bool(uint64_t amount, const crypto::hash &tx_hash, uint64_t height, size_t tx_idx)> f, const tx_out_type output_type) const override;
  virtual bool for_all_outputs(uint64_t amount, const std::function<bool(uint64_t height)> &f, const tx_out_type output_type) const override;
  virtual bool for_all_advanced_outputs(std::function<bool(const crypto::hash &tx_hash, uint64_t height, uint64_t output_id, const cryptonote::txout_to_script& txout)> f, const tx_out_type output_type) const override;

  virtual uint64_t get_current_staked_token_sum() const override;
  virtual uint64_t get_staked_token_sum_for_interval(const uint64_t interval) const override;
  virtual uint64_t get_network_fee_sum_for_interval(const uint64_t interval) const override;
  virtual std::vector<uint64_t> get_token_stake_expiry_outputs(const uint64_t block_height) const override;
  virtual bool get_interval_interest_map(const uint64_t start_interval, const uint64_t  end_interval, safex::map_interval_interest &map) const override;
  virtual uint64_t calculate_staked_token_interest_for_output(const txin_to_script &txin, const uint64_t unlock_height) const override;
  virtual bool get_account_key(const safex::account_username &username, crypto::public_key &pkey) const override;
  virtual bool get_account_data(const safex::account_username &username, std::vector<uint8_t> &data) const override;
  virtual bool get_offer(const crypto::hash offer_id, safex::safex_offer &offer) const override;
  virtual bool get_offer_seller(const crypto::hash offer_id, std::string &username) const override;
  virtual bool get_offer_price(const crypto::hash offer_id, uint64_t &price) const override;
  virtual bool get_offer_quantity(const crypto::hash offer_id, uint64_t &quantity) const override;
  virtual bool get_offer_active_status(const crypto::hash offer_id, bool &active) const override;

  virtual bool get_safex_accounts( std::vector<std::pair<std::string,std::string>> &safex_accounts) const override;
  virtual bool get_safex_offers(std::vector<safex::safex_offer> &offers) const override;
  virtual bool get_safex_offer_height( crypto::hash &offer_id, uint64_t& height) const override;
  virtual bool get_offer_stars_given(const crypto::hash offer_id, uint64_t &stars_received) const override;
  virtual bool get_safex_feedbacks( std::vector<safex::safex_feedback> &safex_feedbacks, const crypto::hash& offer_id) const override;
  virtual bool get_safex_price_pegs( std::vector<safex::safex_price_peg> &safex_price_pegs, const std::string& currency) const override;
  virtual bool get_safex_price_peg( const crypto::hash& price_peg_id,safex::safex_price_peg &safex_price_peg) const override;

  virtual bool get_table_sizes( std::vector<uint64_t> &table_sizes) const override;


    virtual uint64_t add_block( const block& blk
                            , const size_t& block_size
                            , const difficulty_type& cumulative_difficulty
                            , const uint64_t& coins_generated
                            , const uint64_t& tokens_migrated
                            , const std::vector<transaction>& txs
                            ) override;

  virtual void set_batch_transactions(bool batch_transactions) override;
  virtual bool batch_start(uint64_t batch_num_blocks=0, uint64_t batch_bytes=0) override;
  virtual void batch_commit();
  virtual void batch_stop() override;
  virtual void batch_abort() override;

  virtual void block_txn_start(bool readonly) override;
  virtual void block_txn_stop() override;
  virtual void block_txn_abort() override;
  virtual bool block_rtxn_start(MDB_txn **mtxn, mdb_txn_cursors **mcur) const;
  virtual void block_rtxn_stop() const;

  virtual void pop_block(block& blk, std::vector<transaction>& txs) override;

  virtual bool can_thread_bulk_indices() const override { return true; }

  /**
   * @brief return a histogram of outputs on the blockchain
   *
   * @param amounts optional set of amounts to lookup
   * @param unlocked whether to restrict count to unlocked outputs
   * @param recent_cutoff timestamp to determine which outputs are recent
   *
   * @return a set of amount/instances
   */
  std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>> get_output_histogram(const std::vector<uint64_t> &amounts, bool unlocked, uint64_t recent_cutoff, const tx_out_type output_type) const override;

private:
  void do_resize(uint64_t size_increase=0);

  bool need_resize(uint64_t threshold_size=0) const;
  void check_and_resize_for_batch(uint64_t batch_num_blocks, uint64_t batch_bytes);
  uint64_t get_estimated_batch_size(uint64_t batch_num_blocks, uint64_t batch_bytes) const;

  virtual void add_block( const block& blk
                , const size_t& block_size
                , const difficulty_type& cumulative_difficulty
                , const uint64_t& coins_generated
                , const uint64_t& tokens_migrated
                , const crypto::hash& block_hash
                ) override;

  virtual void remove_block() override;

  virtual uint64_t add_transaction_data(const crypto::hash& blk_hash, const transaction& tx, const crypto::hash& tx_hash) override;

  virtual void remove_transaction_data(const crypto::hash& tx_hash, const transaction& tx) override;

  virtual void remove_unstake_token(const crypto::hash& tx_hash, const transaction& tx) override;

  virtual uint64_t add_output(const crypto::hash& tx_hash,
      const tx_out& tx_output,
      const uint64_t& local_index,
      const uint64_t unlock_time,
      const rct::key *commitment
      ) override;

  virtual void add_tx_amount_output_indices(const uint64_t tx_id,
      const std::vector<uint64_t>& amount_output_indices
      ) override;

  void remove_tx_outputs(const uint64_t tx_id, const transaction& tx);

  void remove_output(const uint64_t amount, const uint64_t& out_index, tx_out_type output_type);

  virtual void add_spent_key(const crypto::key_image& k_image) override;

  virtual void remove_spent_key(const crypto::key_image& k_image) override;

  /**
   * Process command input for db related changes
   *
   * @param txin advanced input with command
   */
  virtual void process_command_input(const cryptonote::txin_to_script &txin) override;

  uint64_t num_outputs() const;

  // Hard fork
  virtual void set_hard_fork_version(uint64_t height, uint8_t version) override;
  virtual uint8_t get_hard_fork_version(uint64_t height) const override;
  virtual void check_hard_fork_info() override;
  virtual void drop_hard_fork_info() override;

  /**
   * @brief convert a tx output to a blob for storage
   *
   * @param output the output to convert
   *
   * @return the resultant blob
   */
  blobdata output_to_blob(const tx_out& output) const;

  /**
   * @brief convert a tx output blob to a tx output
   *
   * @param blob the blob to convert
   *
   * @return the resultant tx output
   */
  tx_out output_from_blob(const blobdata& blob) const;

  void check_open() const;

  virtual bool is_read_only() const override;

  // fix up anything that may be wrong due to past bugs
  virtual void fixup() override;

  // migrate from older DB version to current
  void migrate(const uint32_t oldversion);

  void cleanup_batch();

  virtual bool is_valid_transaction_output_type(const txout_target_v &txout);

  uint64_t add_token_output(const tx_out& tx_output, const uint64_t unlock_time, const uint64_t num_outputs);

  uint64_t add_cash_output(const tx_out& tx_output, const uint64_t unlock_time, const uint64_t num_outputs);

  uint64_t add_advanced_output(const tx_out& tx_output, const uint64_t unlock_time, const uint64_t output_id, const tx_out_type out_type);

  void process_advanced_output(const tx_out& tx_output, const uint64_t output_id, const uint8_t output_type);

  void process_advanced_input(const cryptonote::txin_to_script &txin);


  uint64_t update_current_staked_token_sum(const uint64_t delta, int sign);
  uint64_t update_network_fee_sum_for_interval(const uint64_t interval_starting_block, const uint64_t collected_fee) override;

  /**
     * Add new account to database
     *
     * @param username safex account username
     * @param pkey safex account public key
     * @param data account desitription data
     *
     * If any of this cannot be done, it throw the corresponding subclass of DB_EXCEPTION
     *
     */
  void add_safex_account(const safex::account_username &username, const blobdata &blob);

  /**
   * Edit account data
   *
   * @param username safex account username
   * @param new_data account desitription data
   *
   * If any of this cannot be done, it throw the corresponding subclass of DB_EXCEPTION
   */
  void edit_safex_account(const safex::account_username &username, const std::vector<uint8_t> &new_data);

  /**
   * Remove safex account from database
   *
   * @param username safex account username
   * @param output_id id of the account creation output
   *
   * If any of this cannot be done, it throw the corresponding subclass of DB_EXCEPTION
  */
  void remove_safex_account(const safex::account_username &username, const uint64_t& output_id);

    /**
     * Add new offer to database
     *
     * @param offer_id safex offer id
     * @param blob offer data
     *
     * If any of this cannot be done, it throw the corresponding subclass of DB_EXCEPTION
     *
     */
    void add_safex_offer(const crypto::hash &offer_id, const blobdata &blob);


    /**
     * Edit offer in database
     *
     * @param offer_id safex offer id
     * @param blob offer data
     *
     * If any of this cannot be done, it throw the corresponding subclass of DB_EXCEPTION
     *
     */
    void edit_safex_offer(const crypto::hash &offer_id, bool active, uint64_t price, uint64_t quantity);

    /**
     * Remove safex offer from database
     *
     * @param offer_id safex offer id
     * @param output_id id of the offer creation output
     *
     * If any of this cannot be done, it throw the corresponding subclass of DB_EXCEPTION
    */
    void remove_safex_offer(const crypto::hash &offer_id, const uint64_t& output_id);

    /**
     * Remove safex offer update from database
     *
     * @param offer_id safex offer id
     * @param output_id id of the offer edit output
     *
     * If any of this cannot be done, it throw the corresponding subclass of DB_EXCEPTION
    */
    void remove_safex_offer_update(const crypto::hash &offer_id, const uint64_t& output_id);

    /**
     * Remove safex price_peg from database
     *
     * @param price_peg_id safex price_peg id
     * @param output_id id of the price peg creation output
     *
     * If any of this cannot be done, it throw the corresponding subclass of DB_EXCEPTION
    */
    void remove_safex_price_peg(const crypto::hash &price_peg_id, const uint64_t& output_id);

    /**
     * Remove safex price_peg update from database
     *
     * @param price_peg_id safex price_peg id
     * @param output_id id of the price peg update output
     *
     * If any of this cannot be done, it throw the corresponding subclass of DB_EXCEPTION
    */
    void remove_safex_price_peg_update(const crypto::hash &price_peg_id, const uint64_t& output_id);
    /**
    * Create purchase in database
    *
    * @param purchase safex purchase data
    *
    * If any of this cannot be done, it throw the corresponding subclass of DB_EXCEPTION
    *
    */
    void create_safex_purchase(const safex::safex_purchase& purchase);

    /**
     * Create price peg in database
     *
     * @param price_peg_id Unique ID of price peg
     * @param blob safex price peg data
     *
     * If any of this cannot be done, it throw the corresponding subclass of DB_EXCEPTION
     *
     */
    void add_safex_price_peg(const crypto::hash& price_peg_id, const blobdata &blob);

    /**
     * Update price peg in database
     *
     * @param price_peg_id ID of price peg to be updated
     * @param sfx_price_peg_update_result safex price peg data
     *
     * If any of this cannot be done, it throw the corresponding subclass of DB_EXCEPTION
     *
     */
    void update_safex_price_peg(const crypto::hash& price_peg_id, const safex::update_price_peg_result& sfx_price_peg_update_result);
    /**
    * Create feedback in database
    *
    * @param feedback safex feedback data
    *
    * If any of this cannot be done, it throw the corresponding subclass of DB_EXCEPTION
    *
    */
    void create_safex_feedback(const safex::safex_feedback& feedback);
    /**
    * Remove advanced output from DB
    *
    * @param out_type Type of the advanced output
    * @param Output index of the advanced output to be deleted
    *
    * If any of this cannot be done, it throw the corresponding subclass of DB_EXCEPTION
    *
    */
    void remove_advanced_output(const tx_out_type& out_type, const uint64_t& output_index);

  /**
   * Remove last safex account update from database
   *
   * @param username safex account username
   *
   * If any of this cannot be done, it throw the corresponding subclass of DB_EXCEPTION
  */
  void remove_safex_account_update(const safex::account_username &username, const uint64_t& output_id);

  /**
   * Remove last staked tokens from database
   *
   * @param token_amount amount of tokens sent
   * @param Output id of the stake token output to be deleted
   *
   * If any of this cannot be done, it throw the corresponding subclass of DB_EXCEPTION
  */
  void remove_staked_token(const uint64_t token_amount, const uint64_t& output_id);

  /**
   * Remove safex purchase advanced output and update offer quantity from database
   *
   * @param offer_id ID of purchased offer to update
   * @param quantity Quantity of product purchased
   * @param output_id Output ID of the purchase output to be deleted
   *
   * If any of this cannot be done, it throw the corresponding subclass of DB_EXCEPTION
  */
  void remove_safex_purchase(const crypto::hash& offer_id, const uint64_t quantity, const uint64_t& output_id);

    /**
     * Remove safex feedback advanced output and update offer quantity from database
     *
     * @param offer_id ID of offer where feedback is given
     * @param feedback_output_data Data of feedback to be removed
     * @param output_id Output ID of the feedback output to be deleted
     *
     * If any of this cannot be done, it throw the corresponding subclass of DB_EXCEPTION
    */
    void remove_safex_feedback(const crypto::hash& offer_id, safex::create_feedback_data& feedback_output_data, const uint64_t& output_id);

    /**
     * Remove network fee output and update total network fee from database
     *
     * @param offer_id ID of offer where feedback is given
     *
     * If any of this cannot be done, it throw the corresponding subclass of DB_EXCEPTION
    */
    void remove_network_fee_output(const uint64_t& amount, const uint64_t& output_id);

  /**
   * Restore safex account data by getting it from advanced output table
   *
   * @param sfx_account safex account that needs to be updated
   *
   * If any of this cannot be done, it throw the corresponding subclass of DB_EXCEPTION
  */
  void restore_safex_account_data(safex::create_account_result& sfx_account);

    /**
     * Restore safex offer data by getting it from advanced output table
     *
     * @param sfx_offer safex offer that needs to be updated
     *
     * If any of this cannot be done, it throw the corresponding subclass of DB_EXCEPTION
    */
    void restore_safex_offer_data(safex::create_offer_result& sfx_offer);

    /**
     * Restore safex price_peg data by getting it from advanced output table
     *
     * @param sfx_price_peg safex price_peg that needs to be updated
     *
     * If any of this cannot be done, it throw the corresponding subclass of DB_EXCEPTION
    */
    void restore_safex_price_peg_data(safex::create_price_peg_result& sfx_price_peg);

protected:

  uint64_t update_staked_token_for_interval(const uint64_t interval, const uint64_t staked_tokens) override;

  bool remove_staked_token_for_interval(const uint64_t interval) override;

private:
  MDB_env* m_env;

  MDB_dbi m_blocks;
  MDB_dbi m_block_heights;
  MDB_dbi m_block_info;

  MDB_dbi m_txs;
  MDB_dbi m_tx_indices;
  MDB_dbi m_tx_outputs;

  MDB_dbi m_output_txs;
  MDB_dbi m_output_amounts;
  MDB_dbi m_output_token_amounts;


  MDB_dbi m_spent_keys;

  MDB_dbi m_txpool_meta;
  MDB_dbi m_txpool_blob;

  MDB_dbi m_hf_starting_heights;
  MDB_dbi m_hf_versions;

  MDB_dbi m_properties;

  //Safex related
  MDB_dbi m_output_advanced;
  MDB_dbi m_output_advanced_type;
  MDB_dbi m_token_staked_sum;
  MDB_dbi m_token_staked_sum_total;
  MDB_dbi m_network_fee_sum;
  MDB_dbi m_token_lock_expiry;
  MDB_dbi m_safex_account;
  MDB_dbi m_safex_offer;
  MDB_dbi m_safex_feedback;
  MDB_dbi m_safex_price_peg;

  mutable uint64_t m_cum_size;	// used in batch size estimation
  mutable unsigned int m_cum_count;
  std::string m_folder;
  mdb_txn_safe* m_write_txn; // may point to either a short-lived txn or a batch txn
  mdb_txn_safe* m_write_batch_txn; // persist batch txn outside of BlockchainLMDB
  boost::thread::id m_writer;

  bool m_batch_transactions; // support for batch transactions
  bool m_batch_active; // whether batch transaction is in progress

  mdb_txn_cursors m_wcursors;
  mutable boost::thread_specific_ptr<mdb_threadinfo> m_tinfo;


#if defined(__arm__)
  // force a value so it can compile with 32-bit ARM
  constexpr static uint64_t DEFAULT_MAPSIZE = 1LL << 31;
#else
#if defined(ENABLE_AUTO_RESIZE)
  constexpr static uint64_t DEFAULT_MAPSIZE = 1LL << 30;
#else
  constexpr static uint64_t DEFAULT_MAPSIZE = 1LL << 33;
#endif
#endif

  constexpr static float RESIZE_PERCENT = 0.8f;
};

}  // namespace cryptonote
