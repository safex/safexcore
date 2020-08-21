//
// Created by amarko on 19.4.19..
//

#ifndef SAFEX_SAFEX_TEST_COMMON_H
#define SAFEX_SAFEX_TEST_COMMON_H

#include "blockchain_db/blockchain_db.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "safex/safex_account.h"
#include "safex/safex_offer.h"
#include "safex/safex_purchase.h"
#include "safex/safex_feedback.h"

using namespace cryptonote;

class TestDB: public BlockchainDB {
public:
  TestDB() {};
  virtual void open(const std::string& filename, const int db_flags = 0) { }
  virtual void close() {}
  virtual void sync() {}
  virtual void safesyncmode(const bool onoff) {}
  virtual void reset() {}
  virtual std::vector<std::string> get_filenames() const { return std::vector<std::string>(); }
  virtual std::string get_db_name() const { return std::string(); }
  virtual bool lock() { return true; }
  virtual void unlock() { }
  virtual bool batch_start(uint64_t batch_num_blocks=0, uint64_t batch_bytes=0) { return true; }
  virtual void batch_stop() {}
  virtual void batch_abort() {}
  virtual void set_batch_transactions(bool) {}
  virtual void block_txn_start(bool readonly=false) {}
  virtual void block_txn_stop() {}
  virtual void block_txn_abort() {}
  virtual void drop_hard_fork_info() {}
  virtual bool block_exists(const crypto::hash& h, uint64_t *height) const { return false; }
  virtual blobdata get_block_blob_from_height(const uint64_t& height) const { return cryptonote::t_serializable_object_to_blob(get_block_from_height(height)); }
  virtual blobdata get_block_blob(const crypto::hash& h) const { return blobdata(); }
  virtual bool get_tx_blob(const crypto::hash& h, cryptonote::blobdata &tx) const { return false; }
  virtual uint64_t get_block_height(const crypto::hash& h) const { return 0; }
  virtual block_header get_block_header(const crypto::hash& h) const { return block_header(); }
  virtual uint64_t get_block_timestamp(const uint64_t& height) const { return 0; }
  virtual uint64_t get_top_block_timestamp() const { return 0; }
  virtual size_t get_block_size(const uint64_t& height) const { return 128; }
  virtual difficulty_type get_block_cumulative_difficulty(const uint64_t& height) const { return 10; }
  virtual difficulty_type get_block_difficulty(const uint64_t& height) const { return 0; }
  virtual uint64_t get_block_already_generated_coins(const uint64_t& height) const { return 10000000000; }
  virtual uint64_t get_block_already_migrated_tokens(const uint64_t& height) const { return 10000000000; }
  virtual crypto::hash get_block_hash_from_height(const uint64_t& height) const { return crypto::hash(); }
  virtual std::vector<block> get_blocks_range(const uint64_t& h1, const uint64_t& h2) const { return std::vector<block>(); }
  virtual std::vector<crypto::hash> get_hashes_range(const uint64_t& h1, const uint64_t& h2) const { return std::vector<crypto::hash>(); }
  virtual crypto::hash top_block_hash() const { return crypto::hash(); }
  virtual block get_top_block() const { return block(); }
  virtual uint64_t height() const { return blocks.size(); }
  virtual bool tx_exists(const crypto::hash& h) const { return false; }
  virtual bool tx_exists(const crypto::hash& h, uint64_t& tx_index) const { return false; }
  virtual uint64_t get_tx_unlock_time(const crypto::hash& h) const { return 0; }
  virtual transaction get_tx(const crypto::hash& h) const { return transaction(); }
  virtual bool get_tx(const crypto::hash& h, transaction &tx) const { return false; }
  virtual uint64_t get_tx_count() const { return 0; }
  virtual std::vector<transaction> get_tx_list(const std::vector<crypto::hash>& hlist) const { return std::vector<transaction>(); }
  virtual uint64_t get_tx_block_height(const crypto::hash& h) const { return 0; }
  virtual uint64_t get_num_outputs(const uint64_t& amount, const tx_out_type output_type) const { return 1; }
  virtual uint64_t get_num_outputs(const tx_out_type output_type) const {return 1;}
  virtual uint64_t get_indexing_base() const { return 0; }
  virtual output_data_t get_output_key(const uint64_t& amount, const uint64_t& index, const tx_out_type output_type) const { return output_data_t(); }
  virtual output_advanced_data_t  get_output_advanced_data(const tx_out_type output_type, const uint64_t output_index) const  { return output_advanced_data_t{}; }
  virtual bool get_output_id(const tx_out_type output_type, const uint64_t output_index, uint64_t& output_id) const { return 0; }
  virtual tx_out_index get_output_tx_and_index_from_global(const uint64_t& index) const { return tx_out_index(); }
  virtual tx_out_index get_output_tx_and_index(const uint64_t& amount, const uint64_t& index, const tx_out_type output_type) const { return tx_out_index(); }
  virtual void get_output_tx_and_index(const uint64_t& amount, const std::vector<uint64_t> &offsets, std::vector<tx_out_index> &indices, const tx_out_type output_type) const {}
  virtual void get_amount_output_key(const uint64_t &amount, const std::vector<uint64_t> &offsets, std::vector<output_data_t> &outputs, const tx_out_type output_type, bool allow_partial = false) const {}
  virtual void get_advanced_output_key(const std::vector<uint64_t> &output_indexes, std::vector<output_advanced_data_t> &outputs, const tx_out_type output_type, bool allow_partial = false) const {}
  virtual bool can_thread_bulk_indices() const { return false; }
  virtual std::vector<uint64_t> get_tx_output_indices(const crypto::hash& h) const { return std::vector<uint64_t>(); }
  virtual std::vector<uint64_t> get_tx_amount_output_indices(const uint64_t tx_index) const { return std::vector<uint64_t>(); }
  virtual bool has_key_image(const crypto::key_image& img) const { return false; }
  virtual void remove_block() { blocks.pop_back(); }
  virtual uint64_t add_transaction_data(const crypto::hash& blk_hash, const transaction& tx, const crypto::hash& tx_hash) {return 0;}
  virtual void remove_transaction_data(const crypto::hash& tx_hash, const transaction& tx) {}
  virtual void remove_unstake_token(const crypto::hash& tx_hash, const transaction& tx) {}
  virtual uint64_t add_output(const crypto::hash& tx_hash, const tx_out& tx_output, const uint64_t& local_index, const uint64_t unlock_time, const rct::key *commitment) {return 0;}
  virtual void add_tx_amount_output_indices(const uint64_t tx_index, const std::vector<uint64_t>& amount_output_indices) {}
  virtual void add_spent_key(const crypto::key_image& k_image) {}
  virtual void remove_spent_key(const crypto::key_image& k_image) {}
  virtual void process_command_input(const cryptonote::txin_to_script &txin) {}
  virtual uint64_t update_staked_token_sum_for_interval(const uint64_t interval_starting_block, const int64_t delta){return 0;}
  virtual uint64_t update_staked_token_for_interval(const uint64_t interval, const uint64_t new_staked_tokens_in_interval) { return 0;}
  virtual bool remove_staked_token_for_interval(const uint64_t interval){return true;};
  virtual uint64_t update_network_fee_sum_for_interval(const uint64_t interval_starting_block, const uint64_t collected_fee){return 0;}
  virtual bool get_account_key(const safex::account_username &username, crypto::public_key &pkey) const { return true;}
  virtual bool get_account_data(const safex::account_username &username, std::vector<uint8_t> &data) const { return false;}
  virtual bool get_offer(const crypto::hash offer_id, safex::safex_offer &offer) const { return true;}
  virtual bool get_offer_seller(const crypto::hash offer_id, std::string &username) const { return true; };
  virtual bool get_offer_price(const crypto::hash offer_id, uint64_t &price) const { return true; };
  virtual bool get_offer_quantity(const crypto::hash offer_id, uint64_t &quantity) const { return true; };
  virtual bool get_offer_active_status(const crypto::hash offer_id, bool &active) const { return true; };
  virtual bool get_safex_accounts(std::vector<std::pair<std::string,std::string>> &accounts) const { return true; };
  virtual bool get_safex_offers(std::vector<safex::safex_offer> &offers) const { return true; };
  virtual bool get_safex_offer_height( crypto::hash &offer_id, uint64_t& height) const { return true; };
  virtual bool get_offer_stars_given(const crypto::hash offer_id, uint64_t &stars_received) const { return true; };
  virtual bool get_safex_feedbacks( std::vector<safex::safex_feedback> &safex_feedbacks, const crypto::hash& offer_id) const { return true; };
  virtual bool get_safex_price_pegs( std::vector<safex::safex_price_peg> &safex_price_pegs, const std::string& currency) const { return true; };
  virtual bool get_safex_price_peg( const crypto::hash& price_peg_id,safex::safex_price_peg &safex_price_peg) const { return true; };

  virtual bool get_table_sizes( std::vector<uint64_t> &table_sizes) const { return true; };


    virtual bool for_all_key_images(std::function<bool(const crypto::key_image&)>) const { return true; }
  virtual bool for_blocks_range(const uint64_t&, const uint64_t&, std::function<bool(uint64_t, const crypto::hash&, const cryptonote::block&)>) const { return true; }
  virtual bool for_all_transactions(std::function<bool(const crypto::hash&, const cryptonote::transaction&)>) const { return true; }
  virtual bool for_all_outputs(std::function<bool(uint64_t amount, const crypto::hash &tx_hash, uint64_t height, size_t tx_idx)> f, const tx_out_type output_type) const { return true; }
  virtual bool for_all_outputs(uint64_t amount, const std::function<bool(uint64_t height)> &f, const tx_out_type output_type) const { return true; }
  virtual bool for_all_advanced_outputs(std::function<bool(const crypto::hash &tx_hash, uint64_t height, uint64_t output_id, const txout_to_script& txout)> f, const tx_out_type output_type) const { return true;}
  virtual bool is_read_only() const { return false; }
  virtual std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>> get_output_histogram(const std::vector<uint64_t> &amounts, bool unlocked, uint64_t recent_cutoff, const tx_out_type output_type) const { return std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>>(); }

  virtual void add_txpool_tx(const transaction &tx, const txpool_tx_meta_t& details) {}
  virtual void update_txpool_tx(const crypto::hash &txid, const txpool_tx_meta_t& details) {}
  virtual uint64_t get_txpool_tx_count(bool include_unrelayed_txes = true) const { return 0; }
  virtual bool txpool_has_tx(const crypto::hash &txid) const { return false; }
  virtual void remove_txpool_tx(const crypto::hash& txid) {}
  virtual bool get_txpool_tx_meta(const crypto::hash& txid, txpool_tx_meta_t &meta) const { return false; }
  virtual bool get_txpool_tx_blob(const crypto::hash& txid, cryptonote::blobdata &bd) const { return false; }
  virtual cryptonote::blobdata get_txpool_tx_blob(const crypto::hash& txid) const { return ""; }
  virtual bool for_all_txpool_txes(std::function<bool(const crypto::hash&, const txpool_tx_meta_t&, const cryptonote::blobdata*)>, bool include_blob = false, bool include_unrelayed_txes = false) const { return false; }

  virtual uint64_t get_current_staked_token_sum() const { return 0;}
  virtual uint64_t get_staked_token_sum_for_interval(const uint64_t interval_starting_block) const override { return 0;};
  virtual uint64_t get_network_fee_sum_for_interval(const uint64_t interval) const override {return 0;}
  virtual std::vector<uint64_t> get_token_stake_expiry_outputs(const uint64_t block_height) const override {return std::vector<uint64_t>{};}
  virtual bool get_interval_interest_map(const uint64_t start_height, const uint64_t  end_height, safex::map_interval_interest &map) const override {return true;}
  virtual uint64_t calculate_staked_token_interest_for_output(const txin_to_script &txin, const uint64_t unlock_height) const override { return 0; }

  virtual void add_block( const block& blk
                        , const size_t& block_size
                        , const difficulty_type& cumulative_difficulty
                        , const uint64_t& coins_generated
                        , const uint64_t& tokens_migrated
                        , const crypto::hash& blk_hash
                        ) {
    blocks.push_back(blk);
  }
  virtual block get_block_from_height(const uint64_t& height) const {
    return blocks.at(height);
  }
  virtual void set_hard_fork_version(uint64_t height, uint8_t version) {
    if (versions.size() <= height)
      versions.resize(height+1);
    versions[height] = version;
  }
  virtual uint8_t get_hard_fork_version(uint64_t height) const {
    return versions.at(height);
  }
  virtual void check_hard_fork_info() {}

private:
  std::vector<block> blocks;
  std::deque<uint8_t> versions;
};


struct output_index
{
  const cryptonote::txout_target_v out;
  uint64_t amount;
  uint64_t token_amount;
  size_t blk_height; // block height
  size_t tx_no; // index of transaction in block
  size_t out_no; // index of out in transaction
  size_t idx;
  size_t advanced_output_id{0};
  bool spent;
  const cryptonote::block *p_blk;
  const cryptonote::transaction *p_tx;
  cryptonote::tx_out_type out_type{cryptonote::tx_out_type::out_invalid};

  output_index(const cryptonote::txout_target_v &_out, uint64_t _a, uint64_t _t_a, size_t _h, size_t tno, size_t ono, const cryptonote::block *_pb, const cryptonote::transaction *_pt)
          : out(_out), amount(_a), token_amount(_t_a), blk_height(_h), tx_no(tno), out_no(ono), idx(0), spent(false), p_blk(_pb), p_tx(_pt)
  {}

  output_index(const output_index &other)
          : out(other.out), amount(other.amount), token_amount(other.token_amount), blk_height(other.blk_height), tx_no(other.tx_no), out_no(other.out_no),
            idx(other.idx), spent(other.spent), p_blk(other.p_blk), p_tx(other.p_tx), advanced_output_id{other.advanced_output_id}, out_type{other.out_type}
  {}

  const std::string toString() const
  {
    std::stringstream ss;

    ss << "output_index{blk_height=" << blk_height
       << " tx_no=" << tx_no
       << " out_no=" << out_no
       << " amount=" << amount
       << " token_amount=" << token_amount
       << " idx=" << idx
       << " spent=" << spent
       << "}";

    return ss.str();
  }

  output_index &operator=(const output_index &other)
  {
    new(this) output_index(other);
    return *this;
  }
};


typedef std::unordered_map<crypto::hash, cryptonote::transaction> map_hash2tx_t;
typedef std::map<uint64_t, std::vector<size_t> > map_output_t;
typedef std::map<uint64_t, std::vector<output_index> > map_output_idx_t;


bool find_nonce_for_given_block(cryptonote::block &bl, const cryptonote::difficulty_type &diffic, uint64_t height);
bool compare_blocks(const cryptonote::block &a, const cryptonote::block &b);

cryptonote::tx_destination_entry create_tx_destination(const cryptonote::account_base &to, uint64_t amount);
cryptonote::tx_destination_entry create_token_tx_destination(const cryptonote::account_base &to, uint64_t token_amount);
cryptonote::tx_destination_entry create_locked_token_tx_destination(const cryptonote::account_base &to, uint64_t token_amount);

uint64_t get_inputs_amount(const std::vector<cryptonote::tx_source_entry> &s);
uint64_t get_inputs_token_amount(const std::vector<cryptonote::tx_source_entry> &s);


bool fill_output_entries(std::vector<output_index> &out_indices, size_t sender_out, size_t nmix, size_t &real_entry_idx, std::vector<cryptonote::tx_source_entry::output_entry> &output_entries);

bool init_output_indices(map_hash2tx_t &txmap, map_output_idx_t &outs, std::map<uint64_t, std::vector<size_t> > &outs_mine, const std::vector<cryptonote::block> &blockchain,
                         const cryptonote::account_base &from, cryptonote::tx_out_type out_type = cryptonote::tx_out_type::out_cash, const crypto::public_key& safex_account_pkey = {});

bool init_spent_output_indices(map_hash2tx_t &txmap, map_output_idx_t &outs, map_output_t &outs_mine, const std::vector<cryptonote::block> &blockchain,
                               const cryptonote::account_base &from);

bool fill_unlock_token_sources(map_hash2tx_t &txmap, std::vector<cryptonote::block> &blocks,  std::vector<cryptonote::tx_source_entry> &sources, const cryptonote::account_base &from,
        uint64_t value_amount, size_t nmix, cryptonote::tx_out_type out_type = cryptonote::tx_out_type::out_staked_token);

bool fill_migration_tx_sources(map_hash2tx_t &txmap, std::vector<cryptonote::block> &blocks, std::vector<cryptonote::tx_source_entry> &sources, const cryptonote::account_base &from,
                               uint64_t token_amount, uint64_t cash_airdrop_amount, const crypto::hash &bitcoin_transaction_hash);

void fill_migration_tx_sources_and_destinations(map_hash2tx_t &txmap,  std::vector<cryptonote::block> &blocks,  const cryptonote::account_base &from, const cryptonote::account_base &to,
                                                uint64_t token_amount, uint64_t fee, std::vector<cryptonote::tx_source_entry> &sources,
                                                std::vector<cryptonote::tx_destination_entry> &destinations, const crypto::hash &bitcoin_transaction_hash);

crypto::hash get_hash_from_string(const std::string hashstr);

bool construct_tx_to_key(map_hash2tx_t &txmap,  std::vector<cryptonote::block> &blocks, cryptonote::transaction &tx, const cryptonote::account_base &from,
        const cryptonote::account_base &to, uint64_t amount, uint64_t fee, size_t nmix);

bool construct_migration_tx_to_key(map_hash2tx_t &txmap,  std::vector<cryptonote::block> &blocks, cryptonote::transaction &tx, const cryptonote::account_base &from,
        const cryptonote::account_base &to, uint64_t token_amount, uint64_t fee, const crypto::hash &bitcoin_hash);


bool construct_token_tx_to_key(map_hash2tx_t &txmap,  std::vector<cryptonote::block> &blocks, cryptonote::transaction &tx, const cryptonote::account_base &from, const cryptonote::account_base &to,
                               uint64_t token_amount, uint64_t fee, size_t nmix);

bool construct_token_stake_transaction(map_hash2tx_t &txmap, std::vector<cryptonote::block> &blocks, cryptonote::transaction &tx, const cryptonote::account_base &from, const cryptonote::account_base &to,
                                       uint64_t token_amount, uint64_t fee, size_t nmix);

bool construct_token_unstake_transaction(map_hash2tx_t &txmap, std::vector<cryptonote::block> &blocks, cryptonote::transaction &tx,
                                         const cryptonote::account_base &from, const cryptonote::account_base &to, uint64_t token_amount, uint64_t fee, size_t nmix);

bool construct_fee_donation_transaction(map_hash2tx_t &txmap,  std::vector<cryptonote::block> &blocks, cryptonote::transaction &tx,
                                        const cryptonote::account_base &from, uint64_t cash_amount, uint64_t fee, size_t nmix);

bool construct_create_account_transaction(map_hash2tx_t &txmap, std::vector<cryptonote::block> &blocks, cryptonote::transaction &tx, const cryptonote::account_base &from, uint64_t fee,
                                          size_t nmix, const std::string &username, const crypto::public_key &pkey, const std::vector<uint8_t> &account_data, const safex::safex_account_keys &sfx_acc_keys);

bool construct_edit_account_transaction(map_hash2tx_t &txmap, std::vector<cryptonote::block> &blocks, cryptonote::transaction &tx, const cryptonote::account_base &from, uint64_t fee,
                                        size_t nmix, const std::string &username, const std::vector<uint8_t> &new_account_data, const safex::safex_account_keys &sfx_acc_keys);

bool construct_create_offer_transaction(map_hash2tx_t &txmap, std::vector<cryptonote::block> &blocks, cryptonote::transaction &tx, const cryptonote::account_base &from, uint64_t fee,
                                        size_t nmix, const crypto::public_key &pkey, const safex::safex_offer& sfx_offer, const safex::safex_account_keys &sfx_acc_keys);

bool construct_edit_offer_transaction(map_hash2tx_t &txmap, std::vector<cryptonote::block> &blocks, cryptonote::transaction &tx, const cryptonote::account_base &from, uint64_t fee,
                                      size_t nmix, const crypto::public_key &pkey, const safex::safex_offer &sfx_offer, const safex::safex_account_keys &sfx_acc_keys);

bool construct_create_purchase_transaction(map_hash2tx_t &txmap,  std::vector<cryptonote::block> &blocks, cryptonote::transaction &tx, const cryptonote::account_base &from,
                                           uint64_t fee, size_t nmix, const safex::safex_purchase &sfx_purchase, const cryptonote::account_public_address seller_address);

bool construct_create_feedback_transaction(map_hash2tx_t &txmap,  std::vector<cryptonote::block> &blocks, cryptonote::transaction &tx, const cryptonote::account_base &from,
                                           uint64_t fee, size_t nmix, const safex::safex_feedback &sfx_feedback);

bool construct_create_price_peg_transaction(map_hash2tx_t &txmap, std::vector<cryptonote::block> &blocks, cryptonote::transaction &tx, const cryptonote::account_base &from, uint64_t fee,
                                        size_t nmix, const crypto::public_key &pkey, const safex::safex_price_peg& sfx_price_peg, const safex::safex_account_keys &sfx_acc_keys);

bool construct_update_price_peg_transaction(map_hash2tx_t &txmap, std::vector<cryptonote::block> &blocks, cryptonote::transaction &tx, const cryptonote::account_base &from, uint64_t fee,
                                            size_t nmix, const crypto::public_key &pkey, const safex::safex_price_peg& sfx_price_peg, const safex::safex_account_keys &sfx_acc_keys);

bool construct_block(cryptonote::block &blk, uint64_t height, const crypto::hash &prev_id, const cryptonote::account_base &miner_acc,
        uint64_t timestamp, size_t &block_size, std::list<cryptonote::transaction> tx_list);

void remove_files(std::vector<std::string> filenames, std::string prefix);

#endif //SAFEX_SAFEX_TEST_COMMON_H
