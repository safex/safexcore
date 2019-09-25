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

bool construct_block(cryptonote::block &blk, uint64_t height, const crypto::hash &prev_id, const cryptonote::account_base &miner_acc,
        uint64_t timestamp, size_t &block_size, std::list<cryptonote::transaction> tx_list);

void remove_files(std::vector<std::string> filenames, std::string prefix);

#endif //SAFEX_SAFEX_TEST_COMMON_H
