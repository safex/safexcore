#include <numeric>
#include <random>
#include <tuple>
#include <boost/format.hpp>
#include <boost/optional/optional.hpp>
#include <boost/utility/value_init.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/split.hpp>
#include "include_base_utils.h"

using namespace epee;

#include "cryptonote_config.h"
#include "wallet.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "misc_language.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "common/boost_serialization_helper.h"
#include "common/command_line.h"
#include "common/threadpool.h"
#include "profile_tools.h"
#include "crypto/crypto.h"
#include "serialization/binary_utils.h"
#include "serialization/string.h"
#include "cryptonote_basic/blobdatatype.h"
#include "mnemonics/electrum-words.h"
#include "common/i18n.h"
#include "common/util.h"
#include "common/apply_permutation.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "common/json_util.h"
#include "memwipe.h"
#include "common/base58.h"
#include "common/dns_utils.h"
#include "ringdb.h"

extern "C"
{
#include "crypto/keccak.h"
#include "crypto/crypto-ops.h"
}
using namespace std;
using namespace crypto;
using namespace cryptonote;

namespace tools
{

  uint64_t wallet::staked_token_balance(uint32_t index_major) const
  {
    uint64_t staked_token_amount = 0;
    // if(m_light_wallet)
    //     return m_light_wallet_unlocked_token_balance;
    for (const auto &i : staked_token_balance_per_subaddress(index_major))
      staked_token_amount += i.second;
    return staked_token_amount;
  }

  std::map<uint32_t, uint64_t> wallet::staked_token_balance_per_subaddress(uint32_t index_major) const
  {
    std::map<uint32_t, uint64_t> staked_token_amount_per_subaddr;
    for (const auto &td: m_transfers)
    {
      if (td.m_subaddr_index.major == index_major && !td.m_spent && td.m_output_type == tx_out_type::out_staked_token)
      {
        auto found = staked_token_amount_per_subaddr.find(td.m_subaddr_index.minor);
        if (found == staked_token_amount_per_subaddr.end())
          staked_token_amount_per_subaddr[td.m_subaddr_index.minor] = td.get_out_type() == tx_out_type::out_staked_token ? td.token_amount() : 0;
        else
          found->second += td.get_out_type() == tx_out_type::out_staked_token ? td.token_amount() : 0;
      }
    }

    return staked_token_amount_per_subaddr;
  }

  uint64_t wallet::unlocked_staked_token_balance(uint32_t index_major) const
  {
    uint64_t staked_token_amount = 0;
    // if(m_light_wallet)
    //     return m_light_wallet_unlocked_token_balance;
    for (const auto &i : unlocked_staked_token_balance_per_subaddress(index_major))
      staked_token_amount += i.second;
    return staked_token_amount;
  }

  std::map<uint32_t, uint64_t> wallet::unlocked_staked_token_balance_per_subaddress(uint32_t index_major) const
  {
    std::map<uint32_t, uint64_t> staked_token_amount_per_subaddr;
    for (const transfer_details &td: m_transfers)
    {
      if (td.m_output_type == cryptonote::tx_out_type::out_staked_token && td.m_subaddr_index.major == index_major && !td.m_spent && is_transfer_unlocked(td))
      {
        auto found = staked_token_amount_per_subaddr.find(td.m_subaddr_index.minor);
        if (found == staked_token_amount_per_subaddr.end())
          staked_token_amount_per_subaddr[td.m_subaddr_index.minor] = td.m_output_type == tx_out_type::out_staked_token ? td.token_amount() : 0;
        else
          found->second += td.m_output_type == tx_out_type::out_staked_token ? td.token_amount() : 0;
      }
    }
    return staked_token_amount_per_subaddr;
  }


  uint64_t wallet::staked_token_balance_all() const
  {
    uint64_t r = 0;
    for (uint32_t index_major = 0; index_major < get_num_subaddress_accounts(); ++index_major)
      r += staked_token_balance(index_major);
    return r;
  }

  uint64_t wallet::unlocked_staked_token_balance_all() const
  {
    uint64_t r = 0;
    for (uint32_t index_major = 0; index_major < get_num_subaddress_accounts(); ++index_major)
      r += unlocked_staked_token_balance(index_major);
    return r;
  }

//------------------------------------------------------------------------------------------------------------------

  std::vector<wallet::pending_tx> wallet::create_lock_transaction(
          std::vector<cryptonote::tx_destination_entry> dsts,
          const size_t fake_outs_count,
          const uint64_t unlock_time,
          uint32_t priority,
          const std::vector<uint8_t> &extra,
          uint32_t subaddr_account,
          std::set<uint32_t> subaddr_indices,
          bool trusted_daemon)
  {
    return std::vector<wallet::pending_tx>{};
  }

//-----------------------------------------------------------------------------------------------------------------
  uint64_t wallet::get_current_interest(std::vector<std::pair<uint64_t, uint64_t>> &interest_per_output)
  {
    uint64_t my_interest = 0;
    for (auto &transfer : m_transfers)
    {
      if (transfer.m_output_type != tx_out_type::out_staked_token || transfer.m_spent)
      {
        continue;
      }
      uint64_t interest = get_interest_for_transfer(transfer);
      my_interest += interest;

      if (interest > 0)
      {
        interest_per_output.push_back({transfer.token_amount(), interest});
      }
    }

    return my_interest;
  }

//-----------------------------------------------------------------------------------------------------------------
  uint64_t wallet::get_interest_for_transfer(const transfer_details &td)
  {
    if (td.m_spent)
    {
      LOG_PRINT_L2("Trying to get interest for spent transfer");
      return 0;
    }

    if (td.m_output_type != tx_out_type::out_staked_token)
    {
      LOG_PRINT_L2("Trying to get interest for wrong transfer type");
      return 0;
    }

    cryptonote::COMMAND_RPC_GET_INTEREST_MAP::request req = AUTO_VAL_INIT(req);
    cryptonote::COMMAND_RPC_GET_INTEREST_MAP::response res = AUTO_VAL_INIT(res);

    req.begin_interval = safex::calculate_interval_for_height(td.m_block_height, this->nettype()) + 1; //earning interest starts from next interval
    req.end_interval = safex::calculate_interval_for_height(this->get_blockchain_current_height(), this->nettype()) - 1; //finishes in previous interval

    if (req.begin_interval > req.end_interval) return 0;

    static std::map<uint64_t, uint64_t> interest_map;

    if (interest_map.find(req.begin_interval) == interest_map.end() || interest_map.find(req.end_interval) == interest_map.end())
    {

      m_daemon_rpc_mutex.lock();
      bool r = net_utils::invoke_http_json("/get_interest_map", req, res, m_http_client, rpc_timeout);
      m_daemon_rpc_mutex.unlock();

      THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "get_interest_map");
      THROW_WALLET_EXCEPTION_IF(res.status != "OK", error::no_connection_to_daemon, "Failed to get interest map");

      for (auto &item : res.interest_per_interval)
      {
        interest_map.insert({item.interval, item.cash_per_token});
      }

    }

    uint64_t interest = 0;
    for (uint64_t i = req.begin_interval; i <= req.end_interval; ++i)
    {
      LOG_PRINT_L2("Interest map for i=" << i << " is " << interest_map[i]);
      interest += interest_map[i] * (td.token_amount() / SAFEX_TOKEN);
    }

    return interest;
  }

//-----------------------------------------------------------------------------------------------------------------
  std::vector<wallet::pending_tx> wallet::create_unlock_transaction(
          std::vector<cryptonote::tx_destination_entry> dsts,
          const size_t fake_outs_count,
          const uint64_t unlock_time,
          uint32_t priority,
          const std::vector<uint8_t> &extra,
          uint32_t subaddr_account,
          std::set<uint32_t> subaddr_indices,
          bool trusted_daemon)
  {
    return std::vector<wallet::pending_tx>{};
  }

//-----------------------------------------------------------------------------------------------------------------
  std::vector<wallet::pending_tx> wallet::create_donation_transaction(
          std::vector<cryptonote::tx_destination_entry> dsts,
          const size_t fake_outs_count,
          const uint64_t unlock_time,
          uint32_t priority,
          const std::vector<uint8_t> &extra,
          uint32_t subaddr_account,
          std::set<uint32_t> subaddr_indices,
          bool trusted_daemon)
  {
    return std::vector<wallet::pending_tx>{};
  }

  //-----------------------------------------------------------------------------------------------------------------
  bool wallet::generate_safex_account(const std::string &username, const std::vector<uint8_t> &account_data)
  {
    // create a new safex account transaction
    safex::safex_account_key_handler new_safex_account_keys;
    new_safex_account_keys.generate();

    safex::safex_account new_safex_account;

    new_safex_account.username = username;
    new_safex_account.pkey = new_safex_account_keys.get_keys().m_public_key;
    new_safex_account.account_data = account_data;

    m_safex_accounts_keys.push_back(new_safex_account_keys.get_keys());
    m_safex_accounts.push_back(new_safex_account);

    return true;

  }
  //-----------------------------------------------------------------------------------------------------------------
  bool wallet::remove_safex_account(const std::string &username)
  {

    safex::safex_account new_safex_account;

    for (uint32_t i=0;i<m_safex_accounts.size();i++) {
      if (m_safex_accounts[i].username == username) {
         m_safex_accounts.erase(m_safex_accounts.begin()+i);
         m_safex_accounts_keys.erase(m_safex_accounts_keys.begin()+i);
      }
    }

    return true;

  }
  //-----------------------------------------------------------------------------------------------------------------
  bool wallet::update_safex_account_data(const std::string &username, const std::vector<uint8_t> accdata)
  {

    for (uint32_t i = 0; i < m_safex_accounts.size(); i++)
    {
      if (m_safex_accounts[i].username == username)
      {
        m_safex_accounts[i].account_data = accdata;
      }
    }

    return true;
  }
  //-----------------------------------------------------------------------------------------------------------------
  bool wallet::recover_safex_account(const std::string &username, const crypto::secret_key &secret_key)
  {
    safex::safex_account recover_safex_account = AUTO_VAL_INIT(recover_safex_account);

    if(get_safex_account(username,recover_safex_account))
      return true;

    safex::safex_account_key_handler recover_safex_account_keys;
    recover_safex_account_keys.create_from_keys(secret_key);


    recover_safex_account.username = username;
    recover_safex_account.pkey = recover_safex_account_keys.get_keys().m_public_key;
    //data will be updated during block parsing

    m_safex_accounts_keys.push_back(recover_safex_account_keys.get_keys());
    m_safex_accounts.push_back(recover_safex_account);

    return true;
  }
//-----------------------------------------------------------------------------------------------------------------
  bool wallet::get_safex_account(const std::string &username, safex::safex_account &my_account) {
    for (const safex::safex_account& acc: m_safex_accounts) {
      if (username == acc.username)
      {
        my_account = acc;
        return true;
      }
    }

    return false;
  }
//-----------------------------------------------------------------------------------------------------------------

  std::vector<safex::safex_account> wallet::get_safex_accounts()
  {
    return std::vector<safex::safex_account>(m_safex_accounts.begin(), m_safex_accounts.end());
  }
  //-----------------------------------------------------------------------------------------------------------------
  bool wallet::get_safex_account_keys(const std::string &username, safex::safex_account_keys &acckeys)
  {

    for (uint32_t i = 0; i < m_safex_accounts.size(); i++)
    {
      if (m_safex_accounts[i].username == username)
      {
        acckeys = m_safex_accounts_keys[i];
        return true;
      }
    }

    return false;
  }

  bool wallet::add_safex_offer(const safex::safex_offer& offer){

      m_safex_offers.push_back(offer);

      return true;
  }

    bool wallet::update_safex_offer(const safex::safex_offer& offer){

        for (uint32_t i = 0; i < m_safex_offers.size(); i++)
        {
            if (m_safex_offers[i].offer_id == offer.offer_id)
            {
                m_safex_offers[i]=offer;
                return true;
            }
        }

        return true;
    }

    bool wallet::close_safex_offer(const crypto::hash &offer_id){

        for (auto it = m_safex_offers.begin(); it != m_safex_offers.end(); ++it)
        {
            if (it->offer_id == offer_id)
            {
                m_safex_offers.erase(it);
                return true;
            }
        }

        return true;
  }

  std::vector<safex::safex_offer> wallet::get_safex_offers()
  {
    return std::vector<safex::safex_offer>(m_safex_offers.begin(), m_safex_offers.end());
  }

}

