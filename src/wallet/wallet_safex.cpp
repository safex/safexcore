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
    auto sfx_account = find_if(m_safex_accounts.begin(),m_safex_accounts.end(),[&username](const safex::safex_account& it){
        return it.username == username;
    });

    if(sfx_account != m_safex_accounts.end())
      return false;

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
        auto pkey = m_safex_accounts[i].pkey;
        auto safex_keys = find_if(m_safex_accounts_keys.begin(),m_safex_accounts_keys.end(),[&pkey](const safex::safex_account_keys& it){
            return it.get_public_key() == pkey;
        });

        m_safex_accounts.erase(m_safex_accounts.begin()+i);
        if(safex_keys != m_safex_accounts_keys.end())
          m_safex_accounts_keys.erase(safex_keys);
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
        m_safex_accounts[i].activated = true;
      }
    }

    return true;
  }
  //-----------------------------------------------------------------------------------------------------------------
  bool wallet::recover_safex_account(const std::string &username, const crypto::secret_key &secret_key)
  {
    safex::safex_account recover_safex_account = AUTO_VAL_INIT(recover_safex_account);

    safex::safex_account_key_handler recover_safex_account_keys;
    recover_safex_account_keys.create_from_keys(secret_key);


    recover_safex_account.username = username;
    recover_safex_account.pkey = recover_safex_account_keys.get_keys().m_public_key;
    //data will be updated during block parsing


    safex::safex_account_keys sfx_keys;
    if(!get_safex_account_keys(username,sfx_keys))
      m_safex_accounts_keys.push_back(recover_safex_account_keys.get_keys());
    if(!get_safex_account(username,recover_safex_account))
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
  uint8_t wallet::get_safex_account_status(const safex::safex_account& sfx_account) const {
    if(!sfx_account.activated)
      return 0;
    else if (!is_safex_account_unlocked(sfx_account.username))
      return 1;
    else
      return 2;

  }

  bool wallet::is_create_account_token_fee(const transfer_details& td) const
  {
      auto output_token_fee = td.get_public_key();

      return is_create_safex_account_token_fee(td.m_tx.vout, output_token_fee);
  }
//-----------------------------------------------------------------------------------------------------------------

  bool wallet::is_safex_account_unlocked(const std::string& username) const
  {
    for(const transfer_details& td: m_transfers)
    {
      if(td.m_output_type != cryptonote::tx_out_type::out_safex_account) {
        continue;
      }

      for(auto tx_output: td.m_tx.vout)
        if(tx_output.target.type() == typeid(txout_to_script) && get_tx_out_type(tx_output.target) == cryptonote::tx_out_type::out_safex_account){
            const txout_to_script &out = boost::get<txout_to_script>(tx_output.target);
            safex::create_account_data sfx_account;
            const cryptonote::blobdata accblob(std::begin(out.data), std::end(out.data));
            cryptonote::parse_and_validate_from_blob(accblob, sfx_account);
            std::string sfx_username{sfx_account.username.begin(),sfx_account.username.end()};
            //If username is not the one, we get out of the loop
            if(sfx_username != username)
              break;
            //If it is, we found it and we just check the height of the bc
            return td.m_block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE <= m_local_bc_height;
        }
    }
    return false;
  }
  //-----------------------------------------------------------------------------------------------------------------
  bool wallet::get_safex_account_keys(const std::string &username, safex::safex_account_keys &acckeys)
  {

    for (uint32_t i = 0; i < m_safex_accounts.size(); i++)
    {
      if (m_safex_accounts[i].username == username)
      {
        auto pkey = m_safex_accounts[i].pkey;
        auto safex_keys = find_if(m_safex_accounts_keys.begin(),m_safex_accounts_keys.end(),[&pkey](const safex::safex_account_keys& it){
            return it.get_public_key() == pkey;
        });
        if(safex_keys == m_safex_accounts_keys.end())
          return false;
        acckeys = *safex_keys;
        return true;
      }
    }

    return false;
  }

  bool wallet::add_safex_offer(const safex::safex_offer& offer){
      auto exists = std::find_if(m_safex_offers.begin(), m_safex_offers.end(), [offer] (const safex::safex_offer& sfx_offer) {
          return sfx_offer.offer_id == offer.offer_id;
      });
      if(exists == m_safex_offers.end())
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

    bool wallet::update_safex_offer(const safex::create_purchase_data& purchase){

      for (auto & m_safex_offer : m_safex_offers)
      {
        if (m_safex_offer.offer_id == purchase.offer_id)
        {
          m_safex_offer.quantity -= purchase.quantity;
          return true;
        }
      }

      return true;
    }

    bool wallet::safex_account_exists(const std::string &username) {

      cryptonote::COMMAND_RPC_SAFEX_ACCOUNT_INFO::request req = AUTO_VAL_INIT(req);
      cryptonote::COMMAND_RPC_SAFEX_ACCOUNT_INFO::response res = AUTO_VAL_INIT(res);

      req.username = username;

      std::string fail_msg;

      m_daemon_rpc_mutex.lock();
      bool r = net_utils::invoke_http_json("/get_safex_account_info", req, res, m_http_client, rpc_timeout);
      m_daemon_rpc_mutex.unlock();

      THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "get_safex_account_info");
      THROW_WALLET_EXCEPTION_IF(res.status != CORE_RPC_STATUS_OK && res.status != CORE_RPC_STATUS_SAFEX_ACCOUNT_DOESNT_EXIST, error::no_connection_to_daemon, "Failed to get safex offers");

      return res.status != CORE_RPC_STATUS_SAFEX_ACCOUNT_DOESNT_EXIST;
    }

  std::vector<safex::safex_offer> wallet::get_safex_offers()
  {
      cryptonote::COMMAND_RPC_GET_SAFEX_OFFERS::request req = AUTO_VAL_INIT(req);
      cryptonote::COMMAND_RPC_GET_SAFEX_OFFERS::response res = AUTO_VAL_INIT(res);

      std::vector<safex::safex_offer> offers;

      m_daemon_rpc_mutex.lock();
      bool r = net_utils::invoke_http_json("/get_safex_offers", req, res, m_http_client, rpc_timeout);
      m_daemon_rpc_mutex.unlock();

      THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "get_safex_offers");
      THROW_WALLET_EXCEPTION_IF(res.status != "OK", error::no_connection_to_daemon, "Failed to get safex offers");

      for (auto &item : res.offers) {
          if(item.height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE > m_local_bc_height)
              continue;
          crypto::hash offer_hash{};
          epee::string_tools::hex_to_pod(item.offer_id, offer_hash);
          crypto::hash price_peg_hash{};
          epee::string_tools::hex_to_pod(item.price_peg_id, price_peg_hash);
          offers.emplace_back(item.title, item.quantity, item.price, item.description, offer_hash, item.seller, item.active,item.seller_address,item.price_peg_used,price_peg_hash,item.min_sfx_price);
      }

      return offers;
  }

    std::vector<safex::safex_price_peg> wallet::get_safex_price_pegs(const std::string &currency)
    {
      cryptonote::COMMAND_RPC_GET_SAFEX_PRICE_PEGS::request req = AUTO_VAL_INIT(req);
      cryptonote::COMMAND_RPC_GET_SAFEX_PRICE_PEGS::response res = AUTO_VAL_INIT(res);

      std::vector<safex::safex_price_peg> price_pegs;

      req.currency = currency;

      m_daemon_rpc_mutex.lock();
      bool r = net_utils::invoke_http_json("/get_safex_price_pegs", req, res, m_http_client, rpc_timeout);
      m_daemon_rpc_mutex.unlock();

      THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "get_safex_price_pegs");
      THROW_WALLET_EXCEPTION_IF(res.status != "OK", error::no_connection_to_daemon, "Failed to get safex price pegs");

      for (auto &item : res.price_pegs) {
        crypto::hash hash{};
        epee::string_tools::hex_to_pod(item.price_peg_id, hash);
        price_pegs.emplace_back(item.title,item.creator,item.currency,item.description,hash,item.rate);
      }

      return price_pegs;
    }

  std::vector<safex::safex_feedback> wallet::get_safex_ratings(const crypto::hash& offer_id)
  {
      cryptonote::COMMAND_RPC_GET_SAFEX_RATINGS::request req = AUTO_VAL_INIT(req);
      cryptonote::COMMAND_RPC_GET_SAFEX_RATINGS::response res = AUTO_VAL_INIT(res);

      std::vector<safex::safex_feedback> feedbacks;

      req.offer_id = offer_id;

      m_daemon_rpc_mutex.lock();
      bool r = net_utils::invoke_http_json("/get_safex_ratings", req, res, m_http_client, rpc_timeout);
      m_daemon_rpc_mutex.unlock();

      THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "get_safex_ratings");
      THROW_WALLET_EXCEPTION_IF(res.status != CORE_RPC_STATUS_OK, error::no_connection_to_daemon, "Failed to get safex ratings");

      for (auto &item : res.ratings) {
        feedbacks.emplace_back(item.star_rating,item.comment,res.offer_id);
      }

      return feedbacks;
  }

    bool wallet::calculate_sfx_price(const safex::safex_offer& sfx_offer, uint64_t& sfx_price){

      sfx_price = sfx_offer.min_sfx_price;

      std::vector<safex::safex_price_peg> sfx_price_pegs = get_safex_price_pegs();

      if(sfx_offer.price_peg_used){
        crypto::hash price_peg_id = sfx_offer.price_peg_id;
        auto it = std::find_if(sfx_price_pegs.begin(), sfx_price_pegs.end(), [price_peg_id](const safex::safex_price_peg &sfx_price_peg) { return price_peg_id == sfx_price_peg.price_peg_id; });

        if(it == sfx_price_pegs.end())
          return false;

        std::string rate_str = print_money(it->rate);
        double rate = stod(rate_str);

        std::string price_str = print_money(sfx_offer.price);
        double price = stod(price_str);

        uint64_t pegged_price = (price*rate)*SAFEX_CASH_COIN;

        if(pegged_price > sfx_price)
          sfx_price = pegged_price;
      }

      return true;
    }

    bool wallet::add_safex_feedback_token(const safex::create_feedback_token_data& feedback_token){

      m_safex_feedback_tokens.push_back(feedback_token.offer_id);

      return true;
    }

    bool wallet::remove_safex_feedback_token(const crypto::hash& offer_id){

      for(auto it = m_safex_feedback_tokens.begin(); it!=m_safex_feedback_tokens.end();it++)
        if(*it==offer_id) {
          m_safex_feedback_tokens.erase(it);
          return true;
        }

      return true;
    }

    bool wallet::add_safex_price_peg(const safex::safex_price_peg& price_peg){

        m_safex_price_pegs.push_back(price_peg);

        return true;
    }

    bool wallet::update_safex_price_peg(const crypto::hash &price_peg_id, const uint64_t& rate) {

      for (uint32_t i = 0; i < m_safex_price_pegs.size(); i++)
      {
        if (m_safex_price_pegs[i].price_peg_id == price_peg_id)
        {
          m_safex_price_pegs[i].rate=rate;
          return true;
        }
      }

      return true;
    }

  std::vector<safex::safex_offer> wallet::get_my_safex_offers()
  {
        return m_safex_offers;
  }

    std::vector<safex::safex_price_peg> wallet::get_my_safex_price_pegs()
    {
      return m_safex_price_pegs;
    }

    std::vector<crypto::hash> wallet::get_my_safex_feedbacks_to_give()
    {
      return m_safex_feedback_tokens;
    }

  safex::safex_offer wallet::get_my_safex_offer(crypto::hash& offer_id)
  {
        for(auto it: m_safex_offers)
            if(it.offer_id == offer_id)
                return it;
        return safex::safex_offer{};
  }

  void wallet::process_advanced_output(const cryptonote::txout_to_script &txout, const cryptonote::tx_out_type& output_type){
      if (txout.output_type == static_cast<uint8_t>(tx_out_type::out_safex_account)) {
          safex::create_account_data account;
          const cryptonote::blobdata accblob(std::begin(txout.data), std::end(txout.data));
          cryptonote::parse_and_validate_from_blob(accblob, account);
          std::string accusername(begin(account.username), end(account.username));
          update_safex_account_data(accusername, account.account_data);

      } else if (txout.output_type == static_cast<uint8_t>(tx_out_type::out_safex_account_update)) {
          safex::edit_account_data account;
          const cryptonote::blobdata accblob(std::begin(txout.data), std::end(txout.data));
          cryptonote::parse_and_validate_from_blob(accblob, account);
          std::string accusername(begin(account.username), end(account.username));
          update_safex_account_data(accusername, account.account_data);

      } else if (txout.output_type == static_cast<uint8_t>(tx_out_type::out_safex_offer)){
          safex::create_offer_data offer;
          const cryptonote::blobdata offblob(std::begin(txout.data), std::end(txout.data));
          cryptonote::parse_and_validate_from_blob(offblob, offer);
          safex::safex_offer sfx_offer{std::string{offer.title.begin(),offer.title.end()},offer.quantity,offer.price,offer.description,offer.offer_id,
                                       std::string{offer.seller.begin(),offer.seller.end()},offer.active,offer.seller_address,offer.price_peg_used,offer.price_peg_id,offer.min_sfx_price};
          add_safex_offer(sfx_offer);

      } else if (txout.output_type == static_cast<uint8_t>(tx_out_type::out_safex_offer_update)){
          safex::edit_offer_data offer;
          const cryptonote::blobdata offblob(std::begin(txout.data), std::end(txout.data));
          cryptonote::parse_and_validate_from_blob(offblob, offer);
          safex::safex_offer sfx_offer{std::string{offer.title.begin(),offer.title.end()},offer.quantity,offer.price,
                                       offer.description,offer.offer_id,std::string{offer.seller.begin(),offer.seller.end()}};
          if(offer.price_peg_used)
              sfx_offer.set_price_peg(offer.price_peg_id,offer.price,offer.min_sfx_price);
          sfx_offer.active = offer.active;
         update_safex_offer(sfx_offer);

      } else if (txout.output_type == static_cast<uint8_t>(tx_out_type::out_safex_purchase)){
          safex::create_purchase_data purchase_data;
          const cryptonote::blobdata offblob(std::begin(txout.data), std::end(txout.data));
          cryptonote::parse_and_validate_from_blob(offblob, purchase_data);
          safex::safex_offer my_offer = get_my_safex_offer(purchase_data.offer_id);
          update_safex_offer(purchase_data);

      } else if (txout.output_type == static_cast<uint8_t>(tx_out_type::out_safex_feedback_token)){
          safex::create_feedback_token_data feedback_token;
          const cryptonote::blobdata offblob(std::begin(txout.data), std::end(txout.data));
          cryptonote::parse_and_validate_from_blob(offblob, feedback_token);
          add_safex_feedback_token(feedback_token);

      } else if (txout.output_type == static_cast<uint8_t>(tx_out_type::out_safex_feedback)){
          safex::create_feedback_data feedback;
          const cryptonote::blobdata offblob(std::begin(txout.data), std::end(txout.data));
          cryptonote::parse_and_validate_from_blob(offblob, feedback);
          std::string comment{feedback.comment.begin(),feedback.comment.end()};
          remove_safex_feedback_token(feedback.offer_id);

      } else if (txout.output_type == static_cast<uint8_t>(tx_out_type::out_safex_price_peg)){
          safex::create_price_peg_data price_peg;
          const cryptonote::blobdata pricepeggblob(std::begin(txout.data), std::end(txout.data));
          cryptonote::parse_and_validate_from_blob(pricepeggblob, price_peg);
          std::string creator{price_peg.creator.begin(),price_peg.creator.end()};
          std::string title{price_peg.title.begin(),price_peg.title.end()};
          std::string currency{price_peg.currency.begin(),price_peg.currency.end()};
          safex::safex_price_peg sfx_price_peg{title,creator,currency,price_peg.description,price_peg.price_peg_id,price_peg.rate};
          add_safex_price_peg(sfx_price_peg);

      } else if (txout.output_type == static_cast<uint8_t>(tx_out_type::out_safex_price_peg_update)){
          safex::update_price_peg_data price_peg;
          const cryptonote::blobdata pricepeggblob(std::begin(txout.data), std::end(txout.data));
          cryptonote::parse_and_validate_from_blob(pricepeggblob, price_peg);
          update_safex_price_peg(price_peg.price_peg_id,price_peg.rate);

      }

  }

}

