#include <thread>
#include <iostream>
#include <sstream>
#include <fstream>
#include <ctype.h>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include <boost/regex.hpp>
#include "include_base_utils.h"
#include "common/i18n.h"
#include "common/command_line.h"
#include "common/util.h"
#include "common/dns_utils.h"
#include "common/base58.h"
#include "common/scoped_message_writer.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "simplewallet.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "storages/http_abstract_invoke.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "crypto/crypto.h"  // for crypto::secret_key definition
#include "mnemonics/electrum-words.h"
#include "rapidjson/document.h"
#include "common/json_util.h"
#include "ringct/rctSigs.h"
#include "wallet/wallet_args.h"
#include "version.h"
#include <stdexcept>
#include "simplewallet_common.h"

using namespace std;
using namespace epee;
using namespace cryptonote;
using boost::lexical_cast;

namespace cryptonote
{

  bool simple_wallet::create_command(CommandType command_type, const std::vector<std::string> &args_)
  {

    //  "lock_token [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <address> <token_amount> [<payment_id>] [<offer_id]"
    if (m_wallet->ask_password() && !get_and_verify_password())
    { return true; }
    if (!try_connect_to_daemon())
      return true;

    if ((command_type == CommandType::TransferLockToken) ||
            (command_type == CommandType::TransferDonation) ||
            (command_type == CommandType::TransferUnlockToken) || 
            (command_type == CommandType::TransferDemoPurchase))
    {
      //do nothing
    }
    else
    {
      fail_msg_writer() << tr("command not supported");
      return true;
    }

    LOCK_IDLE_SCOPE();

    std::vector<std::string> local_args = args_;

    // ------------------------ Mocking up offer ids for demo purposes.
    std::string offer_id;
    if(command_type == CommandType::TransferDemoPurchase) {
      if(args_.back()[0] != '#') 
      {
        fail_msg_writer() << tr("You didnt put offerid!");
        return true;
      }
      else {
        if (simple_trade_ids.find(args_.back()) != simple_trade_ids.end()) {
          offer_id = local_args.back();
          local_args.pop_back();
        }
        else {
          fail_msg_writer() << tr("There is no offer with given id!!");
          return true;
        }
      }
    }

    std::set<uint32_t> subaddr_indices;
    if (local_args.size() > 0 && local_args[0].substr(0, 6) == "index=")
    {
      if (!parse_subaddress_indices(local_args[0], subaddr_indices))
        return true;
      local_args.erase(local_args.begin());
    }

    uint32_t priority = 0;
    if (local_args.size() > 0 && parse_priority(local_args[0], priority))
      local_args.erase(local_args.begin());

    priority = m_wallet->adjust_priority(priority);

    size_t fake_outs_count = 0;
    if (local_args.size() > 0)
    {
      size_t ring_size;

      if (command_type == CommandType::TransferUnlockToken)
      {
        ring_size = 1;
        fake_outs_count = 0;
      }
      else if (!epee::string_tools::get_xtype_from_string(ring_size, local_args[0]))
      {
        fake_outs_count = m_wallet->default_mixin();
        if (fake_outs_count == 0)
          fake_outs_count = DEFAULT_MIX;
      }
      else if (ring_size == 0)
      {
        fail_msg_writer() << tr("Ring size must not be 0");
        return true;
      }
      else
      {
        fake_outs_count = ring_size - 1;
        local_args.erase(local_args.begin());
      }
    }
    uint64_t adjusted_fake_outs_count = m_wallet->adjust_mixin(fake_outs_count);
    if (adjusted_fake_outs_count > fake_outs_count)
    {
      fail_msg_writer() << (boost::format(tr("ring size %u is too small, minimum is %u")) % (fake_outs_count + 1) % (adjusted_fake_outs_count + 1)).str();
      return true;
    }

    const size_t min_args = (command_type == CommandType::TransferDonation) ? 1:2;
    if (local_args.size() < min_args)
    {
      fail_msg_writer() << tr("wrong number of arguments");
      return true;
    }

    std::string payment_id_str;
    std::vector<uint8_t> extra;
    bool payment_id_seen = false;
    bool expect_even = (min_args % 2 == 1);
    if ((expect_even ? 0 : 1) == local_args.size() % 2)
    {
      payment_id_str = local_args.back();
      local_args.pop_back();

      crypto::hash payment_id;
      bool r = tools::wallet::parse_long_payment_id(payment_id_str, payment_id);
      if (r)
      {
        std::string extra_nonce;
        set_payment_id_to_tx_extra_nonce(extra_nonce, payment_id);
        r = add_extra_nonce_to_tx_extra(extra, extra_nonce);
      }
      else
      {
        crypto::hash8 payment_id8;
        r = tools::wallet::parse_short_payment_id(payment_id_str, payment_id8);
        if (r)
        {
          std::string extra_nonce;
          set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id8);
          r = add_extra_nonce_to_tx_extra(extra, extra_nonce);
        }
      }

      if (!r)
      {
        fail_msg_writer() << tr("payment id has invalid format, expected 16 or 64 character hex string: ") << payment_id_str;
        return true;
      }
      payment_id_seen = true;
    }
    uint64_t safex_network_fee = 0;
    
    vector<cryptonote::tx_destination_entry> dsts;
    for (size_t i = 0; i < local_args.size(); i += 2)
    {
      cryptonote::address_parse_info info = AUTO_VAL_INIT(info);
      cryptonote::tx_destination_entry de = AUTO_VAL_INIT(de);

      if (command_type == CommandType::TransferDonation) {
        //use my own address as destination
        std::string destination_addr = m_wallet->get_subaddress_as_str({m_current_subaddress_account, 0});
        local_args.insert(local_args.begin()+i, destination_addr);
      }

      if (!cryptonote::get_account_address_from_str_or_url(info, m_wallet->nettype(), local_args[i], oa_prompter))
      {
        fail_msg_writer() << tr("failed to parse address");
        return true;
      }
      de.addr = info.address;
      de.is_subaddress = info.is_subaddress;

      if (info.has_payment_id)
      {
        if (payment_id_seen)
        {
          fail_msg_writer() << tr("a single transaction cannot use more than one payment id: ") << local_args[i];
          return true;
        }

        std::string extra_nonce;
        set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, info.payment_id);
        bool r = add_extra_nonce_to_tx_extra(extra, extra_nonce);
        if (!r)
        {
          fail_msg_writer() << tr("failed to set up payment id, though it was decoded correctly");
          return true;
        }
        payment_id_seen = true;
      }

      uint64_t value_amount = 0;

      bool ok = cryptonote::parse_amount(value_amount, local_args[i + 1]);
      if (!ok || 0 == value_amount)
      {
        fail_msg_writer() << tr("amount is wrong: ") << local_args[i] << ' ' << local_args[i + 1] <<
                          ", " << tr("expected number from 0 to ") << print_money(std::numeric_limits<uint64_t>::max());
        return true;
      }
    

      if (command_type == CommandType::TransferLockToken)
      {
        if (!tools::is_whole_coin_amount(value_amount))
        {
          fail_msg_writer() << tr("token amount must be whole number. ") << local_args[i] << ' ' << local_args[i + 1];
          return true;
        }
        de.token_amount = value_amount;
        de.script_output = true;
        de.output_type = tx_out_type::out_staked_token;
      }
      else if (command_type == CommandType::TransferUnlockToken)
      {
        if (!tools::is_whole_coin_amount(value_amount))
        {
          fail_msg_writer() << tr("token amount must be whole number. ") << local_args[i] << ' ' << local_args[i + 1];
          return true;
        }
        de.token_amount = value_amount;
        de.script_output = false;
        de.output_type = tx_out_type::out_token;
      }
      else if (command_type == CommandType::TransferDonation) {
        de.amount = value_amount;
        de.script_output = true;
        de.output_type = tx_out_type::out_network_fee;
      }
      // Allow to collect outputs for regular SFX transaction.
      else if(command_type == CommandType::TransferDemoPurchase) {
        de.amount = value_amount * 95 / 100;
        safex_network_fee += value_amount * 5 / 100;
      }
    
      dsts.push_back(de);
    }

    // If its demo purchase, make special destination_entry for network fee.
    if(command_type == CommandType::TransferDemoPurchase) {
      cryptonote::tx_destination_entry de_net_fee = AUTO_VAL_INIT(de_net_fee);
      std::string destination_addr = m_wallet->get_subaddress_as_str({m_current_subaddress_account, 0});

      cryptonote::address_parse_info info = AUTO_VAL_INIT(info);
      if (!cryptonote::get_account_address_from_str(info, m_wallet->nettype(), destination_addr))
      {
        fail_msg_writer() << tr("failed to parse address");
        return true;
      }

      de_net_fee.addr = info.address;
      de_net_fee.is_subaddress = info.is_subaddress;
      de_net_fee.amount = safex_network_fee;
      de_net_fee.script_output = true;
      de_net_fee.output_type = tx_out_type::out_network_fee;

      dsts.push_back(de_net_fee);
    }

    try
    {
      // figure out what tx will be necessary
      std::vector<tools::wallet::pending_tx> ptx_vector;
      uint64_t bc_height, unlock_block = 0;
      std::string err;
      safex::command_t command = safex::command_t::nop;
      switch (command_type)
      {
        case CommandType::TransferLockToken:
          command = safex::command_t::token_stake;
          break;

        case CommandType::TransferUnlockToken:
          command = safex::command_t::token_unstake;
          break;

        case CommandType::TransferDemoPurchase:
          command = safex::command_t::simple_purchase;
          break;

        case CommandType::TransferDonation:
          command = safex::command_t::donate_network_fee;
          break;

        default:
          LOG_ERROR("Unknown command method, using original");
          return true;
      }
      
      ptx_vector = m_wallet->create_transactions_advanced(command, dsts, fake_outs_count, 0 /* unlock_time */, priority, extra, m_current_subaddress_account, subaddr_indices, m_trusted_daemon);
      
      

      if (ptx_vector.empty())
      {
        fail_msg_writer() << tr("No outputs found, or daemon is not ready");
        return true;
      }

      // if we need to check for backlog, check the worst case tx
      if (m_wallet->confirm_backlog())
      {
        std::stringstream prompt;
        double worst_fee_per_byte = std::numeric_limits<double>::max();
        for (size_t n = 0; n < ptx_vector.size(); ++n)
        {
          const uint64_t blob_size = cryptonote::tx_to_blob(ptx_vector[n].tx).size();
          const double fee_per_byte = ptx_vector[n].fee / (double) blob_size;
          if (fee_per_byte < worst_fee_per_byte)
          {
            worst_fee_per_byte = fee_per_byte;
          }
        }
        try
        {
          std::vector<std::pair<uint64_t, uint64_t>> nblocks = m_wallet->estimate_backlog({std::make_pair(worst_fee_per_byte, worst_fee_per_byte)});
          if (nblocks.size() != 1)
          {
            prompt << "Internal error checking for backlog. " << tr("Is this okay anyway?  (Y/Yes/N/No): ");
          }
          else
          {
            if (nblocks[0].first > m_wallet->get_confirm_backlog_threshold())
              prompt << (boost::format(tr("There is currently a %u block backlog at that fee level. Is this okay?  (Y/Yes/N/No): ")) % nblocks[0].first).str();
          }
        }
        catch (const std::exception &e)
        {
          prompt << tr("Failed to check for backlog: ") << e.what() << ENDL << tr("Is this okay anyway?  (Y/Yes/N/No): ");
        }

        std::string prompt_str = prompt.str();
        if (!prompt_str.empty())
        {
          std::string accepted = input_line(prompt_str);
          if (std::cin.eof())
            return true;
          if (!command_line::is_yes(accepted))
          {
            fail_msg_writer() << tr("transaction cancelled.");

            return true;
          }
        }
      }

      // if more than one tx necessary, prompt user to confirm
      if (m_wallet->always_confirm_transfers() || ptx_vector.size() > 1)
      {
        uint64_t total_sent = 0;
        uint64_t total_token_sent = 0;
        uint64_t total_fee = 0;
        uint64_t dust_not_in_fee = 0;
        uint64_t token_dust_not_in_fee = 0;
        uint64_t dust_in_fee = 0;
        for (size_t n = 0; n < ptx_vector.size(); ++n)
        {
          total_fee += ptx_vector[n].fee;
          for (auto i: ptx_vector[n].selected_transfers)
          {
            total_sent += m_wallet->get_transfer_details(i).amount();
            total_token_sent += m_wallet->get_transfer_details(i).token_amount();
          }
          total_sent -= ptx_vector[n].change_dts.amount + ptx_vector[n].fee;
          total_token_sent -= ptx_vector[n].change_token_dts.token_amount;

          if (ptx_vector[n].dust_added_to_fee)
            dust_in_fee += ptx_vector[n].dust;
          else
            dust_not_in_fee += ptx_vector[n].dust;

          token_dust_not_in_fee += ptx_vector[n].change_token_dts.token_amount;
        }

        std::stringstream prompt;
        for (size_t n = 0; n < ptx_vector.size(); ++n)
        {
          prompt << tr("\nTransaction ") << (n + 1) << "/" << ptx_vector.size() << ":\n";
          subaddr_indices.clear();
          for (uint32_t i : ptx_vector[n].construction_data.subaddr_indices)
            subaddr_indices.insert(i);

          if (subaddr_indices.size() > 1)
            prompt << tr("WARNING: Outputs of multiple addresses are being used together, which might potentially compromise your privacy.\n");
        }

        if (command_type == CommandType::TransferLockToken)
          prompt << boost::format(tr("Locking %s tokens. ")) % print_money(total_token_sent);


        if (ptx_vector.size() > 1)
        {
          prompt << boost::format(tr("Your transaction needs to be split into %llu transactions.  "
                                     "This will result in a transaction fee being applied to each transaction, for a total fee of %s")) %
                    ((unsigned long long) ptx_vector.size()) % print_money(total_fee);
        }
        else
        {
          prompt << boost::format(tr("The transaction fee is %s. ")) %
                    print_money(total_fee);
        }
        if (dust_in_fee != 0) prompt << boost::format(tr(", of which %s is dust from change")) % print_money(dust_in_fee);
        if (dust_not_in_fee != 0)
          prompt << tr(".") << ENDL << boost::format(tr("A total of %s from dust change and %s tokens change  will be sent to dust address "))
                                       % print_money(dust_not_in_fee) % print_money(token_dust_not_in_fee);

        if (m_wallet->print_ring_members())
        {
          if (!print_ring_members(ptx_vector, prompt))
            return true;
        }
        bool default_ring_size = true;
        for (const auto &ptx: ptx_vector)
        {
          for (const auto &vin: ptx.tx.vin)
          {
            if (vin.type() == typeid(txin_to_key))
            {
              const txin_to_key &in_to_key = boost::get<txin_to_key>(vin);
              if (in_to_key.key_offsets.size() != DEFAULT_MIX + 1)
                default_ring_size = false;
            }
          }
        }
        if (m_wallet->confirm_non_default_ring_size() && !default_ring_size)
        {
          prompt << tr("\nWARNING: this is a non default ring size, which may harm your privacy. Default is recommended.");
        }
        prompt << ENDL << tr("Is this okay?  (Y/Yes/N/No): ");

        std::string accepted = input_line(prompt.str());
        if (std::cin.eof())
          return true;
        if (!command_line::is_yes(accepted))
        {
          fail_msg_writer() << tr("transaction cancelled.");

          return true;
        }
      }

      if (m_wallet->watch_only())
      {
        bool r = m_wallet->save_tx(ptx_vector, "unsigned_safex_tx");
        if (!r)
        {
          fail_msg_writer() << tr("Failed to write transaction(s) to file");
        }
        else
        {
          success_msg_writer(true) << tr("Unsigned transaction(s) successfully written to file: ") << "unsigned_safex_tx";
        }
      }
      else
      {
        commit_or_save(ptx_vector, m_do_not_relay);
      }
    }
    catch (const std::exception &e)
    {
      handle_transfer_exception(std::current_exception(), m_trusted_daemon);
    }
    catch (...)
    {
      LOG_ERROR("unknown error");
      fail_msg_writer() << tr("unknown error");
    }

    if(command_type == CommandType::TransferDemoPurchase) {
      success_msg_writer() << boost::format(tr("You successfully paid offer with id %s.  ")) % offer_id;
    }

    if(command_type == CommandType::TransferDonation) {
      success_msg_writer() << boost::format(tr("You successfully donated network!!! "));
    }


    return true;
  }

  bool simple_wallet::lock_token(const std::vector<std::string> &args)
  {
    return create_command(CommandType::TransferLockToken, args);
  }

  bool simple_wallet::unlock_token(const std::vector<std::string> &args)
  {
    return create_command(CommandType::TransferUnlockToken, args);
  }

  bool simple_wallet::donate_safex_fee(const std::vector<std::string> &args)
  {
    return create_command(CommandType::TransferDonation, args);
  }

  bool simple_wallet::locked_token_balance(const std::vector<std::string> &args)
  {
    return false;
  }


  bool simple_wallet::show_staked_token_balance_unlocked(bool detailed)
  {
    std::string extra;
    success_msg_writer() << tr("Currently selected token account: [") << m_current_subaddress_account << tr("] ") << m_wallet->get_subaddress_label({m_current_subaddress_account, 0});
    const std::string tag = m_wallet->get_account_tags().second[m_current_subaddress_account];
    success_msg_writer() << tr("Tag: ") << (tag.empty() ? std::string{tr("(No tag assigned)")} : tag);
    success_msg_writer() << tr("Staked token balance: ") << print_money(m_wallet->staked_token_balance(m_current_subaddress_account)) << ", "
      << tr("unlocked staked token balance: ") << print_money(m_wallet->unlocked_staked_token_balance(m_current_subaddress_account)) << extra;
    std::map<uint32_t, uint64_t> token_balance_per_subaddress = m_wallet->staked_token_balance_per_subaddress(m_current_subaddress_account);
    std::map<uint32_t, uint64_t> unlocked_balance_per_subaddress = m_wallet->unlocked_staked_token_balance_per_subaddress(m_current_subaddress_account);
    if (!detailed || token_balance_per_subaddress.empty())
      return true;

    success_msg_writer() << tr("Staked token balance per address:");
    success_msg_writer() << boost::format("%15s %21s %21s %7s %21s") % tr("Address") % tr("Balance") % tr("Unlocked balance") % tr("Outputs") % tr("Label");
    std::vector<tools::wallet::transfer_details> transfers;
    m_wallet->get_transfers(transfers);

    for (const auto& i : token_balance_per_subaddress)
    {
      cryptonote::subaddress_index subaddr_index = {m_current_subaddress_account, i.first};
      std::string address_str = m_wallet->get_subaddress_as_str(subaddr_index).substr(0, 6);
      uint64_t num_unspent_outputs = std::count_if(transfers.begin(), transfers.end(), [&subaddr_index](const tools::wallet::transfer_details& td) { return td.m_output_type == tx_out_type::out_staked_token && !td.m_spent && td.m_subaddr_index == subaddr_index; });
      success_msg_writer() << boost::format(tr("%8u %6s %21s %21s %7u %21s")) % i.first % address_str % print_money(i.second) % print_money(unlocked_balance_per_subaddress[i.first]) % num_unspent_outputs % m_wallet->get_subaddress_label(subaddr_index);
    }
    return true;
  }

  bool simple_wallet::show_staked_token_balance(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
  {
    if (args.size() > 1 || (args.size() == 1 && args[0] != "detail"))
    {
      fail_msg_writer() << tr("usage: balance_cash [detail]");
      return true;
    }
    LOCK_IDLE_SCOPE();
    show_staked_token_balance_unlocked(args.size() == 1);
    return true;
  }

  bool simple_wallet::demo_purchase(const std::vector<std::string>& args) {
    
    return create_command(CommandType::TransferDemoPurchase, args);
  }

  bool simple_wallet::list_demo_offers(const std::vector<std::string>& args) {
    success_msg_writer() << boost::format("%10s %40s ") % tr("OfferID") % tr("Title");
    for(auto offer : simple_trade_ids) {
      success_msg_writer() << boost::format("%10s %40s ") % tr(offer.first.c_str()) % tr(offer.second.c_str());
    }
    return true;
  }

}
