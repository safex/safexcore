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
#include <safex/command.h>
#include "simplewallet_common.h"
#include "safex/safex_account.h"

using namespace std;
using namespace epee;
using namespace cryptonote;
using boost::lexical_cast;

namespace cryptonote
{

  tx_destination_entry create_safex_account_destination(const account_public_address &to, const std::string &username, const crypto::public_key &pkey,
                                                        const std::vector<uint8_t> &account_data)
  {
    safex::create_account_data acc_output_data{username, pkey, account_data};
    blobdata blobdata = cryptonote::t_serializable_object_to_blob(acc_output_data);
    return tx_destination_entry{0, to, false, tx_out_type::out_safex_account, blobdata};
  }

  tx_destination_entry edit_safex_account_destination(const account_public_address &to, const std::string &username, const std::vector<uint8_t> &account_data)
  {
    safex::edit_account_data acc_output_data{username, account_data};
    blobdata blobdata = cryptonote::t_serializable_object_to_blob(acc_output_data);
    return tx_destination_entry{0, to, false, tx_out_type::out_safex_account_update, blobdata};
  }

    tx_destination_entry create_safex_offer_destination(const account_public_address &to, const safex::safex_offer &sfx_offer)
    {
        safex::create_offer_data offer_output_data{sfx_offer};
        blobdata blobdata = cryptonote::t_serializable_object_to_blob(offer_output_data);
        return tx_destination_entry{0, to, false, tx_out_type::out_safex_offer, blobdata};
    }

    tx_destination_entry edit_safex_offer_destination(const account_public_address &to, const safex::safex_offer &sfx_offer)
    {
        safex::edit_offer_data offer_output_data{sfx_offer};
        blobdata blobdata = cryptonote::t_serializable_object_to_blob(offer_output_data);
        return tx_destination_entry{0, to, false, tx_out_type::out_safex_offer_update, blobdata};
    }

    tx_destination_entry close_safex_offer_destination(const account_public_address &to, const safex::safex_offer &sfx_offer, const crypto::public_key &pkey)
    {
        safex::close_offer_data offer_output_data{sfx_offer.offer_id,pkey,sfx_offer.seller};
        blobdata blobdata = cryptonote::t_serializable_object_to_blob(offer_output_data);
        return tx_destination_entry{0, to, false, tx_out_type::out_safex_offer_close, blobdata};
    }


  bool simple_wallet::create_command(CommandType command_type, const std::vector<std::string> &args_)
  {
    //todo Uncomment
//    if (m_wallet->ask_password() && !get_and_verify_password())
//    { return true; }
    if (!try_connect_to_daemon())
      return true;

    switch (command_type) {
      case CommandType::TransferStakeToken:
      case CommandType::TransferDonation:
      case CommandType::TransferUnstakeToken:
      case CommandType::TransferDemoPurchase:
      case CommandType::TransferCreateAccount:
      case CommandType::TransferEditAccount:
      case CommandType::TransferCreateOffer:
      case CommandType::TransferEditOffer:
      case CommandType::TransferCloseOffer:
        //do nothing
        break;
      default:
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

      if (command_type == CommandType::TransferUnstakeToken)
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

    size_t min_args{2};

    switch (command_type) {
      case CommandType::TransferDonation:
      case CommandType::TransferCreateAccount:
        min_args = 1;
      break;

      default:
        //min_args is 2
        break;
    }
    
    if (local_args.size() < min_args)
    {
      fail_msg_writer() << tr("wrong number of arguments");
      return true;
    }

    std::string payment_id_str;
    std::vector<uint8_t> extra;
    bool payment_id_seen = false;
    bool command_supports_payment_id = (command_type != CommandType::TransferCreateAccount) && (command_type != CommandType::TransferEditAccount) &&
                                        (command_type != CommandType::TransferCreateOffer) && (command_type != CommandType::TransferEditOffer) &&(command_type != CommandType::TransferCloseOffer);
    bool expect_even = (min_args % 2 == 1);
    if (command_supports_payment_id && ((expect_even ? 0 : 1) == local_args.size() % 2))
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

    safex::safex_account my_safex_account = AUTO_VAL_INIT(my_safex_account);
    if (command_type == CommandType::TransferCreateAccount || command_type == CommandType::TransferEditAccount) {
      //use my own current subaddress as destination
      cryptonote::address_parse_info info = AUTO_VAL_INIT(info);
      std::string destination_addr = m_wallet->get_subaddress_as_str({m_current_subaddress_account, 0});
      if (!cryptonote::get_account_address_from_str(info, m_wallet->nettype(), destination_addr))
      {
        fail_msg_writer() << tr("failed to parse address");
        return true;
      }

      const std::string &sfx_username = local_args[0];
      if (!m_wallet->get_safex_account(sfx_username, my_safex_account)) {
        fail_msg_writer() << tr("unknown safex account username");
        return true;
      };

      if (command_type == CommandType::TransferCreateAccount)
      {
        if (!crypto::check_key(my_safex_account.pkey)) {
          fail_msg_writer() << tr("invalid account public key");
          return true;
        }

        cryptonote::tx_destination_entry de_account = create_safex_account_destination(info.address, my_safex_account.username, my_safex_account.pkey, my_safex_account.account_data);

        dsts.push_back(de_account);

        //lock tokens for account creation
        cryptonote::tx_destination_entry token_create_fee = AUTO_VAL_INIT(token_create_fee);
        token_create_fee.addr = info.address;
        token_create_fee.is_subaddress = info.is_subaddress;
        token_create_fee.token_amount = SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_FEE;
        token_create_fee.output_type = tx_out_type::out_token;
        dsts.push_back(token_create_fee);
      }
      else if (command_type == CommandType::TransferEditAccount) {

        std::ostringstream accdata_ostr;
        std::copy(local_args.begin() + 1, local_args.end(), ostream_iterator<string>(accdata_ostr, " "));
        const std::string accdata_str = accdata_ostr.str();
        std::vector<uint8_t> new_accdata(accdata_str.begin(), accdata_str.end()-1);
        if (new_accdata.size() == 0) {
          fail_msg_writer() << tr("failed to parse account data");
          return false;
        }
        cryptonote::tx_destination_entry de_account_update = edit_safex_account_destination(info.address, my_safex_account.username, new_accdata);

        dsts.push_back(de_account_update);

      }
    }
    else if(command_type == CommandType::TransferCreateOffer || command_type == CommandType::TransferEditOffer || command_type == CommandType::TransferCloseOffer){
        //use my own current subaddress as destination
        cryptonote::address_parse_info info = AUTO_VAL_INIT(info);
        std::string destination_addr = m_wallet->get_subaddress_as_str({m_current_subaddress_account, 0});
        if (!cryptonote::get_account_address_from_str(info, m_wallet->nettype(), destination_addr))
        {
            fail_msg_writer() << tr("failed to parse address");
            return true;
        }

        const std::string &sfx_username = local_args[0];
        if (!m_wallet->get_safex_account(sfx_username, my_safex_account)) {
            fail_msg_writer() << tr("unknown safex account username");
            return true;
        };

        if (command_type == CommandType::TransferCreateOffer) {

            std::string offer_title = local_args[1];
            uint64_t quantity = stoi(local_args[2]);
            uint64_t price= stoi(local_args[3]);
            safex::safex_price sfx_price{price,price,5};

            std::ostringstream offerdata_ostr;
            std::copy(local_args.begin() + 4, local_args.end(), ostream_iterator<string>(offerdata_ostr, " "));
            std::string description = offerdata_ostr.str();

            safex::safex_account_keys keys;
            bool res = m_wallet->get_safex_account_keys(my_safex_account.username,keys);

            safex::safex_offer sfx_offer{offer_title, quantity, sfx_price, description,
            true, keys, my_safex_account.username};

            cryptonote::tx_destination_entry de_offer = create_safex_offer_destination(info.address, sfx_offer);
            dsts.push_back(de_offer);

        }
        else if (command_type == CommandType::TransferEditOffer) {

            crypto::hash offer_id_hash;

            for(int i=0, j=0;i<64;i+=2,j++){
                offer_id_hash.data[j] = 0;
                std::stringstream ss;
                std::string str{local_args[1][i]};
                str+=local_args[1][i+1];
                unsigned int x = std::stoul(str, nullptr, 16);
                offer_id_hash.data[j] = x;
            }

            std::string offer_title = local_args[2];
            uint64_t quantity = stoi(local_args[3]);
            uint64_t price= stoi(local_args[4]);
            safex::safex_price sfx_price{price,price,5};
            bool active = stoi(local_args[5]);

            std::ostringstream offerdata_ostr;
            std::copy(local_args.begin() + 6, local_args.end(), ostream_iterator<string>(offerdata_ostr, " "));
            std::string description = offerdata_ostr.str();

            safex::safex_account_keys keys;
            bool res = m_wallet->get_safex_account_keys(my_safex_account.username,keys);

            safex::safex_offer sfx_offer{offer_title, quantity, sfx_price, std::vector<uint8_t>{description.begin(),description.end()},
                                         active, offer_id_hash, my_safex_account.username};

            cryptonote::tx_destination_entry de_offer_update = edit_safex_offer_destination(info.address, sfx_offer);
            dsts.push_back(de_offer_update);

        }
        else if (command_type == CommandType::TransferCloseOffer) {

            safex::safex_offer sfx_offer{};

           crypto::hash offer_id_close{};
            for(int i=0, j=0;i<64;i+=2,j++){
                offer_id_close.data[j] = 0;
                std::stringstream ss;
                std::string str{local_args[1][i]};
                str+=local_args[1][i+1];
                unsigned int x = std::stoul(str, nullptr, 16);
                offer_id_close.data[j] = x;
            }

            sfx_offer.offer_id = offer_id_close;
            sfx_offer.seller = sfx_username;

            cryptonote::tx_destination_entry de_offer_close = close_safex_offer_destination(info.address, sfx_offer,my_safex_account.pkey);
            dsts.push_back(de_offer_close);

        }
    }
    else
    {

      for (size_t i = 0; i < local_args.size(); i += 2)
      {
        cryptonote::address_parse_info info = AUTO_VAL_INIT(info);
        cryptonote::tx_destination_entry de = AUTO_VAL_INIT(de);

        if (command_type == CommandType::TransferDonation)
        {
          //use my own address as destination
          std::string destination_addr = m_wallet->get_subaddress_as_str({m_current_subaddress_account, 0});
          local_args.insert(local_args.begin() + i, destination_addr);
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


        if (command_type == CommandType::TransferStakeToken)
        {
          if (!tools::is_whole_token_amount(value_amount))
          {
            fail_msg_writer() << tr("token amount must be whole number. ") << local_args[i] << ' ' << local_args[i + 1];
            return true;
          }
          de.token_amount = value_amount;
          de.script_output = true;
          de.output_type = tx_out_type::out_staked_token;
        } else if (command_type == CommandType::TransferUnstakeToken)
        {
          if (!tools::is_whole_token_amount(value_amount))
          {
            fail_msg_writer() << tr("token amount must be whole number. ") << local_args[i] << ' ' << local_args[i + 1];
            return true;
          }
          de.token_amount = value_amount;
          de.script_output = false;
          de.output_type = tx_out_type::out_token;
        } else if (command_type == CommandType::TransferDonation)
        {
          de.amount = value_amount;
          de.script_output = true;
          de.output_type = tx_out_type::out_network_fee;
        }
          // Allow to collect outputs for regular SFX transaction.
        else if (command_type == CommandType::TransferDemoPurchase)
        {
          de.amount = value_amount * 95 / 100;
          safex_network_fee += value_amount * 5 / 100;
        }

        dsts.push_back(de);
      }
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
      uint64_t bc_height = m_wallet->get_blockchain_current_height();
      uint64_t unlock_block = 0;
      std::string err;
      safex::command_t command = safex::command_t::nop;
      switch (command_type)
      {
        case CommandType::TransferStakeToken:
          command = safex::command_t::token_stake;
          break;

        case CommandType::TransferUnstakeToken:
          command = safex::command_t::token_unstake;
          break;

        case CommandType::TransferDemoPurchase:
          command = safex::command_t::simple_purchase;
          break;

        case CommandType::TransferDonation:
          command = safex::command_t::donate_network_fee;
          break;

        case CommandType::TransferCreateAccount:
          command = safex::command_t::create_account;
          unlock_block = bc_height + SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_PERIOD + 10; //just in case
          break;

        case CommandType::TransferEditAccount:
          command = safex::command_t::edit_account;
          break;

        case CommandType::TransferCreateOffer:
          command = safex::command_t::create_offer;
          break;

        case CommandType::TransferEditOffer:
          command = safex::command_t::edit_offer;
          break;

        case CommandType::TransferCloseOffer:
          command = safex::command_t::close_offer;
          break;

        default:
          LOG_ERROR("Unknown command method, using original");
          return true;
      }



      
      ptx_vector = m_wallet->create_transactions_advanced(command, dsts, fake_outs_count, unlock_block, priority, extra, m_current_subaddress_account, subaddr_indices, m_trusted_daemon, my_safex_account);

      

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

        if (command_type == CommandType::TransferStakeToken)
          prompt << boost::format(tr("Staking %s tokens. ")) % print_money(total_token_sent);


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

  bool simple_wallet::stake_token(const std::vector<std::string> &args)
  {
    return create_command(CommandType::TransferStakeToken, args);
  }

  bool simple_wallet::unstake_token(const std::vector<std::string> &args)
  {
    return create_command(CommandType::TransferUnstakeToken, args);
  }

  bool simple_wallet::donate_safex_fee(const std::vector<std::string> &args)
  {
    return create_command(CommandType::TransferDonation, args);
  }

  bool simple_wallet::staked_token_balance(const std::vector<std::string> &args)
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

  bool simple_wallet::get_my_interest(const std::vector<std::string>& args)
  {
    std::vector<std::pair<uint64_t, uint64_t>> interest_per_output;
    uint64_t collected_interest = m_wallet->get_current_interest(interest_per_output);
    
    success_msg_writer() << tr("Collected interest so far is: ") << print_money(collected_interest);
    success_msg_writer() << boost::format("%30s %20s") % tr("Output amount") % tr("Available interest");
    for(auto& pair : interest_per_output)
    {
      success_msg_writer() << boost::format("%30s %20s") % pair.first % print_money(pair.second);
    }
    return true;
  }

  void simple_wallet::print_safex_accounts()
  {
    success_msg_writer() << tr("Safex accounts");
    success_msg_writer() << boost::format("%30s %80s") % tr("Account Username") % tr("Account Data");
    for (auto& acc: m_wallet->get_safex_accounts()) {
      success_msg_writer() << boost::format("%30s %80s ") % acc.username % std::string(begin(acc.account_data), end(acc.account_data));
    }
  }


  void simple_wallet::print_safex_offers() {
      success_msg_writer() << tr("Safex offers");
      success_msg_writer() << boost::format("%30s %10s %10s %30s %60s %20s") % tr("Offer title") %  tr("Price") % tr("Quantity") % tr("Seller") % tr("Description") %tr("Offer ID");
      for (auto &offer: m_wallet->get_safex_offers()) {
          success_msg_writer() << boost::format("%30s %10s %10s %30s %60s %20s") % offer.title % offer.price.price % offer.quantity % offer.seller %
                                  std::string(begin(offer.description), end(offer.description)) % offer.offer_id;
      }
  }


    bool simple_wallet::safex_account(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
  {
    // Usage:
    //   safex_account
    //   safex_account new <account_username>
    //   safex_account remove <account_username>
    //   safex_account recover <account_username> <account_private_key>
    //   safex_account keys <account_username>
    //   safex_account create [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <account_username>
    //   safex_account edit [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <account_username> <new_account_data>

    if (args.empty())
    {
      // print all the existing accounts
      LOCK_IDLE_SCOPE();
      print_safex_accounts();
      return true;
    }

    std::vector<std::string> local_args = args;
    std::string command = local_args[0];
    local_args.erase(local_args.begin());
    if (command == "new")
    {
      const std::string &username = local_args[0];

      std::ostringstream accdata_ostr;
      std::copy(local_args.begin() + 1, local_args.end(), ostream_iterator<string>(accdata_ostr, " "));
      const std::string accdata_str = accdata_ostr.str();
      std::vector<uint8_t> accdata(accdata_str.begin(), accdata_str.end()-1);
      if (accdata.size() == 0) {
        fail_msg_writer() << tr("failed to parse account data");
        return true;
      }

      if (m_wallet->generate_safex_account(username, accdata)) {
        success_msg_writer() << tr("New account created");
      } else {
        fail_msg_writer() << tr("Failed to create account");
      }
    }
    else if (command == "remove")
    {
      const std::string &username = local_args[0];


      if (m_wallet->remove_safex_account(username)) {
        success_msg_writer() << tr("Account removed");
      } else {
        fail_msg_writer() << tr("Failed to remove account ") << username;
      }
    }
    else if (command == "recover")
    {

      if (local_args.size() != 2) {
        fail_msg_writer() << tr("Please provide username and secret key for account recovery ");
        return true;
      }

      const std::string &username = local_args[0];
      const std::string &private_key = local_args[1];


      crypto::secret_key skey{};
      epee::string_tools::hex_to_pod(private_key, skey);

      if (m_wallet->recover_safex_account(username, skey)) {
        success_msg_writer() << tr("Account recovered");
      } else {
        fail_msg_writer() << tr("Failed to recover account ") << username;
      }
    }
    else if (command == "keys")
    {
      const std::string &username = local_args[0];

      if (m_wallet->ask_password() && !get_and_verify_password()) { return true; }

      safex::safex_account_keys keys = AUTO_VAL_INIT(keys);
      if (m_wallet->get_safex_account_keys(username, keys)) {
        success_msg_writer() << tr("Account ") << username<< tr(" keys:");
        success_msg_writer() << tr("Public key: ") <<  epee::string_tools::pod_to_hex(keys.m_public_key) ;
        success_msg_writer() << tr("Secret key: ") <<  epee::string_tools::pod_to_hex(keys.m_secret_key) ;

      } else {
        fail_msg_writer() << tr("Failed to print account keys ") << username;
      }
    }
    else if (command == "create")
    {
      // create a new safex account transaction
      return create_command(CommandType::TransferCreateAccount, local_args);
    }
    else if (command == "edit")
    {
      return create_command(CommandType::TransferEditAccount, local_args);
    }
    else
    {
      success_msg_writer() << tr("usage:\n"
                              "  safex_account\n"
                              "  safex_account new <account_username> <account_data>\n"
                              "  safex_account remove <account_username>\n"
                              "  safex_account keys <account_username>\n"
                              "  safex_account recover <account_username> <account_private_key>\n"
                              "  safex_account create [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <account_username>\n"
                              "  safex_account edit [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <account_username> <new_account_data>");
    }
    return true;
  }


    bool simple_wallet::safex_offer(const std::vector<std::string> &args){
        //   Usage:
        //   safex_offer
        //   safex_offer new    <offer_name> <offer_data> <offer_price> <offer_quantity>
        //   safex_offer create <offer_name>
        //   safex_offer edit   <offer_name> <offer_data> <offer_price> <offer_quantity>
        //   safex_offer close  <offer_name>

        if (args.empty())
        {
            // print all the existing offers
            LOCK_IDLE_SCOPE();
            print_safex_offers();
            return true;
        }

        std::vector<std::string> local_args = args;
        std::string command = local_args[0];
        local_args.erase(local_args.begin());
        if (command == "create")
        {
            // create a new safex offer transaction
            return create_command(CommandType::TransferCreateOffer, local_args);
        }
        else if (command == "close")
        {
            return create_command(CommandType::TransferCloseOffer, local_args);

        }
        else if (command == "edit")
        {
            return create_command(CommandType::TransferEditOffer, local_args);
        }
        else
        {
            success_msg_writer() << tr("usage:\n"
                                       "  safex_offer\n"
                                       "  safex_offer create [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <account_name> <offer_name> <offer_quantity> <offer_price> <offer_description>\n"
                                       "  safex_offer edit [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <offer_id> <offer_data> <offer_price> <offer_quantity>\n"
                                       "  safex_offer close [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <offer_id>");
        }
        return true;
  }


    //----------------------------------------------------------------------------------------------------
  void simple_wallet::on_advanced_output_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, const txout_to_script &txout, const cryptonote::subaddress_index& subaddr_index){
    if (txout.output_type == static_cast<uint8_t>(tx_out_type::out_safex_account)) {
      safex::create_account_data account;
      const cryptonote::blobdata accblob(std::begin(txout.data), std::end(txout.data));
      cryptonote::parse_and_validate_from_blob(accblob, account);
      std::string accusername(begin(account.username), end(account.username));
      m_wallet->update_safex_account_data(accusername, account.account_data);

      message_writer(console_color_green, false) << "\r" <<
                                                 tr("Height ") << height << ", " <<
                                                 tr("txid ") << txid << ", " <<
                                                 tr("Output of type account, username: ") << accusername << " received, " <<
                                                 tr("idx ") << subaddr_index;
    } else if (txout.output_type == static_cast<uint8_t>(tx_out_type::out_safex_account_update)) {
      safex::edit_account_data account;
      const cryptonote::blobdata accblob(std::begin(txout.data), std::end(txout.data));
      cryptonote::parse_and_validate_from_blob(accblob, account);
      std::string accusername(begin(account.username), end(account.username));
      m_wallet->update_safex_account_data(accusername, account.account_data);


      message_writer(console_color_green, false) << "\r" <<
                                                 tr("Height ") << height << ", " <<
                                                 tr("txid ") << txid << ", " <<
                                                 tr("Updated for account, username: ") << accusername << " received, " <<
                                                 tr("idx ") << subaddr_index;
    } else if (txout.output_type == static_cast<uint8_t>(tx_out_type::out_safex_offer)){
        safex::create_offer_data offer;
        const cryptonote::blobdata offblob(std::begin(txout.data), std::end(txout.data));
        cryptonote::parse_and_validate_from_blob(offblob, offer);
        safex::safex_offer sfx_offer{std::string{offer.title.begin(),offer.title.end()},offer.quantity,offer.price,offer.description,offer.active,offer.offer_id,std::string{offer.seller.begin(),offer.seller.end()}};

        m_wallet->add_safex_offer(sfx_offer);

    } else if (txout.output_type == static_cast<uint8_t>(tx_out_type::out_safex_offer_update)){
        safex::edit_offer_data offer;
        const cryptonote::blobdata offblob(std::begin(txout.data), std::end(txout.data));
        cryptonote::parse_and_validate_from_blob(offblob, offer);
        safex::safex_offer sfx_offer{std::string{offer.title.begin(),offer.title.end()},offer.quantity,offer.price,
                                     offer.description,offer.active,offer.offer_id,std::string{offer.seller.begin(),offer.seller.end()}};

        m_wallet->update_safex_offer(sfx_offer);

    } else if (txout.output_type == static_cast<uint8_t>(tx_out_type::out_safex_offer_close)){
        safex::close_offer_data offer;
        const cryptonote::blobdata offblob(std::begin(txout.data), std::end(txout.data));
        cryptonote::parse_and_validate_from_blob(offblob, offer);

        m_wallet->close_safex_offer(offer.offer_id);

    }


    if (m_auto_refresh_refreshing)
      m_cmd_binder.print_prompt();
    else
      m_refresh_progress_reporter.update(height, true);
  }
//----------------------------------------------------------------------------------------------------

}
