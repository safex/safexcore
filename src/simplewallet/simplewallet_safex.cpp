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

    tx_destination_entry create_safex_purchase_destination(const cryptonote::account_public_address  &to, const safex::safex_purchase &sfx_purchase)
    {
        safex::create_purchase_data safex_purchase_output_data{sfx_purchase};
        blobdata blobdata = cryptonote::t_serializable_object_to_blob(safex_purchase_output_data);
        return tx_destination_entry{0, to, false, tx_out_type::out_safex_purchase, blobdata};
    }

    tx_destination_entry create_safex_feedback_token_destination(const cryptonote::account_public_address  &to, const safex::create_feedback_token_data &safex_feedback_token_output_data)
    {
        blobdata blobdata = cryptonote::t_serializable_object_to_blob(safex_feedback_token_output_data);
        return tx_destination_entry{0, to, false, tx_out_type::out_safex_feedback_token,blobdata};
    }

    tx_destination_entry create_safex_feedback_destination(const cryptonote::account_public_address  &to, const safex::safex_feedback &sfx_feedback)
    {
        safex::create_feedback_data safex_feedback_output_data{sfx_feedback};
        blobdata blobdata = cryptonote::t_serializable_object_to_blob(safex_feedback_output_data);
        return tx_destination_entry{0, to, false, tx_out_type::out_safex_feedback,blobdata};
    }

    tx_destination_entry create_safex_price_peg_destination(const cryptonote::account_public_address  &to, const safex::safex_price_peg &sfx_price_peg)
    {
      safex::create_price_peg_data safex_price_peg_output_data{sfx_price_peg};
      blobdata blobdata = cryptonote::t_serializable_object_to_blob(safex_price_peg_output_data);
      return tx_destination_entry{0, to, false, tx_out_type::out_safex_price_peg,blobdata};
    }

    tx_destination_entry update_safex_price_peg_destination(const cryptonote::account_public_address  &to, const safex::safex_price_peg &sfx_price_peg)
    {
      safex::update_price_peg_data safex_price_peg_output_data{sfx_price_peg};
      blobdata blobdata = cryptonote::t_serializable_object_to_blob(safex_price_peg_output_data);
      return tx_destination_entry{0, to, false, tx_out_type::out_safex_price_peg_update,blobdata};
    }

  bool simple_wallet::calculate_sfx_price(const safex::safex_offer& sfx_offer, uint64_t& sfx_price){

    sfx_price = sfx_offer.min_sfx_price;

    std::vector<safex::safex_price_peg> sfx_price_pegs = m_wallet->get_safex_price_pegs();

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

  bool simple_wallet::create_command(CommandType command_type, const std::vector<std::string> &args_)
  {
    //todo Uncomment
//    if (m_wallet->ask_password() && !get_and_verify_password())
//    { return true; }
    if (!try_connect_to_daemon())
      return true;


    LOCK_IDLE_SCOPE();

    std::vector<std::string> local_args = args_;



    std::set<uint32_t> subaddr_indices;
    if (!local_args.empty() && local_args[0].substr(0, 6) == "index=")
    {
      if (!parse_subaddress_indices(local_args[0], subaddr_indices))
        return true;
      local_args.erase(local_args.begin());
    }

    uint32_t priority = 0;
    if (!local_args.empty() && parse_priority(local_args[0], priority))
      local_args.erase(local_args.begin());

    priority = m_wallet->adjust_priority(priority);

    size_t fake_outs_count = 0;
    if (!local_args.empty())
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

      case CommandType::TransferFeedback:
        min_args = 3;
      break;

      case CommandType::TransferCreateOffer:
      case CommandType::TransferCreatePricePeg:
        min_args = 5;
      break;

      case CommandType::TransferUpdatePricePeg:
        min_args = 5;
        break;

      case CommandType::TransferEditOffer:
        min_args = 7;
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
                                        (command_type != CommandType::TransferCreateOffer) && (command_type != CommandType::TransferEditOffer) &&
                                        (command_type != CommandType::TransferFeedback) && (command_type != CommandType::TransferCreatePricePeg) &&
                                        (command_type != CommandType::TransferUpdatePricePeg);
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
    else if(command_type == CommandType::TransferCreateOffer || command_type == CommandType::TransferEditOffer){
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
            uint64_t price;
            uint64_t quantity;

            try{

              price = stold(local_args[2])*SAFEX_CASH_COIN;
              quantity = stoi(local_args[3]);

              long double check_price = stold(local_args[2]);
              long double check_quantity =  stold(local_args[3]);

              if(check_price < 0 || check_quantity < 0){
                fail_msg_writer() << tr("Negative amount or quantity entered");
                return true;
              }
            }
            catch(std::invalid_argument& e){
              fail_msg_writer() << tr("One of the arguments is missing. Please check needed arguments again.");
              return true;
            }

            std::ostringstream offerdata_ostr;
            std::copy(local_args.begin() + 4, local_args.end(), ostream_iterator<string>(offerdata_ostr, " "));
            std::string description = offerdata_ostr.str();

            safex::safex_offer sfx_offer{offer_title, quantity, price, description, my_safex_account.username,m_wallet->get_account().get_keys().m_view_secret_key,m_wallet->get_account().get_keys().m_account_address};

            std::string confirm = input_line(tr("Do you want to attach this offer to a price peg?  (Y/Yes/N/No): "));
            if (!std::cin.eof() && command_line::is_yes(confirm)) {
              if(!attach_price_peg(sfx_offer))
                return true;
            }

            cryptonote::tx_destination_entry de_offer = create_safex_offer_destination(info.address, sfx_offer);
            dsts.push_back(de_offer);

        }
        else if (command_type == CommandType::TransferEditOffer) {

            crypto::hash offer_id_hash;
            epee::string_tools::hex_to_pod(local_args[1], offer_id_hash);

            std::string offer_title = local_args[2];
            uint64_t price;
            uint64_t quantity;
            bool active;
            try {
                price = stold(local_args[3])*SAFEX_CASH_COIN;
                quantity = stoi(local_args[4]);
                active = stoi(local_args[5]);

            }
            catch(std::invalid_argument& e){
                fail_msg_writer() << tr("One of the arguments is missing. Please check needed arguments again.");
                return true;
            }

            std::ostringstream offerdata_ostr;
            std::copy(local_args.begin() + 6, local_args.end(), ostream_iterator<string>(offerdata_ostr, " "));
            std::string description = offerdata_ostr.str();

            safex::safex_offer sfx_offer{offer_title, quantity, price, std::vector<uint8_t>{description.begin(),description.end()},
                                          offer_id_hash, my_safex_account.username, active, m_wallet->get_account().get_keys().m_account_address, m_wallet->get_account().get_keys().m_view_secret_key};

          std::string confirm = input_line(tr("Do you want to attach this offer to a price peg?  (Y/Yes/N/No): "));
          if (!std::cin.eof() && command_line::is_yes(confirm)) {
            if(!attach_price_peg(sfx_offer))
              return true;
          }

            cryptonote::tx_destination_entry de_offer_update = edit_safex_offer_destination(info.address, sfx_offer);
            dsts.push_back(de_offer_update);

        }
    }
    else if (command_type == CommandType::TransferPurchase)
    {
        crypto::hash purchase_offer_id{};
        std::vector<safex::safex_offer> offers = m_wallet->get_safex_offers();
        std::vector<safex::safex_offer>::iterator offer_to_purchase;
        uint64_t quantity_to_purchase;

        if (!epee::string_tools::get_xtype_from_string(quantity_to_purchase, local_args.back())){
            fail_msg_writer() << tr("Bad quantity to purchase given!!!");
            return true;
        }
        local_args.pop_back();
        if(!epee::string_tools::hex_to_pod(local_args.back(), purchase_offer_id)){
            fail_msg_writer() << tr("Bad offer ID given!!!");
            return true;
        }

        offer_to_purchase = std::find_if(offers.begin(), offers.end(), [purchase_offer_id](safex::safex_offer offer){
            return offer.offer_id == purchase_offer_id;});

        if(offer_to_purchase!=offers.end())
            local_args.pop_back();
        else {
            fail_msg_writer() << tr("There is no offer with given id!!");
            return true;
        }

        cryptonote::tx_destination_entry de = AUTO_VAL_INIT(de);

        uint64_t sfx_price;
        bool res = calculate_sfx_price(*offer_to_purchase, sfx_price);

        uint64_t total_sfx_to_pay = quantity_to_purchase*sfx_price;

        de.amount = total_sfx_to_pay * 95  / 100;
        de.output_type = tx_out_type::out_cash;
        safex_network_fee += total_sfx_to_pay * 5  / 100;

        cryptonote::address_parse_info info = AUTO_VAL_INIT(info);
        cryptonote::tx_destination_entry de_purchase = AUTO_VAL_INIT(de_purchase);
        std::string destination_addr = m_wallet->get_subaddress_as_str({m_current_subaddress_account, 0});
        if (!cryptonote::get_account_address_from_str(info, m_wallet->nettype(), destination_addr))
        {
            fail_msg_writer() << tr("failed to parse address");
            return true;
        }
        //Purchase
        safex::create_purchase_data safex_purchase_output_data{purchase_offer_id,quantity_to_purchase,total_sfx_to_pay};
        blobdata blobdata = cryptonote::t_serializable_object_to_blob(safex_purchase_output_data);
        de_purchase = tx_destination_entry{0, offer_to_purchase->seller_address, false, tx_out_type::out_safex_purchase, blobdata};
        dsts.push_back(de_purchase);

        //Feedback token
        safex::create_feedback_token_data safex_feedback_token_output_data;
        safex_feedback_token_output_data.offer_id = purchase_offer_id;
        cryptonote::tx_destination_entry de_feedback_token = AUTO_VAL_INIT(de_feedback_token);
        de_feedback_token = create_safex_feedback_token_destination(info.address, safex_feedback_token_output_data);
        dsts.push_back(de_feedback_token);

        de.addr = offer_to_purchase->seller_address;

        dsts.push_back(de);
    }
    else if (command_type == CommandType::TransferFeedback)
    {
        crypto::hash purchase_offer_id{};
        uint64_t stars_given;
        std::string comment;

        cryptonote::address_parse_info info = AUTO_VAL_INIT(info);
        std::string destination_addr = m_wallet->get_subaddress_as_str({m_current_subaddress_account, 0});
        if (!cryptonote::get_account_address_from_str(info, m_wallet->nettype(), destination_addr))
        {
            fail_msg_writer() << tr("failed to parse address");
            return true;
        }

        if(!epee::string_tools::hex_to_pod(local_args.front(), purchase_offer_id)){
            fail_msg_writer() << tr("Bad offer ID given!!!");
            return true;
        }
        local_args.erase(local_args.begin());

        if (!epee::string_tools::get_xtype_from_string(stars_given, local_args.front())){
            fail_msg_writer() << tr("Bad stars rating format given!!!");
            return true;
        }

        if(stars_given > 3){
          fail_msg_writer() << tr("Feedback rating can be from 0 to 3");
          return true;
        }

        std::ostringstream comment_ostr;
        std::copy(local_args.begin() + 1, local_args.end(), ostream_iterator<string>(comment_ostr, " "));
        comment = comment_ostr.str();

        safex::safex_feedback sfx_feedback{stars_given,comment,purchase_offer_id};


        cryptonote::tx_destination_entry de = AUTO_VAL_INIT(de);

        tx_destination_entry de_feedback = create_safex_feedback_destination(info.address, sfx_feedback);
        dsts.push_back(de_feedback);
    }
    else if(command_type == CommandType::TransferCreatePricePeg || command_type == CommandType::TransferUpdatePricePeg){
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

      if (command_type == CommandType::TransferCreatePricePeg) {

        std::string price_peg_title = local_args[1];
        std::string price_peg_currency = local_args[2];
        uint64_t rate;

        if(price_peg_currency.length() > SAFEX_PRICE_PEG_CURRENCY_MAX_SIZE){
          fail_msg_writer() << tr("Currency must be equal or less than ") << SAFEX_PRICE_PEG_CURRENCY_MAX_SIZE<<tr(" characters!");
          return true;
        }

        try {
          rate = stod(local_args[3])*COIN;
        }
        catch(std::invalid_argument& e){
          fail_msg_writer() << tr("One of the arguments is missing. Please check needed arguments again.");
          return true;
        }
        std::ostringstream pricepeg_ostr;
        std::copy(local_args.begin() + 4, local_args.end(), ostream_iterator<string>(pricepeg_ostr, " "));
        std::string description = pricepeg_ostr.str();

        safex::safex_price_peg sfx_price_peg{price_peg_title,sfx_username,price_peg_currency,description,rate};

        cryptonote::tx_destination_entry de_price_peg = create_safex_price_peg_destination(info.address, sfx_price_peg);
        dsts.push_back(de_price_peg);

      } else if (command_type == CommandType::TransferUpdatePricePeg) {

        crypto::hash price_peg_id_hash;
        epee::string_tools::hex_to_pod(local_args[1], price_peg_id_hash);

        std::string price_peg_title = local_args[2];
        std::string price_peg_currency = local_args[3];
        uint64_t rate;

        if(price_peg_currency.length() > SAFEX_PRICE_PEG_CURRENCY_MAX_SIZE){
          fail_msg_writer() << tr("Currency must be equal or less than ") << SAFEX_PRICE_PEG_CURRENCY_MAX_SIZE<<tr(" characters!");
          return true;
        }

        try {
          rate = stod(local_args[4])*COIN;
        }
        catch(std::invalid_argument& e){
          fail_msg_writer() << tr("One of the arguments is missing. Please check needed arguments again.");
          return true;
        }

        std::ostringstream pricepeg_ostr;
        std::copy(local_args.begin() + 5, local_args.end(), ostream_iterator<string>(pricepeg_ostr, " "));
        std::string description = pricepeg_ostr.str();
        std::vector<uint8_t> description_arg{description.begin(),description.end()};

        safex::safex_price_peg sfx_price_peg{price_peg_title,sfx_username,price_peg_currency,description_arg,price_peg_id_hash,rate};

        cryptonote::tx_destination_entry de_price_peg_update = update_safex_price_peg_destination(info.address, sfx_price_peg);
        dsts.push_back(de_price_peg_update);

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

          uint64_t minimum_tokens = safex::get_minimum_token_stake_amount(m_wallet->nettype());

          if (value_amount < minimum_tokens)
          {
            fail_msg_writer() << tr("token amount must be at least. ") << print_money(minimum_tokens);
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

        dsts.push_back(de);
      }
    }

    // If its demo purchase, make special destination_entry for network fee.
    if(command_type == CommandType::TransferPurchase) {
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

        case CommandType::TransferPurchase:
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

        case CommandType::TransferFeedback:
          command = safex::command_t::create_feedback;
          break;

        case CommandType::TransferCreatePricePeg:
          command = safex::command_t::create_price_peg;
          break;

        case CommandType::TransferUpdatePricePeg:
          command = safex::command_t::update_price_peg;
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

  bool simple_wallet::safex_purchase(const std::vector<std::string>& args) {
      if (args.empty())
      {
          success_msg_writer() << tr("usage:\n"
                                     "  safex_purchase [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <offer_id> <quantity>\n");
          return true;
      }
    return create_command(CommandType::TransferPurchase, args);
  }

    bool simple_wallet::safex_feedback(const std::vector<std::string>& args) {
      if (args.empty())
      {
        // print all the possible feedbacks to give
        LOCK_IDLE_SCOPE();
        print_not_given_feedbacks();
        return true;
      }
        return create_command(CommandType::TransferFeedback, args);
    }

  bool simple_wallet::list_offers(const std::vector<std::string>& args) {


    std::vector<safex::safex_price_peg> sfx_price_pegs = m_wallet->get_safex_price_pegs();

    success_msg_writer() << tr(std::string(78,'#').c_str()) <<  tr(" Safex offers in the Blockchain ") << tr(std::string(77,'#').c_str());

    success_msg_writer() << boost::format("#%|=20|#%|=20|#%|=20|#%|=30|#%|=20|#%|=70|#")  % tr("Offer title") %  tr("Price") % tr("Quantity") % tr("Seller")  % tr("Description") %tr("Offer ID");
    success_msg_writer() << tr(std::string(1,'#').c_str()) <<  tr(std::string(185,'#').c_str()) << tr(std::string(1,'#').c_str());

    bool first = false;


    for (auto &offer: m_wallet->get_safex_offers()) {



      if(first)
        success_msg_writer() << boost::format("#%|=20|#%|=20|#%|=20|#%|=30|#%|=20|#%|=70|#")  % tr(std::string(20, '-').c_str()) %  tr(std::string(20, '-').c_str())
                                  % tr(std::string(20, '-').c_str()) % tr(std::string(30, '-').c_str()) % tr(std::string(20, '-').c_str()) %tr(std::string(70, '-').c_str());

      first = true;

      print_safex_offer(offer);
      }
    success_msg_writer() << tr(std::string(1,'#').c_str()) <<  tr(std::string(185,'#').c_str()) << tr(std::string(1,'#').c_str());

    return true;
  }

    bool simple_wallet::list_price_pegs(const std::vector<std::string>& args) {

      std::string currency = args.empty()?"":args[0];
      auto price_pegs = m_wallet->get_safex_price_pegs(currency);

      print_price_pegs(price_pegs);

      return true;
    }

    void simple_wallet::print_price_pegs(const std::vector<safex::safex_price_peg>& price_pegs){
      success_msg_writer() << tr(std::string(81,'#').c_str()) <<  tr(" Safex price pegs in the Blockchain ") << tr(std::string(80,'#').c_str());

      success_msg_writer() << boost::format("#%|=30|#%|=20|#%|=20|#%|=30|#%|=20|#%|=70|#")  % tr("Price peg title") %  tr("Currency") % tr("Rate")  % tr("Creator") %tr("Description") %tr("Price peg ID");
      success_msg_writer() << tr(std::string(1,'#').c_str()) <<  tr(std::string(195,'#').c_str()) << tr(std::string(1,'#').c_str());

      bool first = false;


      for (auto price_peg: price_pegs) {

        if(first)
          success_msg_writer() << boost::format("#%|=30|#%|=20|#%|=20|#%|=30|#%|=20|#%|=70|#")  % tr(std::string(30, '-').c_str()) %  tr(std::string(20, '-').c_str())
                                  % tr(std::string(20, '-').c_str()) % tr(std::string(30, '-').c_str()) % tr(std::string(20, '-').c_str()) %tr(std::string(70, '-').c_str());

        first = true;

        print_safex_price_peg(price_peg);
      }
      success_msg_writer() << tr(std::string(1,'#').c_str()) <<  tr(std::string(195,'#').c_str()) << tr(std::string(1,'#').c_str());
    }

    void simple_wallet::print_not_given_feedbacks(){
      success_msg_writer() << tr(std::string(20,'#').c_str()) <<  tr(" Safex feedbacks left to give for offers: ") << tr(std::string(20,'#').c_str());

      success_msg_writer() << boost::format("#%|=80|#")  % tr("Offer ID");
      success_msg_writer() << boost::format("#%|=80|#")  % std::string(80,'#');
      bool first = false;
      for (auto &offer_id: m_wallet->get_my_safex_feedbacks_to_give()) {
        if(first)
          success_msg_writer() << boost::format("#%|=80|#")  % std::string(80,'-');
        first = true;
        success_msg_writer() << boost::format("#%|=80|#")  % offer_id;
      }
      success_msg_writer() << boost::format("#%|=80|#")  % std::string(80,'#');
    }

    bool simple_wallet::list_ratings(const std::vector<std::string>& args) {

        crypto::hash offer_id;
        if(args.empty() || !epee::string_tools::hex_to_pod(args.front(), offer_id)) {
            fail_msg_writer() << tr("Bad offer ID given!!!");
            return true;
        }
      double avg_rating = 0;
      success_msg_writer() << tr(std::string(72,'#').c_str()) <<  tr(" Safex rating for offer ") << tr(std::string(73,'#').c_str());
      success_msg_writer() << tr(std::string(50,'#').c_str()) <<  boost::format("%|=68|") % tr(args.front().c_str()) << tr(std::string(51,'#').c_str());
      success_msg_writer() << boost::format("#%|=6|#%|=160|#") % tr("Rating") %tr("Comment");
      success_msg_writer() << tr(std::string(169,'#').c_str());
      auto ratings = m_wallet->get_safex_ratings(offer_id);
      bool first = false;
      for (auto &rating: ratings) {

        if(first)
          success_msg_writer() << boost::format("#%|=6|#%|=160|#") %  tr(std::string(6, '-').c_str()) % tr(std::string(160, '-').c_str());
        first = true;
        success_msg_writer() << boost::format("#%|=6|#%|=160|#") % rating.stars_given % rating.comment;
          avg_rating += rating.stars_given;
      }
      success_msg_writer() << tr(std::string(169,'#').c_str());

      success_msg_writer() << boost::format("#AVG rating for this offer is : %|=10|%|=126|#") % (ratings.size()==0?avg_rating:avg_rating/ratings.size()) %  tr(std::string(1,' ').c_str());
      success_msg_writer() << tr(std::string(169,'#').c_str());

      return true;
    }

  bool simple_wallet::attach_price_peg(safex::safex_offer& sfx_offer){
    std::string currency = input_line(
            tr("For what currency do you want to attach your offer? (leave blank to list all price pegs in the BC): "));
    auto price_pegs = m_wallet->get_safex_price_pegs(currency);
    if (price_pegs.empty()) {
      fail_msg_writer() << tr("No price peg for given currency found!");
      return true;
    }

    print_price_pegs(price_pegs);

    std::string price_peg_id_str = input_line(tr("Enter price peg ID to choose : "));

    bool found = false;
    crypto::hash price_peg_id;
    if(!epee::string_tools::hex_to_pod(price_peg_id_str, price_peg_id)){
      fail_msg_writer() << tr("Bad price peg ID given!!!");
      return false;
    }

    for (auto price_peg: price_pegs)
      if(price_peg.price_peg_id == price_peg_id){
        currency = price_peg.currency;
        found = true;
        break;
      }
    if(!found){
      fail_msg_writer() << tr("No price peg from list selected!");
      return false;
    }

    std::string prompt = "Enter price in "+currency+" : ";
    std::string price_str = input_line(tr(prompt.c_str()));
    uint64_t new_price = stold(price_str);
    new_price*=SAFEX_CASH_COIN;

    prompt = "Enter minimum SFX price : ";
    std::string min_price_str = input_line(tr(prompt.c_str()));
    uint64_t min_price = stold(min_price_str);
    min_price*=SAFEX_CASH_COIN;
    sfx_offer.set_price_peg(price_peg_id,new_price,min_price);

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
      success_msg_writer() << boost::format("%30s %20s") % print_money(pair.first) % print_money(pair.second);
    }
    return true;
  }

  void simple_wallet::print_safex_accounts()
  {
    success_msg_writer() << tr(std::string(49,'#').c_str()) <<  tr(" Safex accounts ") << tr(std::string(48,'#').c_str());
    success_msg_writer() << boost::format("#%|=30|#%|=80|#") % tr("Account Username") % tr("Account Data");
    success_msg_writer() << tr(std::string(113,'#').c_str());
    bool first = false;

    for (auto& acc: m_wallet->get_safex_accounts()) {
      if(first)
        success_msg_writer() << boost::format("#%|=30|#%|=80|#")  % tr(std::string(30, '-').c_str()) %  tr(std::string(80, '-').c_str());
      first=true;
      success_msg_writer() << boost::format("#%|=30|#%|=80|#") % acc.username % std::string(begin(acc.account_data), end(acc.account_data));
    }
    success_msg_writer() << tr(std::string(113,'#').c_str());

  }

    void simple_wallet::print_safex_offer(safex::safex_offer& offer){


      uint64_t sfx_price;
      bool res = calculate_sfx_price(offer,sfx_price);

      if(!res)
        return;

      auto size_desc = offer.description.size();

      uint64_t lines = size_desc / 20 + 1;

      auto desc = offer.description;

      uint64_t avaliable = size_desc > 20 ? 20: size_desc;

      for(uint64_t i = 0; i < lines; i++){
        if(i==lines/2)
          success_msg_writer() << boost::format("#%|=20|#%|=20|#%|=20|#%|=30|#%|=20|#%|=70|#") % offer.title % print_money(sfx_price) % offer.quantity % offer.seller %
                                  std::string(begin(desc), begin(desc)+avaliable) % offer.offer_id;
        else
          success_msg_writer() << boost::format("#%|=20|#%|=20|#%|=20|#%|=30|#%|=20|#%|=70|#") % " " % " " % " " % " " %
                                  std::string(begin(desc), begin(desc)+avaliable) % " ";
        desc = std::vector<uint8_t>(desc.begin()+avaliable,desc.end());
        size_desc = size_desc - avaliable;
        avaliable = size_desc > 20 ? 20: size_desc;
      }


    }

    void simple_wallet::print_safex_price_peg(safex::safex_price_peg& price_peg){


      auto size_desc = price_peg.description.size();

      uint64_t lines = size_desc / 20 + 1;

      auto desc = price_peg.description;

      uint64_t avaliable = size_desc > 20 ? 20: size_desc;

      for(uint64_t i = 0; i < lines; i++){
        if(i==lines/2)
          success_msg_writer() << boost::format("#%|=30|#%|=20|#%|=20|#%|=30|#%|=20|#%|=70|#") % price_peg.title % price_peg.currency % print_money(price_peg.rate)% price_peg.creator %
                                  std::string(begin(desc), begin(desc)+avaliable) % price_peg.price_peg_id;
        else
          success_msg_writer() << boost::format("#%|=30|#%|=20|#%|=20|#%|=30|#%|=20|#%|=70|#") % " " % " " % " " % " " %
                                  std::string(begin(desc), begin(desc)+avaliable) % " ";
        desc = std::vector<uint8_t>(desc.begin()+avaliable,desc.end());
        size_desc = size_desc - avaliable;
        avaliable = size_desc > 20 ? 20: size_desc;
      }


    }


  void simple_wallet::print_my_safex_offer(safex::safex_offer& offer, std::vector<safex::safex_price_peg>& price_pegs){

    auto size_desc = offer.description.size();

    uint64_t lines = size_desc / 20 + 1;

    auto desc = offer.description;

    uint64_t avaliable = size_desc > 20 ? 20: size_desc;

    auto price_peg_id = offer.price_peg_id;

    auto it = std::find_if(price_pegs.begin(), price_pegs.end(), [price_peg_id](const safex::safex_price_peg &sfx_price_peg) { return price_peg_id == sfx_price_peg.price_peg_id; });

    std::string currency = "SFX";

    if(it!=price_pegs.end())
      currency = it->currency;

    for(uint64_t i = 0; i < lines; i++){
      if(i==lines/2)
        success_msg_writer() << boost::format("#%|=20|#%|=20|#%|=20|#%|=20|#%|=30|#%|=69|#%|=20|#%|=20|#%|=70|#%|=20|#") % offer.title % print_money(offer.price) % currency % offer.quantity % offer.seller % (offer.price_peg_used?epee::string_tools::pod_to_hex(offer.price_peg_id):"N/A") % print_money(offer.min_sfx_price) %
                                std::string(begin(desc), begin(desc)+avaliable) % offer.offer_id % (offer.active?"True":"False");
      else
        success_msg_writer() << boost::format("#%|=20|#%|=20|#%|=20|#%|=20|#%|=30|#%|=69|#%|=20|#%|=20|#%|=70|#%|=20|#") % " " % " " % " " % " " % " " % " " % " " %
                                std::string(begin(desc), begin(desc)+avaliable) % " " % " ";
      desc = std::vector<uint8_t>(desc.begin()+avaliable,desc.end());
      size_desc = size_desc - avaliable;
      avaliable = size_desc > 20 ? 20: size_desc;
    }


  }


  void simple_wallet::print_my_safex_offers() {
    success_msg_writer() << tr(std::string(153,'#').c_str()) <<  tr(" Safex offers ") << tr(std::string(153,'#').c_str());
    success_msg_writer() << boost::format("#%|=20|#%|=20|#%|=20|#%|=20|#%|=30|#%|=69|#%|=20|#%|=20|#%|=70|#%|=20|#")  % tr("Offer title") %  tr("Price") %  tr("Currency") % tr("Quantity") % tr("Seller") % tr("Price peg") % tr("Minimum SFX price") % tr("Description") %tr("Offer ID") %tr("Active");
    success_msg_writer() << tr(std::string(320,'#').c_str());

    bool first = false;

    auto price_pegs = m_wallet->get_safex_price_pegs("");

    for (auto &offer: m_wallet->get_my_safex_offers()) {

      if(first)
        success_msg_writer() << boost::format("#%|=20|#%|=20|#%|=20|#%|=20|#%|=30|#%|=69|#%|=20|#%|=20|#%|=70|#%|=20|#")  % tr(std::string(20, '-').c_str()) %  tr(std::string(20, '-').c_str())  % tr(std::string(20, '-').c_str())
                                              % tr(std::string(20, '-').c_str()) % tr(std::string(30, '-').c_str()) % tr(std::string(69, '-').c_str())
                                              % tr(std::string(20, '-').c_str())  % tr(std::string(20, '-').c_str()) %tr(std::string(70, '-').c_str()) %tr(std::string(20,'-').c_str());

      first = true;
      print_my_safex_offer(offer, price_pegs);

    }
    success_msg_writer() << tr(std::string(320,'#').c_str()) ;

  }

  void simple_wallet::print_my_safex_price_pegs() {
    success_msg_writer() << tr(std::string(104,'#').c_str()) <<  tr(" Safex price pegs ") << tr(std::string(104,'#').c_str());
    success_msg_writer() << boost::format("#%|=20|#%|=20|#%|=20|#%|=30|#%|=60|#%|=69|#") % "Price peg title" %  "Currency" % "Rate" % "Creator" % "Description" % "Price peg ID";
    success_msg_writer() << tr(std::string(1,'#').c_str()) <<  tr(std::string(224,'#').c_str()) << tr(std::string(1,'#').c_str());

    bool first = false;

    for(auto price_peg: m_wallet->get_my_safex_price_pegs()) {

      if(first)
        success_msg_writer() << boost::format("#%|=20|#%|=20|#%|=20|#%|=30|#%|=60|#%|=69|#")  % tr(std::string(20, '-').c_str()) %  tr(std::string(20, '-').c_str()) % tr(std::string(20, '-').c_str()) % tr(std::string(30, '-').c_str()) % tr(std::string(60, '-').c_str()) %tr(std::string(69, '-').c_str());

      first = true;

      success_msg_writer() << boost::format("#%|=20|#%|=20|#%|=20|#%|=30|#%|=60|#%|=69|#") % price_peg.title % price_peg.currency %
                   print_money(price_peg.rate) % price_peg.creator %
                   std::string(begin(price_peg.description), end(price_peg.description)) % price_peg.price_peg_id;

    }
    success_msg_writer() << tr(std::string(226,'#').c_str());

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
      if (local_args.size() < 2){
        fail_msg_writer() << tr("usage: safex_account new <account_username> <account_data>");
        return true;
      }
      const std::string &username = local_args[0];

      if(m_wallet->safex_account_exists(username)) {
        fail_msg_writer() << tr("safex account username already exists in the Blockchain");
        return true;
      }

      for(auto ch: username){
        if (!(std::islower(ch) || std::isdigit(ch)) && ch!='_' && ch!='-') {
          fail_msg_writer() << tr("safex account username can only have lowercase letters, _ and -");
          return true;
        }
      }


      std::ostringstream accdata_ostr;
      std::copy(local_args.begin() + 1, local_args.end(), ostream_iterator<string>(accdata_ostr, " "));
      const std::string accdata_str = accdata_ostr.str();
      std::vector<uint8_t> accdata(accdata_str.begin(), accdata_str.end()-1);
      if (accdata.size() == 0) {
        fail_msg_writer() << tr("failed to parse account data");
        return true;
      }

      if (m_wallet->generate_safex_account(username, accdata)) {
        save_safex({});
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
        save_safex({});
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
        //   safex_offer create [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <account_username> <offer_name> <offer_price> <offer_quantity> <offer_description>
        //   safex_offer edit [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <account_username> <offer_id> <offer_name> <offer_price> <offer_quantity> <active_status(1,0)> <offer_description>
        if (args.empty())
        {
            // print all the existing offers
            LOCK_IDLE_SCOPE();
            print_my_safex_offers();
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
        else if (command == "edit")
        {
            return create_command(CommandType::TransferEditOffer, local_args);
        }
        else
        {
            success_msg_writer() << tr("usage:\n"
                                       "  safex_offer\n"
                                       "  safex_offer create [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <account_username> <offer_name> <offer_price> <offer_quantity> <offer_description>\n"
                                       "  safex_offer edit [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <account_username> <offer_id> <offer_name> <offer_price> <offer_quantity> <active_status(1,0)> <offer_description>");

        }
        return true;
  }

    bool simple_wallet::safex_price_peg(const std::vector<std::string> &args){
      //   Usage:
      //  safex_price_peg
      //  safex_price_peg create [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <account_username> <price_peg_title> <price_peg_currency> <price_peg_rate> <price_peg_description>
      //  safex_price_peg update [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <account_username> <price_peg_id> <price_peg_title> <price_peg_currency> <price_peg_rate> <price_peg_description>
      if (args.empty())
      {
        // print all the existing price pegs
        LOCK_IDLE_SCOPE();
        print_my_safex_price_pegs();
        return true;
      }

      std::vector<std::string> local_args = args;
      std::string command = local_args[0];
      local_args.erase(local_args.begin());
      if (command == "create")
      {
        // create a new safex price peg transaction
        return create_command(CommandType::TransferCreatePricePeg, local_args);
      }
      else if (command == "update")
      {
        return create_command(CommandType::TransferUpdatePricePeg, local_args);
      }
      else
      {
        success_msg_writer() << tr("usage:\n"
                                   "  safex_price_peg\n"
                                   "  safex_price_peg create [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <account_username> <price_peg_title> <price_peg_currency> <price_peg_rate> <price_peg_description>\n"
                                   "  safex_price_peg update [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <account_username> <price_peg_id> <price_peg_title> <price_peg_currency> <price_peg_rate> <price_peg_description>");

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
        safex::safex_offer sfx_offer{std::string{offer.title.begin(),offer.title.end()},offer.quantity,offer.price,offer.description,offer.offer_id,
                                      std::string{offer.seller.begin(),offer.seller.end()},offer.active,offer.seller_address,offer.price_peg_used,offer.price_peg_id,offer.min_sfx_price};

        m_wallet->add_safex_offer(sfx_offer);
        message_writer(console_color_green, false) << "\r" <<
                                                   tr("Height ") << height << ", " <<
                                                   tr("txid ") << txid << ", " <<
                                                   tr("Updated for account, username: ") << sfx_offer.seller <<
                                                   tr("Offer title: ") << sfx_offer.title << " received, " <<
                                                   tr("idx ") << subaddr_index;
    } else if (txout.output_type == static_cast<uint8_t>(tx_out_type::out_safex_offer_update)){
        safex::edit_offer_data offer;
        const cryptonote::blobdata offblob(std::begin(txout.data), std::end(txout.data));
        cryptonote::parse_and_validate_from_blob(offblob, offer);
        safex::safex_offer sfx_offer{std::string{offer.title.begin(),offer.title.end()},offer.quantity,offer.price,
                                     offer.description,offer.offer_id,std::string{offer.seller.begin(),offer.seller.end()}};
        sfx_offer.active = offer.active;

        m_wallet->update_safex_offer(sfx_offer);

    } else if (txout.output_type == static_cast<uint8_t>(tx_out_type::out_safex_purchase)){
        safex::create_purchase_data purchase_data;
        const cryptonote::blobdata offblob(std::begin(txout.data), std::end(txout.data));
        cryptonote::parse_and_validate_from_blob(offblob, purchase_data);

        safex::safex_offer my_offer = m_wallet->get_my_safex_offer(purchase_data.offer_id);

        message_writer(console_color_blue, false) << "\r" <<
                                                  tr("Height ") << height << ", " <<
                                                  tr("txid ") << txid << ", " <<
                                                  tr("Updated for account, username: ") << my_offer.seller <<
                                                  tr("Purchased offer: ") << my_offer.title << " received, " <<
                                                  tr("Quantity purchased: ") << purchase_data.quantity <<
                                                  tr("idx ") << subaddr_index;
        m_wallet->update_safex_offer(purchase_data);

    } else if (txout.output_type == static_cast<uint8_t>(tx_out_type::out_safex_feedback_token)){
        safex::create_feedback_token_data feedback_token;
        const cryptonote::blobdata offblob(std::begin(txout.data), std::end(txout.data));
        cryptonote::parse_and_validate_from_blob(offblob, feedback_token);
        message_writer(console_color_blue, false) << "\r" <<
                                          tr("Height ") << height << ", " <<
                                          tr("txid ") << txid << ", " <<
                                          tr("Feedback token received for offer: ") << feedback_token.offer_id << " received, " <<
                                          tr("idx ") << subaddr_index;
        m_wallet->add_safex_feedback_token(feedback_token);

    } else if (txout.output_type == static_cast<uint8_t>(tx_out_type::out_safex_feedback)){
        safex::create_feedback_data feedback;
        const cryptonote::blobdata offblob(std::begin(txout.data), std::end(txout.data));
        cryptonote::parse_and_validate_from_blob(offblob, feedback);
        std::string comment{feedback.comment.begin(),feedback.comment.end()};
        message_writer(console_color_blue, false) << "\r" <<
                                                  tr("Height ") << height << ", " <<
                                                  tr("txid ") << txid << ", " <<
                                                  tr("Feedback sent received for offer: ") << feedback.offer_id << " received, " <<
                                                  tr("Stars given: ") << feedback.stars_given <<
                                                  tr("Comment given: ") << comment <<
                                                  tr("idx ") << subaddr_index;
        m_wallet->remove_safex_feedback_token(feedback.offer_id);

    } else if (txout.output_type == static_cast<uint8_t>(tx_out_type::out_safex_price_peg)){
      safex::create_price_peg_data price_peg;
      const cryptonote::blobdata pricepeggblob(std::begin(txout.data), std::end(txout.data));
      cryptonote::parse_and_validate_from_blob(pricepeggblob, price_peg);
      std::string creator{price_peg.creator.begin(),price_peg.creator.end()};
      std::string title{price_peg.title.begin(),price_peg.title.end()};
      std::string currency{price_peg.currency.begin(),price_peg.currency.end()};
      message_writer(console_color_blue, false) << "\r" <<
                                                tr("Height ") << height << ", " <<
                                                tr("txid ") << txid << ", " <<
                                                tr("Price peg creation for account: ") << creator << " received, " <<
                                                tr("Price peg ID: ") << price_peg.price_peg_id <<
                                                tr("Price peg rate: ") << price_peg.rate <<
                                                tr("Price peg currency: ") << currency <<
                                                tr("idx ") << subaddr_index;

      safex::safex_price_peg sfx_price_peg{title,creator,currency,price_peg.description,price_peg.price_peg_id,price_peg.rate};

      m_wallet->add_safex_price_peg(sfx_price_peg);

    } else if (txout.output_type == static_cast<uint8_t>(tx_out_type::out_safex_price_peg_update)){
      safex::update_price_peg_data price_peg;
      const cryptonote::blobdata pricepeggblob(std::begin(txout.data), std::end(txout.data));
      cryptonote::parse_and_validate_from_blob(pricepeggblob, price_peg);
      std::string creator{price_peg.creator.begin(),price_peg.creator.end()};
      std::string title{price_peg.title.begin(),price_peg.title.end()};
      std::string currency{price_peg.currency.begin(),price_peg.currency.end()};
      message_writer(console_color_blue, false) << "\r" <<
                                                tr("Height ") << height << ", " <<
                                                tr("txid ") << txid << ", " <<
                                                tr("Price peg update for account: ") << creator << " received, " <<
                                                tr("Price peg ID: ") << price_peg.price_peg_id <<
                                                tr("Price peg rate: ") << price_peg.rate <<
                                                tr("Price peg currency: ") << currency <<
                                                tr("idx ") << subaddr_index;

      safex::safex_price_peg sfx_price_peg{title,creator,currency,price_peg.description,price_peg.price_peg_id,price_peg.rate};

      m_wallet->update_safex_price_peg(sfx_price_peg);

    }



      if (m_auto_refresh_refreshing)
      m_cmd_binder.print_prompt();
    else
      m_refresh_progress_reporter.update(height, true);
  }
//----------------------------------------------------------------------------------------------------

}
