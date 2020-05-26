//
// Created by amarko on 4.3.19..
//

#include "cryptonote_config.h"
#include "command.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "cryptonote_core/blockchain.h"


#include "fee_distribution.h"


#undef SAFEX_DEFAULT_LOG_CATEGORY
#define SAFEX_DEFAULT_LOG_CATEGORY "safex"

namespace safex
{


  token_stake_result* token_stake::execute(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
  {

    execution_status result = validate(blokchainDB, txin);
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES(result == execution_status::ok, "Failed to validate token stake command", this->get_command_type());

    token_stake_result *cr = new token_stake_result{};
    cr->token_amount = txin.token_amount;
    cr->block_number = blokchainDB.height();
    cr->valid = true;
    cr->status = execution_status::ok;

    MINFO("Block height:" << cr->block_number << " interval:" << calculate_interval_for_height(blokchainDB.height(), blokchainDB.get_net_type()) << " stake tokens:" << cr->token_amount);

    return cr;
  }

  execution_status token_stake::validate(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
  {
    execution_status result = execution_status::ok;

    //per input execution, one input could be less than SAFEX_MINIMUM_TOKEN_STAKE_AMOUNT, all inputs must be SAFEX_MINIMUM_TOKEN_STAKE_AMOUNT
    if(!tools::is_whole_token_amount(this->get_staked_token_amount()))
        result = execution_status::error_wrong_input_params;
    if(!(txin.token_amount == this->get_staked_token_amount()))
        result = execution_status::error_wrong_input_params;

    return result;
  }

  token_unstake_result* token_unstake::execute(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
  {

    execution_status result = validate(blokchainDB, txin);
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES(result == execution_status::ok, "Failed to validate token unstake command", this->get_command_type());


    token_unstake_result *cr = new token_unstake_result{};
    cr->token_amount = txin.token_amount;
    cr->block_number = blokchainDB.height();

    uint64_t locked_token_output_index = txin.key_offsets[0];
    cr->interest = calculate_token_interest(locked_token_output_index, cr->block_number, cr->token_amount);
    cr->valid = true;
    cr->status = execution_status::ok;

    MINFO("Block height:" << cr->block_number << " interval:" << calculate_interval_for_height(blokchainDB.height(), blokchainDB.get_net_type()) << " unstake tokens:" << cr->token_amount);

    return cr;
  }

  execution_status token_unstake::validate(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
  {

    execution_status result = execution_status::ok;

    if(!(txin.key_offsets.size() == 1))
        result = execution_status::error_wrong_input_params;

    if(!(txin.key_offsets[0] == this->get_staked_token_output_index()))
        result = execution_status::error_wrong_input_params;

    uint64_t staked_token_index = this->get_staked_token_output_index();
    const cryptonote::output_advanced_data_t od = blokchainDB.get_output_advanced_data(cryptonote::tx_out_type::out_staked_token, staked_token_index);


    auto toi = blokchainDB.get_output_tx_and_index_from_global(od.output_id);
    auto tx = blokchainDB.get_tx(toi.first);
    bool output_found = false;
    for(auto out: tx.vout)
      if(out.target.type() == typeid(cryptonote::txout_to_script) && get_tx_out_type(out.target) == cryptonote::tx_out_type::out_staked_token)
        if(out.token_amount == txin.token_amount)
          output_found = true;

    uint64_t expected_interest = blokchainDB.calculate_staked_token_interest_for_output(txin, blokchainDB.height());

    if(txin.amount > expected_interest)
        result = execution_status::error_unstake_token_network_fee_not_matching;

    if(!output_found)
        result = execution_status::error_unstake_token_output_not_found;
    if(od.height + get_safex_minumum_token_lock_period(blokchainDB.get_net_type()) > blokchainDB.height())
        result = execution_status::error_unstake_token_minimum_period;

    return result;
  }


  token_collect_result* token_collect::execute(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
  {

    execution_status result = validate(blokchainDB, txin);
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES(result == execution_status::ok, "Failed to validate token collect command", this->get_command_type());


    token_collect_result *cr = new token_collect_result{};
    cr->token_amount = txin.token_amount;
    cr->block_number = blokchainDB.height();

    uint64_t locked_token_output_index = txin.key_offsets[0];
    cr->interest = calculate_token_interest(locked_token_output_index, cr->block_number, cr->token_amount);
    cr->valid = true;
    cr->status = execution_status::ok;

    return cr;
  }

  execution_status token_collect::validate(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
  {

    //TODO: GRKI Do not allow token_collect for now
    execution_status result = execution_status::invalid;

    //todo Get data about locked token output from database using its index
    //todo check if db output amount is same as txin amount
    //todo check if minimum amount of time is fulfilled

    return result;
  }


  donate_fee_result* donate_fee::execute(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
  {

    execution_status result = validate(blokchainDB, txin);
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES(result == execution_status::ok, "Failed to validate donate fee command", this->get_command_type());

    donate_fee_result *cr = new donate_fee_result{};
    cr->amount = txin.amount;
    cr->valid = true;
    cr->status = execution_status::ok;

    return cr;
  };

  execution_status donate_fee::validate(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
  {

    execution_status result = execution_status::ok;

    if(!(txin.amount > 0))
        return execution_status::error_wrong_input_params;
    if(txin.token_amount != 0)
        return execution_status::error_wrong_input_params;

    return result;
  };

  simple_purchase_result* simple_purchase::execute(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
  {

    execution_status result = validate(blokchainDB, txin);
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES(result == execution_status::ok, "Failed to validate simple purchase command", this->get_command_type());

    simple_purchase_result *cr = new simple_purchase_result{};
    cr->offer_id = this->offer_id;
    cr->quantity = this->quantity;
    cr->price = this->price;
    cr->shipping = this->shipping;
    cr->valid = true;
    cr->status = execution_status::ok;

    return cr;
  };

  execution_status simple_purchase::validate(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
  {
    std::unique_ptr<safex::simple_purchase> cmd = safex::safex_command_serializer::parse_safex_command<safex::simple_purchase>(txin.script);

    execution_status result = execution_status::ok;

    safex::safex_offer sfx_offer{};
    if (!blokchainDB.get_offer(cmd->offer_id,sfx_offer)) {
        return execution_status::error_offer_non_existant;
    }

    if(!sfx_offer.active)
        return execution_status::error_purchase_offer_not_active;

    if(sfx_offer.quantity < cmd->quantity)
        return execution_status::error_purchase_out_of_stock;

    if(cmd->quantity==0)
      return execution_status::error_wrong_input_params;

    uint64_t sfx_price = sfx_offer.min_sfx_price;

    if(sfx_offer.price_peg_used){
      safex::safex_price_peg sfx_price_peg;
      if (!blokchainDB.get_safex_price_peg(sfx_offer.price_peg_id,sfx_price_peg)) {
        return execution_status::error_offer_price_peg_not_existant;
      }
      std::string rate_str = cryptonote::print_money(sfx_price_peg.rate);
      double rate = stod(rate_str);

      std::string price_str = cryptonote::print_money(sfx_offer.price);
      double price_dbl = stod(price_str);

      uint64_t pegged_price = (price_dbl*rate)*SAFEX_CASH_COIN;

      if(sfx_price < pegged_price)
        sfx_price = pegged_price;
    }

    if(sfx_price * cmd->quantity > cmd->price)
        return execution_status::error_purchase_not_enough_funds;

    if(!(txin.amount > 0))
        return execution_status::error_wrong_input_params;
    if(txin.token_amount != 0)
        return execution_status::error_wrong_input_params;

    return result;
  };

  create_account_result* create_account::execute(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
  {

    execution_status result = validate(blokchainDB, txin);
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES(result == execution_status::ok, "Failed to validate create account command", this->get_command_type());

    create_account_result *cr = new create_account_result{this->username, this->pkey, this->account_data};
    cr->valid = true;
    cr->status = execution_status::ok;

    return cr;
  };

  execution_status create_account::validate(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
  {
    if(txin.token_amount == 0)
        return execution_status::error_wrong_input_params;

    std::unique_ptr<safex::create_account> cmd = safex::safex_command_serializer::parse_safex_command<safex::create_account>(txin.script);

    for (auto ch: cmd->get_username()) {
      if (!(std::islower(ch) || std::isdigit(ch)) && ch!='_' && ch!='-') {
        return execution_status::error_invalid_account_name;
      }
    }

    std::vector<uint8_t>  dummy{};
    if (blokchainDB.get_account_data(cmd->get_username(), dummy)) {
      return execution_status::error_account_already_exists;
    }

    if (cmd->get_username().length() > SAFEX_ACCOUNT_USERNAME_MAX_SIZE)
    {
      return execution_status::error_account_data_too_big;
    }

    if (cmd->get_account_data().size() > SAFEX_ACCOUNT_DATA_MAX_SIZE)
    {
      return execution_status::error_account_data_too_big;
    }

    return execution_status::ok;
  };

  edit_account_result* edit_account::execute(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
  {

    execution_status result = validate(blokchainDB, txin);
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES(result == execution_status::ok, "Failed to validate edit account command", this->get_command_type());

    edit_account_result *cr = new edit_account_result{this->username, this->new_account_data};
    cr->valid = true;
    cr->status = execution_status::ok;

    return cr;
  };

    execution_status edit_account::validate(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
    {

        execution_status result = execution_status::ok;
        std::unique_ptr<safex::edit_account> cmd = safex::safex_command_serializer::parse_safex_command<safex::edit_account>(txin.script);


        for (auto ch: cmd->get_username()) {
          if (!(std::islower(ch) || std::isdigit(ch)) && ch!='_' && ch!='-') {
                result = execution_status::error_invalid_account_name;
            }
        }

        std::vector<uint8_t>  dummy{};
        if (!blokchainDB.get_account_data(cmd->get_username(), dummy)) {
            result = execution_status::error_account_non_existant;
        }

        if (cmd->get_username().length() > SAFEX_ACCOUNT_USERNAME_MAX_SIZE)
        {
          return execution_status::error_account_data_too_big;
        }

        if (cmd->get_new_account_data().size() > SAFEX_ACCOUNT_DATA_MAX_SIZE)
        {
          return execution_status::error_account_data_too_big;
        }

        return result;
    };


    create_offer_result* create_offer::execute(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
    {

        execution_status result = validate(blokchainDB, txin);
        SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES(result == execution_status::ok, "Failed to validate create offer command", this->get_command_type());

        create_offer_result *cr = new create_offer_result{this->offer_id,this->seller,this->price,this->quantity,this->active};
        cr->valid = true;
        cr->status = execution_status::ok;

        return cr;
    };

    execution_status create_offer::validate(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
    {

        execution_status result = execution_status::ok;
        std::unique_ptr<safex::create_offer> cmd = safex::safex_command_serializer::parse_safex_command<safex::create_offer>(txin.script);

        std::vector<uint8_t>  dummy{};
        if (!blokchainDB.get_account_data(cmd->get_seller(), dummy)) {
            result = execution_status::error_account_non_existant;
        }

        if(cmd->get_min_sfx_price() < SAFEX_OFFER_MINIMUM_PRICE){
            result = execution_status::error_offer_price_too_small;
        }

        if(cmd->get_price() > MONEY_SUPPLY) {
          result = execution_status::error_offer_price_too_big;
        }

        if (cmd->get_title().size() > SAFEX_OFFER_NAME_MAX_SIZE)
        {
          MERROR("Offer title is bigger than max allowed " + std::to_string(SAFEX_OFFER_NAME_MAX_SIZE));
          result = execution_status::error_offer_data_too_big;
        }

        if (cmd->get_description().size() > SAFEX_OFFER_DATA_MAX_SIZE)
        {
          MERROR("Offer data is bigger than max allowed " + std::to_string(SAFEX_OFFER_DATA_MAX_SIZE));
          result = execution_status::error_offer_data_too_big;
        }

        safex::safex_price_peg sfx_price_peg{};
        if(cmd->get_price_peg_used() && !blokchainDB.get_safex_price_peg(cmd->get_price_peg_id(),sfx_price_peg)){
          result = execution_status::error_offer_price_peg_not_existant;
        }

        return result;
    };

    edit_offer_result* edit_offer::execute(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
    {
        execution_status result = validate(blokchainDB, txin);
        SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES(result == execution_status::ok, "Failed to validate edit offer command", this->get_command_type());

        edit_offer_result *cr = new edit_offer_result{this->offer_id,this->seller,this->price,this->quantity,this->active};
        cr->valid = true;
        cr->status = execution_status::ok;

        return cr;
    };

    execution_status edit_offer::validate(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
    {

        execution_status result = execution_status::ok;
        std::unique_ptr<safex::edit_offer> cmd = safex::safex_command_serializer::parse_safex_command<safex::edit_offer>(txin.script);

        std::vector<uint8_t>  dummy{};
        if (!blokchainDB.get_account_data(cmd->get_seller(), dummy)) {
            result = execution_status::error_account_non_existant;
        }

        if(cmd->get_min_sfx_price() < SAFEX_OFFER_MINIMUM_PRICE){
            result = execution_status::error_offer_price_too_small;
        }

        if(cmd->get_price() > MONEY_SUPPLY) {
          result = execution_status::error_offer_price_too_big;
        }

        if (cmd->get_title().size() > SAFEX_OFFER_NAME_MAX_SIZE)
        {
          MERROR("Offer title is bigger than max allowed " + std::to_string(SAFEX_OFFER_NAME_MAX_SIZE));
          result = execution_status::error_offer_data_too_big;
        }

        if (cmd->get_description().size() > SAFEX_OFFER_DATA_MAX_SIZE)
        {
          MERROR("Offer data is bigger than max allowed " + std::to_string(SAFEX_OFFER_DATA_MAX_SIZE));
          result = execution_status::error_offer_data_too_big;
        }

        safex::safex_price_peg sfx_price_peg{};
        if(cmd->get_price_peg_used() && !blokchainDB.get_safex_price_peg(cmd->get_price_peg_id(),sfx_price_peg)){
          result = execution_status::error_offer_price_peg_not_existant;
        }

        safex::safex_offer sfx_dummy{};
        if (!blokchainDB.get_offer(cmd->get_offerid(), sfx_dummy)) {
            result = execution_status::error_offer_non_existant;
        }
        return result;
    };

    create_feedback_result* create_feedback::execute(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
    {
        execution_status result = validate(blokchainDB, txin);
        SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES(result == execution_status::ok, "Failed to validate create feedback command", this->get_command_type());

        create_feedback_result *cr = new create_feedback_result{this->offer_id,this->comment,this->stars_given};
        cr->valid = true;
        cr->status = execution_status::ok;

        return cr;
    };

    execution_status create_feedback::validate(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
    {

        execution_status result = execution_status::ok;
        std::unique_ptr<safex::create_feedback> cmd = safex::safex_command_serializer::parse_safex_command<safex::create_feedback>(txin.script);

        safex::safex_offer sfx_dummy{};
        if (!blokchainDB.get_offer(cmd->get_offerid(), sfx_dummy)) {
            result = execution_status::error_offer_non_existant;
        }

        uint64_t rating_given = cmd->get_stars_given();

        if(rating_given > 3 )
          result = execution_status::error_feedback_invalid_rating;

        if(cmd->get_comment().size() > SAFEX_FEEDBACK_DATA_MAX_SIZE)
          result = execution_status::error_feedback_data_too_big;

        return result;
    };

    create_price_peg_result* create_price_peg::execute(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
    {

      execution_status result = validate(blokchainDB, txin);
      SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES(result == execution_status::ok, "Failed to validate create price peg command", this->get_command_type());

      create_price_peg_result *cr = new create_price_peg_result{this->price_peg_id,this->title,this->creator,this->description,this->currency,this->rate};
      cr->valid = true;
      cr->status = execution_status::ok;

      return cr;
    };

    execution_status create_price_peg::validate(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
    {

      execution_status result = execution_status::ok;
      std::unique_ptr<safex::create_price_peg> cmd = safex::safex_command_serializer::parse_safex_command<safex::create_price_peg>(txin.script);

      if (cmd->get_title().size() > SAFEX_PRICE_PEG_NAME_MAX_SIZE)
      {
        result = execution_status::error_price_peg_data_too_big;
      }

      if (cmd->get_currency().size() > SAFEX_PRICE_PEG_CURRENCY_MAX_SIZE)
      {
        result = execution_status::error_price_peg_bad_currency_format;
      }

      for (auto ch: cmd->get_currency()) {
        if (!std::isupper(ch)) {
          result = execution_status::error_price_peg_bad_currency_format;
        }
      }

      if(cmd->get_rate() == 0)
      {
          result = execution_status::error_price_peg_rate_zero;
      }

      //check price peg data size
      if (cmd->get_description().size() > SAFEX_PRICE_PEG_DATA_MAX_SIZE)
      {
        result = execution_status::error_price_peg_data_too_big;
      }

      return result;
    };

    update_price_peg_result* update_price_peg::execute(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
    {

      execution_status result = validate(blokchainDB, txin);
      SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES(result == execution_status::ok, "Failed to validate update price peg command", this->get_command_type());

      update_price_peg_result *cr = new update_price_peg_result{this->price_peg_id,this->rate};
      cr->valid = true;
      cr->status = execution_status::ok;

      return cr;
    };

    execution_status update_price_peg::validate(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
    {

      execution_status result = execution_status::ok;
      std::unique_ptr<safex::update_price_peg> cmd = safex::safex_command_serializer::parse_safex_command<safex::update_price_peg>(txin.script);


      if(cmd->get_rate() == 0)
      {
          result = execution_status::error_price_peg_rate_zero;
      }

      safex::safex_price_peg sfx_dummy{};
      if (!blokchainDB.get_safex_price_peg(cmd->get_price_peg_id(), sfx_dummy)) {
        result = execution_status::error_price_peg_not_existant;
      }

      return result;
    };

  bool validate_safex_command(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
  {
    //parse command and validate it
    try
    {
        if(!safex::is_safex_key_image_verification_needed(txin.command_type) && txin.key_offsets.size() != 1)
        {
          LOG_ERROR("Commands that don't have key image verification must have only 1 key offset");
          return false;
        }
      std::unique_ptr<command> cmd = safex_command_serializer::parse_safex_object(txin.script, txin.command_type);
      execution_status result{cmd->validate(blokchainDB, txin)};
      if (result != execution_status::ok)
      {
        LOG_ERROR("Validation of safex command failed, status:" << static_cast<int>(result));
        return false;
      }
    }
    catch (command_exception &ex)
    {
      LOG_ERROR("Error in safex command validation:" << ex.what());
      return false;
    }


    return true;
  }


  bool execute_safex_command(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
  {
    //parse command and execute it
    try
    {
      std::unique_ptr<command> cmd = safex_command_serializer::parse_safex_object(txin.script, txin.command_type);
      std::shared_ptr<execution_result> result{cmd->execute(blokchainDB, txin)};
      if (result->status != execution_status::ok)
      {
        LOG_ERROR("Execution of safex command failed, status:" << static_cast<int>(result->status));
        return false;
      }
    }
    catch (command_exception &ex)
    {
      LOG_ERROR("Error in safex command execution:" << ex.what());
      return false;
    }


    return true;
  }


}
