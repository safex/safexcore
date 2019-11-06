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
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((tools::is_whole_token_amount(this->get_staked_token_amount())), "Staked input is not whole token amount", this->get_command_type());
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.token_amount == this->get_staked_token_amount()), "Input amount differs from token stake command amount", this->get_command_type());

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

    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.key_offsets.size() == 1), "Only one locked token output could be processed per input", this->get_command_type());
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.key_offsets[0] == this->get_staked_token_output_index()), "Locked token output ID does not match", this->get_command_type());

    //todo Get data about locked token output from database using its index
    //todo check if db output amount is same as txin amount
    //todo check if minimum amount of time is fulfilled

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

    execution_status result = execution_status::ok;

    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.key_offsets.size() == 1), "Only one locked token output could be processed per input", this->get_command_type());
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.key_offsets[0] == this->get_staked_token_output_index()), "Locked token output ID does not match", this->get_command_type());

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

    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.amount > 0), "Amount to donate must be greater than zero ", this->get_command_type());
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.token_amount == 0), "Tokens could not be donated to network ", this->get_command_type());

    return result;
  };

  simple_purchase_result* simple_purchase::execute(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
  {

    execution_status result = validate(blokchainDB, txin);
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES(result == execution_status::ok, "Failed to validate simple purchase command", this->get_command_type());

    simple_purchase_result *cr = new simple_purchase_result{};
    cr->offer_id = this->offer_id;
    cr->valid = true;
    cr->status = execution_status::ok;

    return cr;
  };

  execution_status simple_purchase::validate(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
  {

    execution_status result = execution_status::ok;

    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.amount > 0), "Purchase amount must be greater than zero ", this->get_command_type());
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.token_amount == 0), "Could not purchase with tokens ", this->get_command_type());

    return result;
  };


  distribute_fee_result* distribute_fee::execute(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
  {
    execution_status result = validate(blokchainDB, txin);
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES(result == execution_status::ok, "Failed to validate distribute fee command", this->get_command_type());

    distribute_fee_result *cr = new distribute_fee_result{};
    cr->amount = txin.amount;
    cr->valid = true;
    cr->status = execution_status::ok;
    return cr;
  };

  execution_status distribute_fee::validate(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
  {

    execution_status result = execution_status::ok;
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.amount > 0), "Amount to donate must be greater than zero ", this->get_command_type());
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.token_amount == 0), "Tokens could not be donated to network ", this->get_command_type());

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
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.token_amount > 0), "Create account must reference at least one token output and in total is "+
                  std::to_string(SAFEX_CREATE_ACCOUNT_TOKEN_LOCK_FEE)+" tokens needed for locking", this->get_command_type());

    std::unique_ptr<safex::create_account> cmd = safex::safex_command_serializer::parse_safex_command<safex::create_account>(txin.script);

    for (auto ch: cmd->get_username()) {
      if (!std::isalnum(ch) && ch!='_') {
        return execution_status::error_invalid_account_name;
      }
    }

    std::vector<uint8_t>  dummy{};
    if (blokchainDB.get_account_data(cmd->get_username(), dummy)) {
      return execution_status::error_account_already_exists;
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
            if (!std::isalnum(ch) && ch!='_') {
                result = execution_status::error_invalid_account_name;
            }
        }

        std::vector<uint8_t>  dummy{};
        if (!blokchainDB.get_account_data(cmd->get_username(), dummy)) {
            result = execution_status::error_account_non_existant;
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

        for (auto ch: cmd->get_seller()) {
            if (!std::isalnum(ch) && ch!='_') {
                result = execution_status::error_invalid_account_name;
            }
        }

        std::vector<uint8_t>  dummy{};
        if (!blokchainDB.get_account_data(cmd->get_seller(), dummy)) {
            result = execution_status::error_account_non_existant;
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

        for (auto ch: cmd->get_seller()) {
            if (!std::isalnum(ch) && ch!='_') {
                result = execution_status::error_invalid_account_name;
            }
        }

        std::vector<uint8_t>  dummy{};
        if (!blokchainDB.get_account_data(cmd->get_seller(), dummy)) {
            result = execution_status::error_account_non_existant;
        }

        safex::safex_offer sfx_dummy{};
        if (!blokchainDB.get_offer(cmd->get_offerid(), sfx_dummy)) {
            result = execution_status::error_offer_non_existant;
        }
        return result;
    };

    close_offer_result* close_offer::execute(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
    {
        execution_status result = validate(blokchainDB, txin);
        SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES(result == execution_status::ok, "Failed to validate close offer command", this->get_command_type());

        close_offer_result *cr = new close_offer_result{this->offer_id};
        cr->valid = true;
        cr->status = execution_status::ok;

        return cr;
    };

    execution_status close_offer::validate(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
    {

        execution_status result = execution_status::ok;
        std::unique_ptr<safex::close_offer> cmd = safex::safex_command_serializer::parse_safex_command<safex::close_offer>(txin.script);

        safex::safex_offer sfx_dummy{};
        if (!blokchainDB.get_offer(cmd->get_offerid(), sfx_dummy)) {
            result = execution_status::error_offer_non_existant;
        }
        return result;
    };


  bool validate_safex_command(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
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
