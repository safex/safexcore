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
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((this->get_lock_token_amount() >= SAFEX_MINIMUM_TOKEN_STAKE_AMOUNT), "Minumum amount of tokens to lock is " + std::to_string(SAFEX_MINIMUM_TOKEN_STAKE_AMOUNT), this->command_type);
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.token_amount == this->get_lock_token_amount()), "Input amount differs from token stake command amount", this->command_type);

    token_stake_result *cr = new token_stake_result{};
    cr->token_amount = txin.token_amount;
    cr->block_number = blokchainDB.height();
    cr->valid = true;
    cr->status = execution_status::ok;

    return cr;
  }

  token_unstake_result* token_unstake::execute(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
  {

    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.key_offsets.size() == 1), "Only one locked token output could be processed per input", this->command_type);
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.key_offsets[0] == this->get_staked_token_output_index()), "Locked token output ID does not match", this->command_type);

    //todo Get data about locked token output from database using its index
    //todo check if db output amount is same as txin amount
    //todo check if minimum amount of time is fulfilled


    token_unstake_result *cr = new token_unstake_result{};
    cr->token_amount = txin.token_amount;
    cr->block_number = blokchainDB.height();

    uint64_t locked_token_output_index = txin.key_offsets[0];
    cr->interest = calculate_token_interest(locked_token_output_index, cr->block_number, cr->token_amount);
    cr->valid = true;
    cr->status = execution_status::ok;

    return cr;
  }


  token_collect_result* token_collect::execute(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin)
  {

    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.key_offsets.size() == 1), "Only one locked token output could be processed per input", this->command_type);
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.key_offsets[0] == this->get_staked_token_output_index()), "Locked token output ID does not match", this->command_type);

    //todo Get data about locked token output from database using its index
    //todo check if db output amount is same as txin amount
    //todo check if minimum amount of time is fulfilled


    token_collect_result *cr = new token_collect_result{};
    cr->token_amount = txin.token_amount;
    cr->block_number = blokchainDB.height();

    uint64_t locked_token_output_index = txin.key_offsets[0];
    cr->interest = calculate_token_interest(locked_token_output_index, cr->block_number, cr->token_amount);
    cr->valid = true;
    cr->status = execution_status::ok;

    return cr;
  }


  donate_fee_result* donate_fee::execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) {
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.amount > 0), "Amount to donate must be greater than zero ", this->command_type);
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.token_amount == 0), "Tokens could not be donated to network ", this->command_type);

    donate_fee_result *cr = new donate_fee_result{};
    cr->amount = txin.amount;
    cr->valid = true;
    cr->status = execution_status::ok;

    return cr;
  };


  distribute_fee_result* distribute_fee::execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) {
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.amount > 0), "Amount to donate must be greater than zero ", this->command_type);
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.token_amount == 0), "Tokens could not be donated to network ", this->command_type);

    distribute_fee_result *cr = new distribute_fee_result{};
    cr->amount = txin.amount;
    cr->valid = true;
    cr->status = execution_status::ok;
    return cr;
  };


  bool execute_safex_command(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin, const safex::command_t command_type)
  {
    //todo here implement execution of advanced concepts

    return true;
  }


}