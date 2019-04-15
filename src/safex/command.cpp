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


  bool token_lock::store(epee::serialization::portable_storage &ps) const
  {
    command<token_lock_result>::store(ps);
    ps.set_value(FIELD_LOCK_TOKEN_AMOUNT, (uint64_t) this->lock_token_amount, nullptr);
    return true;
  }


  bool token_lock::load(epee::serialization::portable_storage &ps)
  {
    command<token_lock_result>::load(ps);
    CHECK_COMMAND_TYPE(this->get_command_type(), command_t::token_lock);
    ps.get_value(FIELD_LOCK_TOKEN_AMOUNT, this->lock_token_amount, nullptr);
    return true;
  }


  bool token_lock::execute(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin, token_lock_result &command_result)
  {
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((this->get_lock_token_amount() >= SAFEX_MINIMUM_TOKEN_LOCK_AMOUNT), "Minumum amount of tokens to lock is " + std::to_string(SAFEX_MINIMUM_TOKEN_LOCK_AMOUNT), this->command_type);
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.token_amount == this->get_lock_token_amount()), "Input amount differs from token lock command amount", this->command_type);

    token_lock_result cr = AUTO_VAL_INIT(cr);
    cr.token_amount = txin.token_amount;
    cr.block_number = blokchainDB.height();

    cr.valid = true;

    command_result = cr;
    return true;
  }


  bool token_unlock::store(epee::serialization::portable_storage &ps) const
  {
    command<token_unlock_result>::store(ps);
    ps.set_value(FIELD_LOCKED_TOKEN_OUTPUT_INDEX, (uint64_t) this->locked_token_output_index, nullptr);
    return true;
  }


  bool token_unlock::load(epee::serialization::portable_storage &ps)
  {
    command<token_unlock_result>::load(ps);
    CHECK_COMMAND_TYPE(this->get_command_type(), command_t::token_unlock);
    ps.get_value(FIELD_LOCKED_TOKEN_OUTPUT_INDEX, this->locked_token_output_index, nullptr);
    return true;
  }


  bool token_unlock::execute(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin, token_unlock_result &command_result)
  {

    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.key_offsets.size() == 1), "Only one locked token output could be processed per input", this->command_type);
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.key_offsets[0] == this->get_locked_token_output_index()), "Locked token output ID does not match", this->command_type);

    //todo Get data about locked token output from database using its index
    //todo check if db output amount is same as txin amount
    //todo check if minimum amount of time is fulfilled


    token_unlock_result cr = AUTO_VAL_INIT(cr);
    cr.token_amount = txin.token_amount;
    cr.block_number = blokchainDB.height();

    uint64_t locked_token_output_index = txin.key_offsets[0];
    cr.interest = calculate_token_interest(locked_token_output_index, cr.block_number, cr.token_amount);
    cr.valid = true;

    command_result = cr;

    return true;
  }





  bool token_collect::store(epee::serialization::portable_storage &ps) const
  {
    command<token_collect_result>::store(ps);
    ps.set_value(FIELD_LOCKED_TOKEN_OUTPUT_INDEX, (uint64_t) this->locked_token_output_index, nullptr);
    return true;
  }


  bool token_collect::load(epee::serialization::portable_storage &ps)
  {
    command<token_collect_result>::load(ps);
    CHECK_COMMAND_TYPE(this->get_command_type(), command_t::token_collect);
    ps.get_value(FIELD_LOCKED_TOKEN_OUTPUT_INDEX, this->locked_token_output_index, nullptr);
    return true;
  }


  bool token_collect::execute(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin, token_collect_result &command_result)
  {

    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.key_offsets.size() == 1), "Only one locked token output could be processed per input", this->command_type);
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.key_offsets[0] == this->get_locked_token_output_index()), "Locked token output ID does not match", this->command_type);

    //todo Get data about locked token output from database using its index
    //todo check if db output amount is same as txin amount
    //todo check if minimum amount of time is fulfilled


    token_collect_result cr = AUTO_VAL_INIT(cr);
    cr.token_amount = txin.token_amount;
    cr.block_number = blokchainDB.height();

    uint64_t locked_token_output_index = txin.key_offsets[0];
    cr.interest = calculate_token_interest(locked_token_output_index, cr.block_number, cr.token_amount);
    cr.valid = true;

    command_result = cr;
    return true;
  }


  bool donate_fee::execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin, donate_fee_result &command_result) {
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.amount > 0), "Amount to donate must be greater than zero ", this->command_type);
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((txin.token_amount == 0), "Tokens could not be donated to network ", this->command_type);

    donate_fee_result cr = AUTO_VAL_INIT(cr);
    cr.amount = txin.amount;
    cr.valid = true;
    command_result = cr;
    return true;
  };

  bool donate_fee::store(epee::serialization::portable_storage &ps) const
  {
    command<donate_fee_result>::store(ps);
    ps.set_value(FIELD_LOCKED_TOKEN_OUTPUT_INDEX, (uint64_t) this->donation_safex_cash_amount, nullptr);
    return true;
  }


  bool donate_fee::load(epee::serialization::portable_storage &ps)
  {
    command<donate_fee_result>::load(ps);
    CHECK_COMMAND_TYPE(this->get_command_type(), command_t::donate_network_fee);
    ps.get_value(FIELD_LOCKED_TOKEN_OUTPUT_INDEX, this->donation_safex_cash_amount, nullptr);
    return true;
  }


}