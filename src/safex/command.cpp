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

  template<typename CommandResult>
  bool command<CommandResult>::store(epee::serialization::portable_storage &ps) const
  {
    ps.set_value(FIELD_VERSION, (uint32_t) this->version, nullptr);
    ps.set_value(FIELD_COMMAND, (uint32_t) this->command_type, nullptr);

    return true;
  }


  template<typename CommandResult>
  bool command<CommandResult>::load(epee::serialization::portable_storage &ps)
  {


    uint32_t _command_type = 0;

    ps.get_value(FIELD_VERSION, this->version, nullptr);
    ps.get_value(FIELD_COMMAND, _command_type, nullptr);

    this->command_type = static_cast<command_t>(_command_type);

    return true;
  }

  bool dummy_command::store(epee::serialization::portable_storage &ps) const {return false;};
  bool dummy_command::load(epee::serialization::portable_storage &ps) {return false;};


  bool token_lock::store(epee::serialization::portable_storage &ps) const
  {
    command<token_lock_result>::store(ps);

    ps.set_value(FIELD_LOCK_TOKEN_AMOUNT, (uint64_t) this->lock_token_amount, nullptr);

    return true;
  }


  bool token_lock::load(epee::serialization::portable_storage &ps)
  {
    command<token_lock_result>::load(ps);

    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((this->get_command_type() == command_t::token_lock), "Could not create command, wrong command type", this->command_type);

    ps.get_value(FIELD_LOCK_TOKEN_AMOUNT, this->lock_token_amount, nullptr);

    return true;
  }


  bool token_lock::execute(const cryptonote::BlockchainDB &blokchainDB, const cryptonote::txin_to_script &txin, token_lock_result &command_result)
  {


    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((this->get_lock_token_amount() >= MINIMUM_TOKEN_LOCK_AMOUNT), "Minumum amount of tokens to lock is " + std::to_string(MINIMUM_TOKEN_LOCK_AMOUNT), this->command_type);
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

    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((this->get_command_type() == command_t::token_unlock), "Could not create command, wrong command type", this->command_type);

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

    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((this->get_command_type() == command_t::token_collect), "Could not create command, wrong command type", this->command_type);

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


}