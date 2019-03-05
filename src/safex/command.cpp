//
// Created by amarko on 4.3.19..
//

#include "cryptonote_config.h"
#include "command.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_config.h"
#include "cryptonote_core/blockchain.h"

namespace safex
{

  bool token_lock::execute(cryptonote::Blockchain& blokchain, token_lock_result &cr) {

    if (token_amount < MINIMUM_TOKEN_LOCK_AMOUNT) {
      throw command_exception(command_t::token_lock, "Minumum amount of tokens to lock is "+std::to_string(MINIMUM_TOKEN_LOCK_AMOUNT));
    }


    cr.token_amount = this->token_amount;
    cr.block_number = blokchain.get_current_blockchain_height();
    cr.valid = true;


    return true;
  }


  bool parse_arguments(const std::vector<const uint8_t> &arguments) {
    //todo

    return true;
  }



}