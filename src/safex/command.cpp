//
// Created by amarko on 4.3.19..
//

#include "cryptonote_config.h"
#include "command.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "cryptonote_core/blockchain.h"

namespace safex
{

  bool token_lock::execute(cryptonote::Blockchain& blokchain, token_lock_result &cr) {

    if (token_amount < MINIMUM_TOKEN_LOCK_AMOUNT) {
      throw command_exception(command_t::token_lock, "Minumum amount of tokens to lock is "+std::to_string(MINIMUM_TOKEN_LOCK_AMOUNT));
    }

    if (this->keys.size() == 0) throw command_exception(command_t::token_lock, "Public key missing, command execution failed!");

    cr.token_amount = this->token_amount;
    cr.block_number = blokchain.get_current_blockchain_height();

    //Calculate has, locked output ID
    cryptonote::blobdata b_blob = AUTO_VAL_INIT(b_blob);
    b_blob.append(reinterpret_cast<const char*>(&this->token_amount), sizeof(this->token_amount));
    b_blob.append(reinterpret_cast<const char*>(&this->cash_amount), sizeof(this->cash_amount));
    b_blob.append(reinterpret_cast<const char*>(&(this->keys[0])), sizeof(this->keys[0]));
    b_blob.append(reinterpret_cast<const char*>(&cr.block_number), sizeof(cr.block_number));
    cryptonote::get_blob_hash(b_blob, cr.id);
    
    cr.valid = true;


    return true;
  }


  bool parse_arguments(const std::vector<const uint8_t> &arguments) {
    //todo

    return true;
  }



}