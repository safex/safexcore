//
// Created by amarko on 26.3.19..
//

#include <cstdint>
#include <string>
#include <exception>
#include <map>
#include <vector>
#include <crypto/hash.h>
#include "misc_log_ex.h"
#include "cryptonote_config.h"

#ifndef SAFEX_SAFEX_CORE_H
#define SAFEX_SAFEX_CORE_H


namespace safex
{
  typedef std::map<uint64_t, uint64_t> map_interval_interest; //key is interval starting block, value is safex cash per token interest


  struct account_username {

    account_username(std::string ss) {
      username = std::vector<uint8_t>(ss.begin(), ss.end());
    }

    account_username(const char* cc, uint32_t size) {
      username = std::vector<uint8_t>(cc, cc+size);
    }

    account_username(const std::vector<uint8_t> &vv) {
      username = std::vector<uint8_t>(vv.begin(), vv.end());
    }

    const char* c_str() const {
      return (const char*)username.data();
    }

    crypto::hash hash() const {return crypto::cn_fast_hash(username.data(), username.size());}

    std::vector<uint8_t> username = std::vector<uint8_t>(64, 0); //todo decide if we would use utf8 or something else

  };

/**
* It is indicator in transaction version 2 extra field, to ease transaction verification
* */
  enum class command_domain : uint32_t
  {
      none = 0x00,
      token_locking = 0x01
  };

/**
 * Command type
 * */
  enum class command_t : uint32_t
  {
      nop = 0x0,
      token_stake = 0x01,
      token_unstake = 0x02,
      token_collect = 0x03,
      donate_network_fee = 0x04, /* Donate safex cash to newtork token holders */
      distribute_network_fee = 0x05, /* Distribute collected newtork fee to token holders */
      simple_purchase = 0x06,
      create_account = 0x0A, /* Create Safex account */
      edit_account = 0x0B, /* Edit Safex account */
      create_offer = 0x10,
      edit_offer = 0x11,
      close_offer = 0x12,
      invalid_command
  };

/**
 * In case of error during execution, exception will be thrown
 * */
  class command_exception : public std::exception
  {
    public:

      command_exception(const command_t _command_type, const std::string &_message) : command_type{_command_type}, what_message{_message}
      {

      }

      virtual const char *what() const noexcept override
      {
        return what_message.c_str();
      }

      command_t getCommand()
      { return command_type; }


    private:

      const command_t command_type;
      const std::string what_message;

  };

#define SAFEX_COMMAND_ASSERT_MES_AND_THROW(message, command_type) {LOG_ERROR(message); std::stringstream ss; ss << message; throw safex::command_exception(command_type, ss.str());}
#define SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES(expr, message, command_type) do {if(!(expr)) SAFEX_COMMAND_ASSERT_MES_AND_THROW(message, command_type);} while(0)


  /**
 * Returns number of blocks in interval
 *
 *
 * @return number of blocks
 */
  inline uint64_t get_safex_interval_period(const cryptonote::network_type nettype = cryptonote::network_type::MAINNET)
  {

    if (nettype == cryptonote::network_type::FAKECHAIN)
      return SAFEX_DEFAULT_INTERVAL_PERIOD/100;
    else if (nettype == cryptonote::network_type::TESTNET)
      return SAFEX_DEFAULT_INTERVAL_PERIOD/100;
    else
      return SAFEX_DEFAULT_INTERVAL_PERIOD;
  }


  /**
 * Calculates locking interval  where block height belongs
 *
 * For example, blocks with height from 1-1000 will be first locked belong to interval 1,
 * and will be first locked from interval 2 (from block 1001)
 * @param height - block height
 * @param nettype network type, main, test or fake
 * @return interval
 */
  inline uint64_t calculate_interval_for_height(const uint64_t height, const cryptonote::network_type nettype)
  {
    if (height == 0) return 0; //zero height is zero interval
    uint64_t interval = height > 0 ? ((height - 1) / get_safex_interval_period(nettype)) + 1 : 0; //blocks 1-1000 first interval, 1001-2000 second etc.
    return interval; //returns interval number
  }

 /**
 * Calculates locking interval starting block where block with height belongs
 *
 * @param height - block height
 * @param nettype network type, main, test or fake
 * @return interval starting block
 */
    inline uint64_t calculate_interval_starting_block_for_height(const uint64_t height, const cryptonote::network_type nettype)
    {
      uint64_t interval = calculate_interval_for_height(height, nettype);
      uint64_t result = (interval-1) * get_safex_interval_period(nettype) + 1;
      return result;
    }

  /**
  * Check if block is valid interval representation (interval starting block)
  *
  * For first interval, value is 1, for second 1001, for third 2001, etc
  * @param block_height - block height
  * @return true or false
  */
  inline bool is_interval_starting_block(const uint64_t block_height, const cryptonote::network_type nettype)
  {
    return ((block_height - 1) % get_safex_interval_period(nettype) == 0);
  }

  /**
  * Check if block is interval last block
  *
  * @param block_height - block height
  * @return true or false
  */
  inline bool is_interval_last_block(const uint64_t block_height, const cryptonote::network_type nettype)
  {
    return is_interval_starting_block(block_height+1, nettype);
  }

  /**
  * Check if block is valid interval representation (interval starting block)
  *
  * For first interval, value is 1, for second 1001, for third 2001, etc
  * @param block_height - block height
  * @return true or false
  */
  inline uint64_t calulate_starting_block_for_interval(const uint64_t interval, const cryptonote::network_type nettype)
  {
    uint64_t result = (interval-1) * get_safex_interval_period(nettype) + 1;
    return result;
  }

  /**
  * Return minimal token lock period
  *
  * @return number of blocks that is munimum token lock period
  */
  inline uint64_t get_safex_minumum_token_lock_period(const cryptonote::network_type nettype)
  {

    if (nettype == cryptonote::network_type::FAKECHAIN)
      return get_safex_interval_period(cryptonote::network_type::FAKECHAIN) * 3;
    else if (nettype == cryptonote::network_type::TESTNET)
      return get_safex_interval_period(cryptonote::network_type::TESTNET) * 1;
    else
      return SAFEX_DEFAULT_MINUMUM_TOKEN_STAKE_PERIOD;
  }

  /**
   * Calculate amount safex network fee
   *
   * @param cash_amount amount of saxex cash in transaction
   * @param nettype network type
   * @param command_type safex network fee may depend of differend scenearious
   * @return
   */
  inline uint64_t calculate_safex_network_fee(const uint64_t cash_amount,  const cryptonote::network_type nettype, const safex::command_t command_type)
  {
    uint64_t fee = 0;

    //todo handle multiplication that overflows
    SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((cash_amount * SAFEX_DEFAULT_NETWORK_FEE_PERCENTAGE) < cash_amount, "Overflow calculating transaction fee", safex::command_t::token_stake);

    switch (nettype) {
      default:
        fee = cash_amount * SAFEX_DEFAULT_NETWORK_FEE_PERCENTAGE / 100;
    }

    return fee;
  }


  /**
   * Gets minumum token stake amount
   *
   * @return
   */
  inline uint64_t get_minimum_token_stake_amount(const cryptonote::network_type nettype = cryptonote::network_type::MAINNET)
  {

    switch (nettype) {
      case cryptonote::network_type::TESTNET:
        return SAFEX_MINIMUM_TOKEN_STAKE_AMOUNT;

      default: 
        return SAFEX_MINIMUM_TOKEN_STAKE_AMOUNT;
    }
  }




}

#endif //SAFEX_SAFEX_CORE_H
