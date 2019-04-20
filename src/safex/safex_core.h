//
// Created by amarko on 26.3.19..
//

#include <cstdint>
#include <string>
#include <exception>

#include "cryptonote_config.h"

#ifndef SAFEX_SAFEX_CORE_H
#define SAFEX_SAFEX_CORE_H


namespace safex
{
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
      token_lock = 0x01,
      token_unlock = 0x02,
      token_collect = 0x03,
      donate_network_fee = 0x04, /* Donate safex cash to newtork token holders */
      distribute_network_fee = 0x05, /* Distribute collected newtork fee to token holders */
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
      return 10;
    else
      return SAFEX_DEFAULT_INTERVAL_PERIOD;
  }


  /**
 * Calculates locking interval starting block for block with height
 *
 * For example, blocks with height from 1-1000 will be first locked belong to interval 1,
 * and will be first locked from interval 2 (from block 1001)
 * @param height - block height
 * @param nettype network type, main, test or fake
 * @return Starting block of the interval
 */
  inline uint64_t calculate_interval_block_for_height(const uint64_t height, const cryptonote::network_type nettype)
  {
    if (height == 0) return 0; //zero height is zero interval
    uint64_t interval = height > 0 ? ((height - 1) / get_safex_interval_period(nettype)) + 1 : 0; //blocks 1-1000 first interval, 1001-2000 second etc.
    uint64_t result = (interval-1) * get_safex_interval_period(nettype) + 1;
    return result; //returns interval starting block
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
      return get_safex_interval_period(cryptonote::network_type::FAKECHAIN) * 10;
    else
      return SAFEX_DEFAULT_MINUMUM_TOKEN_LOCK_PERIOD;
  }

}

#endif //SAFEX_SAFEX_CORE_H
