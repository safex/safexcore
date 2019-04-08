//
// Created by amarko on 26.3.19..
//

#include <cstdint>
#include <string>
#include <exception>

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
 * Calculates locking interval starting block for block with height
 *
 * For example, blocks with height from 1-1000 will be first locked belong to interval 1,
 * and will be first locked from interval 2 (from block 1001)
 * @param height - block height
 * @return Starting block of the interval
 */
  inline uint64_t calculate_interval_for_height(const uint64_t height)
  {
    uint64_t interval = height > 0 ? (height - 1) / 1000 : 0;
    return (interval*1000 + 1); //returns interval starting block
  }

  /**
  * Check if block is valid interval representation (interval starting block)
  *
  * For first interval, value is 1, for second 1001, for third 2001, etc
  * @param block_height - block height
  * @return true or false
  */
  inline bool is_interval_starting_block(const uint64_t block_height)
  {
    return ((block_height - 1) % 1000 == 0);
  }

  /**
  * Check if block is valid interval representation (interval starting block)
  *
  * For first interval, value is 1, for second 1001, for third 2001, etc
  * @param block_height - block height
  * @return true or false
  */
  inline uint64_t calulate_starting_block_for_interval(const uint64_t interval)
  {
    return interval*1000 + 1;
  }


}

#endif //SAFEX_SAFEX_CORE_H
