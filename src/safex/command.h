//
// Created by amarko on 4.3.19..
//

#ifndef SAFEX_COMMAND_H
#define SAFEX_COMMAND_H

#include <string>
#include <exception>
#include <vector>

#include "crypto/crypto.h"
#include "cryptonote_core/blockchain.h"


namespace safex
{

  /**
  * It is indicator in transaction version 2 extra field, to ease transaction verification
  * */
  enum class command_domain
  {


  };

  /**
   * Command type
   * */
  enum class command_t
  {
    nop = 0x0,
    token_lock = 0x01,
    token_unlock = 0x02
  };

  /**
   * In case of error during execution, exception will be thrown
   * */
  class command_exception : public std::exception
  {
    public:

    command_exception(command_t _command_type, std::string _message) : command_type{_command_type}, what_message{_message}
    {

    }

    virtual const char *what() const noexcept override
    {
      return what_message.c_str();
    }

    command_t getCommand() { return command_type; }


    private:

    command_t command_type;
    std::string what_message;

  };


  struct token_lock_result
  {
    uint64_t token_amount;
    uint32_t block_number;
    bool valid;
  };


  /**
  * @brief script command representation
  *
  * Safex Command protocol is intended to expand functionality
  * of the blockchain and to enable easy addition of the new features
  * without having to make significant changes
  * to the current blockchain core protocol.
  */
  template<typename Result>
  class command
  {
    public:

    /**
     * @param _version Safex command protocol version
     * @param _command_type actuall command, like token lock
     * @param _cash_amount Safex cash amount provided in the UTXO (txout_to_script) where the command is defined
     * @param _token_amount Safex token amount provided in the UTXO (txout_to_script) where the command is defined
     * @param _key public key related to the owner of the output, who posses private key and is able to "spend", use this output
     *
    * */
    command(const uint32_t _version, const command_t _command_type, const uint64_t _cash_amount, const uint64_t _token_amount, const std::vector<crypto::public_key> &_keys) :
            version(_version), command_type(_command_type), cash_amount(_cash_amount), token_amount(_token_amount), keys(_keys)
    {


    }

    virtual bool execute(cryptonote::Blockchain &blokchain, token_lock_result &cr) = 0;

    virtual bool parse_arguments(const std::vector<const uint8_t> &arguments) = 0;


    const uint32_t version;
    const command_t command_type;
    const uint64_t cash_amount;
    const uint64_t token_amount;
    const std::vector<crypto::public_key> keys;
  };


  class token_lock : public command<token_lock_result>
  {
    token_lock(const uint32_t _version, const command_t _command_type, const uint64_t _cash_amount, const uint64_t _token_amount, const std::vector<crypto::public_key> &_keys) :
            command(_version, _command_type, _cash_amount, _token_amount, _keys)
    {


    }

    virtual bool execute(cryptonote::Blockchain &blokchain, token_lock_result &cr) override;

    virtual bool parse_arguments(const std::vector<const uint8_t> &arguments) override;

  };



  //Token lock command




} //namespace safex


#endif //SAFEX_COMMAND_H
