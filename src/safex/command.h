//
// Created by amarko on 4.3.19..
//

#ifndef SAFEX_COMMAND_H
#define SAFEX_COMMAND_H

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

    command_exception(command_t _command_type, std::string _message) : command_type(_command_type), what_message(_message),
    {

    }

    const char *what() override
    {
      return what_message.c_str();
    }


    private:

    command_t command_type;
    std::string what_message;

  };

  /**
   * It is command specific result with data as result of command execution
   * */
  struct command_result
  {
    bool valid = false;
  };


  /**
  * @brief script command representation
  *
  * Safex Command protocol is intended to expand functionality
  * of the blockchain and to enable easy addition of the new features
  * without having to make significant changes
  * to the current blockchain core protocol.
  */
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
    command(uint32_t _version, command_t _command_type, uint64_t _cash_amount, uint64_t _token_amount, crypto::public_key _key) :
            version(_version), command_type(_command_type), cash_amount(_cash_amount), token_amount(_token_amount), key(_key)
    {


    }

    virtual bool execute(command_result &cr) = 0;

    virtual bool parse_arguments(const vector<const uint8_t> &arguments) = 0;


    const uint32_t version;
    const command_t command_type;
    const uint64_t cash_amount;
    const uint64_t token_amount;
    const crypto::public_key key;
  };


} //namespace safex


#endif //SAFEX_COMMAND_H
