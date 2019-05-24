//
// Created by amarko on 4.3.19..
//

#ifndef SAFEX_COMMAND_H
#define SAFEX_COMMAND_H

#include <string>
#include <exception>
#include <vector>
#include <iostream>

#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "cryptonote_core/blockchain.h"

#include "storages/portable_storage.h"
#include "serialization/serialization.h"
#include "safex_core.h"

#include "misc_log_ex.h"

#define CHECK_COMMAND_TYPE(TYPE_TO_CHECK,EXPECTED_TYPE) SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((TYPE_TO_CHECK == EXPECTED_TYPE), "Could not create command, wrong command type", TYPE_TO_CHECK);

namespace safex
{

  /* Binary storage fields */
  static const std::string FIELD_VERSION = "version";
  static const std::string FIELD_COMMAND = "command";
  static const std::string FIELD_STAKE_TOKEN_AMOUNT = "stake_token_amount";
  static const std::string FIELD_STAKED_TOKEN_OUTPUT_INDEX = "staked_token_output_index";


  enum class execution_status
  {
      ok = 0,
      wrong_input_params = 1,
      invalid = 2
  };

  struct execution_result
  {
    bool valid = false;
    execution_status status = execution_status::invalid;
  };

  struct token_stake_result : public execution_result
  {
    uint64_t token_amount = 0; //staked amount
    uint32_t block_number = 0; //block where it is locked
  };


  struct token_unstake_result : public execution_result
  {
    uint64_t token_amount = 0; //unlocked token amount
    uint64_t interest = 0; //collected interest from network fees over period
    uint32_t block_number = 0; //block where it is unlocked
  };

  struct token_collect_result : public execution_result
  {
    uint64_t token_amount = 0; //amount of tokens that is relocked
    uint64_t interest = 0; //collected interest from network fees over period
    uint32_t block_number = 0; //block where it is unlocked
  };

  struct donate_fee_result : public execution_result
  {
    uint64_t amount = 0; //cash amount do donate to newtork token holders
  };

  struct distribute_fee_result : public execution_result
  {
    uint64_t amount = 0; //cash amount do donate to newtork token holders
  };




  struct command_data
  {

  };

  struct token_stake_data : public command_data
  {
    uint32_t reserved = 0;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(reserved)
    END_SERIALIZE()
  };

  struct donate_fee_data : public command_data
  {
    uint32_t reserved = 0;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(reserved)
    END_SERIALIZE()
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

      friend class safex_command_serializer;

      /**
       * @param _version Safex command protocol version
       * @param _command_type actuall command, like stake token
      * */
      command(const uint32_t _version, const command_t _command_type) : version(_version), command_type(_command_type)
      {
        SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((_command_type < command_t::invalid_command), "Invalid command type", _command_type);
        SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((_version <= SAFEX_COMMAND_PROTOCOL_VERSION), "Unsupported command protocol version " + std::to_string(_version), command_type);

      }

      virtual execution_result* execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) = 0;

      uint32_t getVersion() const
      { return version; }

      command_t get_command_type() const
      { return command_type; }

      virtual ~command() = default;

      BEGIN_SERIALIZE_OBJECT()
        VARINT_FIELD(version)
        VARINT_FIELD(command_type)
      END_SERIALIZE()


    protected:

      uint32_t version;
      command_t command_type;
  };

  //Dummy command for serialization
  class dummy_command : public command
  {
    public:

      friend class safex_command_serializer;

      dummy_command() :  command(0, command_t::nop) {}

      virtual execution_result* execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override {return new execution_result{};};

      BEGIN_SERIALIZE_OBJECT()
        FIELDS(*static_cast<command *>(this))
      END_SERIALIZE()
  };


  //Token stake command
  class token_stake : public command
  {
    public:

      friend class safex_command_serializer;

      /**
       * @param _version Safex command protocol version
       * @param _token_amount amount of tokens to lock
      * */
      token_stake(const uint32_t _version, const uint64_t _token_amount) : command(_version, command_t::token_stake), lock_token_amount(_token_amount) {}

      token_stake() : command(0, command_t::token_stake), lock_token_amount(0) {}

      uint64_t get_lock_token_amount() const { return lock_token_amount; }

      virtual token_stake_result* execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;

      BEGIN_SERIALIZE_OBJECT()
        FIELDS(*static_cast<command *>(this))
        CHECK_COMMAND_TYPE(this->get_command_type(), command_t::token_stake);
        VARINT_FIELD(lock_token_amount)
      END_SERIALIZE()

    protected:

      uint64_t lock_token_amount;
  };


  //Token unlock command
  class token_unstake : public command
  {
    public:

      friend class safex_command_serializer;

      /**
       * @param _version Safex command protocol version
       * @param _staked_token_output_index global index of txout_to_script output that is being unlocked
      * */
      token_unstake(const uint32_t _version, const uint64_t _staked_token_output_index) : command(_version, command_t::token_unstake),
              staked_token_output_index(_staked_token_output_index) {}

      token_unstake() : command(0, command_t::token_unstake), staked_token_output_index(0) {}

      uint64_t get_staked_token_output_index() const { return staked_token_output_index; }

      virtual token_unstake_result* execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;

      BEGIN_SERIALIZE_OBJECT()
        FIELDS(*static_cast<command*>(this))
        CHECK_COMMAND_TYPE(this->get_command_type(), command_t::token_unstake);
        VARINT_FIELD(staked_token_output_index)
      END_SERIALIZE()

    protected:

      uint64_t staked_token_output_index;
  };


  //Token collect command
  class token_collect : public command
  {
    public:

      friend class safex_command_serializer;

      /**
       * @param _version Safex command protocol version
       * @param _staked_token_output_index global index of txout_to_script output that is being unstaked
       *
      * */
      token_collect(const uint32_t _version, const uint64_t _staked_token_output_index) : command(_version, command_t::token_collect),
                                                                                          staked_token_output_index(_staked_token_output_index) {}

      token_collect() : command(0, command_t::token_collect), staked_token_output_index(0) {}

      uint64_t get_staked_token_output_index() const { return staked_token_output_index; }

      virtual token_collect_result* execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;

      BEGIN_SERIALIZE_OBJECT()
        FIELDS(*static_cast<command *>(this))
        CHECK_COMMAND_TYPE(this->get_command_type(), command_t::token_collect);
        VARINT_FIELD(staked_token_output_index)
      END_SERIALIZE()

    protected:

      uint64_t staked_token_output_index;
  };

  class donate_fee : public command
  {
    public:
      friend class safex_command_serializer;

      /**
       * @param _version Safex command protocol version
       * @param _donate_amount //amount of safex cash that will be donated to the network token holder to be distributed as interest
      * */
      donate_fee(const uint32_t _version, const uint64_t _donation_safex_cash_amount) : command(_version, command_t::donate_network_fee),
                                                                                       donation_safex_cash_amount(_donation_safex_cash_amount) {}

      donate_fee() : command(0, command_t::donate_network_fee), donation_safex_cash_amount(0) {}

      uint64_t get_locked_token_output_index() const { return donation_safex_cash_amount; }

      virtual donate_fee_result* execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;

      BEGIN_SERIALIZE_OBJECT()
        FIELDS(*static_cast<command *>(this))
        CHECK_COMMAND_TYPE(this->get_command_type(),  command_t::donate_network_fee);
        VARINT_FIELD(donation_safex_cash_amount)
      END_SERIALIZE()

    protected:

      uint64_t donation_safex_cash_amount;
  };


  class distribute_fee : public command
  {
    public:
      friend class safex_command_serializer;

      /**
       * @param _version Safex command protocol version
       * @param _donate_amount //amount of safex cash that will be distributed to token holders that unstake tokens
      * */
      distribute_fee(const uint32_t _version, const uint64_t _donation_safex_cash_amount) : command(_version, command_t::distribute_network_fee),
                                                                                        safex_cash_amount(_donation_safex_cash_amount) {}

      distribute_fee() : command(0, command_t::distribute_network_fee), safex_cash_amount(0) {}

      uint64_t get_staked_token_output_index() const { return safex_cash_amount; }

      virtual distribute_fee_result* execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;

      BEGIN_SERIALIZE_OBJECT()
        FIELDS(*static_cast<command *>(this))
        CHECK_COMMAND_TYPE(this->get_command_type(),  command_t::distribute_network_fee);
        VARINT_FIELD(safex_cash_amount)
      END_SERIALIZE()

    protected:

      uint64_t safex_cash_amount;
  };


  bool execute_safex_command(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin, const safex::command_t command_type);



  class safex_command_serializer
  {
    public:

      template<typename CommandOrData>
      static bool serialize_safex_object(const CommandOrData &commandOrData, std::vector<uint8_t> &buffer)
      {
        cryptonote::blobdata blob = cryptonote::t_serializable_object_to_blob(commandOrData);
        buffer.resize(blob.size());
        memcpy(&buffer[0], blob.data(), blob.size());
        return true;
      }


      template<typename CommandOrData>
      static bool parse_safex_object(const std::vector<uint8_t> &buffer, CommandOrData &commandOrData)
      {
        cryptonote::blobdata command_blob;
        const uint8_t* serialized_buffer_ptr = &buffer[0];
        std::copy(serialized_buffer_ptr, serialized_buffer_ptr + buffer.size(), std::back_inserter(command_blob));

        std::stringstream ss;
        ss << command_blob;
        binary_archive<false> ba(ss);
        bool r = ::serialization::serialize(ba, commandOrData);
        SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES(r, "Failed to parse command or data from blob", command_t::invalid_command);
        return true;
      }

      static inline command_t get_command_type(const std::vector<uint8_t> &script)
      {

        cryptonote::blobdata command_blob;
        const uint8_t* serialized_buffer_ptr = &script[0];
        std::copy(serialized_buffer_ptr, serialized_buffer_ptr + 2, std::back_inserter(command_blob));

        std::stringstream ss;
        ss << command_blob;
        binary_archive<false> ba(ss);
        dummy_command temp; //just take any command, we just need command type deserialized
        bool r = ::serialization::serialize(ba, static_cast<command&>(temp));
        SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES(r, "Failed to parse command from blob", command_t::invalid_command);

        return static_cast<command_t>(temp.get_command_type());
      }
  };


} //namespace safex


#endif //SAFEX_COMMAND_H
