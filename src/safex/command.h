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
  static const std::string FIELD_LOCK_TOKEN_AMOUNT = "lock_token_amount";
  static const std::string FIELD_LOCKED_TOKEN_OUTPUT_INDEX = "locked_token_output_index";


  struct token_lock_result
  {
    uint64_t token_amount; //locked amount
    uint32_t block_number; //block where it is locked

    bool valid;
  };

  struct token_lock_data
  {
    uint32_t reserved;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(reserved)
    END_SERIALIZE()
  };

  struct token_unlock_result
  {
    uint64_t token_amount; //unlocked token amount
    uint64_t interest; //collected interest from network fees over period
    uint32_t block_number; //block where it is unlocked
    bool valid;
  };

  struct token_collect_result
  {
    uint64_t token_amount; //amount of tokens that is relocked
    uint64_t interest; //collected interest from network fees over period
    uint32_t block_number; //block where it is unlocked
    bool valid;
  };

  struct donate_fee_result
  {
    uint64_t amount; //cash amount do donate to newtork token holders
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
  template<typename CommandResult>
  class command
  {
    public:

      friend class safex_command_serializer;

      /**
       * @param _version Safex command protocol version
       * @param _command_type actuall command, like token lock
      * */
      command(const uint32_t _version, const command_t _command_type) : version(_version), command_type(_command_type)
      {
        SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((_command_type < command_t::invalid_command), "Invalid command type", _command_type);
        SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES((_version <= SAFEX_COMMAND_PROTOCOL_VERSION), "Unsupported command protocol version " + std::to_string(_version), command_type);

      }

      virtual bool execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin, CommandResult &cr) = 0;

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

      virtual bool store(epee::serialization::portable_storage &ps) const;

      virtual bool load(epee::serialization::portable_storage &ps);

      uint32_t version;
      command_t command_type;
  };

  //Dummy command for serialization
  typedef struct{} dummy_struct;
  class dummy_command : public command<dummy_struct>
  {

    public:

      friend class safex_command_serializer;

      dummy_command() :  command<dummy_struct>(0, command_t::nop) {}

      virtual bool execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin, dummy_struct &cr) override { return false;};

      BEGIN_SERIALIZE_OBJECT()
        FIELDS(*static_cast<command<dummy_struct> *>(this))
      END_SERIALIZE()

    protected:
      virtual bool store(epee::serialization::portable_storage &ps) const override;
      virtual bool load(epee::serialization::portable_storage &ps) override;

  };


  //Token lock command
  class token_lock : public command<token_lock_result>
  {
    public:

      friend class safex_command_serializer;

      /**
       * @param _version Safex command protocol version
       * @param _token_amount amount of tokens to lock
      * */
      token_lock(const uint32_t _version, const uint64_t _token_amount) : command<token_lock_result>(_version, command_t::token_lock), lock_token_amount(_token_amount) {}

      token_lock() : command<token_lock_result>(0, command_t::token_lock), lock_token_amount(0) {}

      uint64_t get_lock_token_amount() const { return lock_token_amount; }

      virtual bool execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin, token_lock_result &cr) override;

      BEGIN_SERIALIZE_OBJECT()
        FIELDS(*static_cast<command<token_lock_result> *>(this))
        CHECK_COMMAND_TYPE(this->get_command_type(), command_t::token_lock);
        VARINT_FIELD(lock_token_amount)
      END_SERIALIZE()

    protected:
      virtual bool store(epee::serialization::portable_storage &ps) const override;
      virtual bool load(epee::serialization::portable_storage &ps) override;

      uint64_t lock_token_amount;
  };


  //Token unlock command
  class token_unlock : public command<token_unlock_result>
  {
    public:

      friend class safex_command_serializer;

      /**
       * @param _version Safex command protocol version
       * @param _locked_token_output_index global index of txout_to_script output that is being unlocked
      * */
      token_unlock(const uint32_t _version, const uint64_t _locked_token_output_index) : command<token_unlock_result>(_version, command_t::token_unlock),
              locked_token_output_index(_locked_token_output_index) {}

      token_unlock() : command<token_unlock_result>(0, command_t::token_unlock), locked_token_output_index(0) {}

      uint64_t get_locked_token_output_index() const { return locked_token_output_index; }

      virtual bool execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin, token_unlock_result &cr) override;

      BEGIN_SERIALIZE_OBJECT()
        FIELDS(*static_cast<command<token_unlock_result> *>(this))
        CHECK_COMMAND_TYPE(this->get_command_type(), command_t::token_unlock);
        VARINT_FIELD(locked_token_output_index)
      END_SERIALIZE()

    protected:

      virtual bool store(epee::serialization::portable_storage &ps) const override;
      virtual bool load(epee::serialization::portable_storage &ps) override;

      uint64_t locked_token_output_index;
  };


  //Token collect command
  class token_collect : public command<token_collect_result>
  {
    public:

      friend class safex_command_serializer;

      /**
       * @param _version Safex command protocol version
       * @param _locked_token_output_index global index of txout_to_script output that is being unlocked
       *
      * */
      token_collect(const uint32_t _version, const uint64_t _locked_token_output_index) : command<token_collect_result>(_version, command_t::token_collect),
                                                                                          locked_token_output_index(_locked_token_output_index) {}

      token_collect() : command<token_collect_result>(0, command_t::token_collect), locked_token_output_index(0) {}

      uint64_t get_locked_token_output_index() const { return locked_token_output_index; }

      virtual bool execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin, token_collect_result &cr) override;

      BEGIN_SERIALIZE_OBJECT()
        FIELDS(*static_cast<command<token_collect_result> *>(this))
        CHECK_COMMAND_TYPE(this->get_command_type(), command_t::token_collect);
        VARINT_FIELD(locked_token_output_index)
      END_SERIALIZE()

    protected:

      virtual bool store(epee::serialization::portable_storage &ps) const override;
      virtual bool load(epee::serialization::portable_storage &ps) override;

      uint64_t locked_token_output_index;
  };

  class donate_fee : public command<donate_fee_result>
  {
    public:
      friend class safex_command_serializer;

      /**
       * @param _version Safex command protocol version
       * @param _donate_amount //amount of safex cash that will be donated to the network token holder to be distributed as interest
      * */
      donate_fee(const uint32_t _version, const uint64_t _donation_safex_cash_amount) : command<donate_fee_result>(_version, command_t::donate_network_fee),
                                                                                       donation_safex_cash_amount(_donation_safex_cash_amount) {}

      donate_fee() : command<donate_fee_result>(0, command_t::donate_network_fee), donation_safex_cash_amount(0) {}

      uint64_t get_locked_token_output_index() const { return donation_safex_cash_amount; }

      virtual bool execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin, donate_fee_result &cr) override;

      BEGIN_SERIALIZE_OBJECT()
        FIELDS(*static_cast<command<donate_fee_result> *>(this))
        CHECK_COMMAND_TYPE(this->get_command_type(),  command_t::donate_network_fee);
        VARINT_FIELD(donation_safex_cash_amount)
      END_SERIALIZE()

    protected:

      virtual bool store(epee::serialization::portable_storage &ps) const override;
      virtual bool load(epee::serialization::portable_storage &ps) override;

      uint64_t donation_safex_cash_amount;
  };


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

      static command_t get_command_type(const std::vector<uint8_t> &script)
      {

        cryptonote::blobdata command_blob;
        const uint8_t* serialized_buffer_ptr = &script[0];
        std::copy(serialized_buffer_ptr, serialized_buffer_ptr + 2, std::back_inserter(command_blob));

        std::stringstream ss;
        ss << command_blob;
        binary_archive<false> ba(ss);
        dummy_command temp; //just take any command, we just need command type deserialized
        bool r = ::serialization::serialize(ba, static_cast<command<dummy_struct>&>(temp));
        SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES(r, "Failed to parse command from blob", command_t::invalid_command);

        return static_cast<command_t>(temp.get_command_type());
      }

      template<typename Command>
      static bool store_command_to_potable_storage(const Command &com, std::vector<uint8_t> &target)
      {
        epee::serialization::portable_storage ps = AUTO_VAL_INIT(ps);

        //here serialize particular
        com.store(ps);

        epee::serialization::binarybuffer bin_target = AUTO_VAL_INIT(bin_target);

        if (!ps.store_to_binary(bin_target))
        {
          throw safex::command_exception(com.get_command_type(), "Could not store to portable storage binary blob");
        }

        target.clear();
        target = std::vector<uint8_t>(bin_target.begin(), bin_target.end());

        return true;
      }

      template<typename Command>
      static bool load_command_from_portable_storage(const std::vector<uint8_t> &source, Command &com)
      {
        const epee::serialization::binarybuffer bin_source(source.begin(), source.end());
        epee::serialization::portable_storage ps = AUTO_VAL_INIT(ps);
        if (!ps.load_from_binary(bin_source))
        {
          throw safex::command_exception(command_t::invalid_command, "Could not load portable storage from binary blob");
        }

        com.load(ps);

        return true;

      }


      static command_t get_command_type_portable_storage(const std::vector<uint8_t> &source)
      {
        const epee::serialization::binarybuffer bin_source(source.begin(), source.end());
        epee::serialization::portable_storage ps = AUTO_VAL_INIT(ps);
        if (!ps.load_from_binary(bin_source))
        {
          throw safex::command_exception(command_t::nop, "Could not load portable storage from binary blob");
        }

        uint32_t command_type = 0;
        ps.get_value(FIELD_COMMAND, command_type, nullptr);

        return static_cast<command_t>(command_type);
      }

  };


} //namespace safex


#endif //SAFEX_COMMAND_H
