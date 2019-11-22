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
#include "safex_offer.h"
#include "safex_purchase.h"

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
    invalid = 1,
    error_wrong_input_params = 1,
    error_account_data_too_big = 10,
    error_account_already_exists = 11,
    error_invalid_account_name = 12,
    error_account_non_existant = 13,
    error_offer_non_existant = 14
  };

  struct execution_result
  {
    bool valid = false;
    execution_status status = execution_status::invalid;

    virtual ~execution_result() = default;
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

  struct simple_purchase_result : public execution_result
  {

      simple_purchase_result(){}

      simple_purchase_result(const crypto::hash &_offer_id, uint64_t _quantity, uint64_t _price, bool _shipping) :
                                                                                                offer_id(_offer_id),quantity{_quantity},
                                                                                                price{_price},shipping{_shipping}{}

      crypto::hash offer_id{}; //unique id of the offer
      uint64_t quantity{};
      uint64_t price;
      bool shipping{};

      BEGIN_SERIALIZE_OBJECT()
          FIELD(offer_id)
          FIELD(quantity)
          FIELD(price)
          FIELD(shipping)
      END_SERIALIZE()
  };

  struct distribute_fee_result : public execution_result
  {
    uint64_t amount = 0; //cash amount do donate to newtork token holders
  };

  struct create_account_result : public execution_result
  {

    create_account_result(){}

    create_account_result(const std::vector<uint8_t> &_username, const crypto::public_key &_pkey, const std::vector<uint8_t>& _account_data):
            username{_username}, pkey{_pkey}, account_data{_account_data}{
        output_ids.clear();
    }

    std::vector<uint8_t> username{};
    crypto::public_key pkey{};
    std::vector<uint8_t> account_data{};
    std::vector<uint64_t> output_ids{};

      BEGIN_SERIALIZE_OBJECT()
          FIELD(username)
          FIELD(pkey)
          FIELD(account_data)
          FIELD(output_ids)
      END_SERIALIZE()
  };

  struct edit_account_result : public execution_result
  {
    edit_account_result(const std::vector<uint8_t> &_username, std::vector<uint8_t>& _account_data):
            username{_username}, account_data{_account_data} {
    }
    std::vector<uint8_t> username{};
    crypto::public_key pkey{};
    std::vector<uint8_t> account_data{};
    uint64_t output_id{};

      BEGIN_SERIALIZE_OBJECT()
          FIELD(username)
          FIELD(pkey)
          FIELD(account_data)
          FIELD(output_id)
      END_SERIALIZE()
  };

struct create_offer_result : public execution_result
{

    create_offer_result(){}

    create_offer_result(crypto::hash _offer_id, std::vector<uint8_t> _seller, uint64_t _price, uint64_t _quantity,
            bool _active): offer_id{_offer_id},seller{_seller},price{_price},quantity{_quantity},active{_active},output_id{0} {

    }

    crypto::hash offer_id{};
    std::vector<uint8_t> seller{};
    uint64_t quantity{};
    uint64_t price;
    bool active{};
    uint64_t output_id{};

    BEGIN_SERIALIZE_OBJECT()
        FIELD(offer_id)
        FIELD(seller)
        FIELD(price)
        FIELD(quantity)
        FIELD(active)
        FIELD(output_id)
    END_SERIALIZE()

};

struct edit_offer_result : public execution_result
{

    edit_offer_result(){}

    edit_offer_result(crypto::hash _offer_id, std::vector<uint8_t> _seller, uint64_t _price, uint64_t _quantity,
                        bool _active): offer_id{_offer_id},seller{_seller},price{_price},quantity{_quantity},active{_active},output_id{0} {

    }

    crypto::hash offer_id{};
    std::vector<uint8_t> seller{};
    uint64_t quantity{};
    uint64_t price;
    bool active{};
    uint64_t output_id{};

    BEGIN_SERIALIZE_OBJECT()
        FIELD(offer_id)
        FIELD(seller)
        FIELD(price)
        FIELD(quantity)
        FIELD(active)
        FIELD(output_id)
    END_SERIALIZE()

};

struct close_offer_result : public execution_result
{

    close_offer_result(){}

    close_offer_result(crypto::hash _offer_id): offer_id{_offer_id} {

    }

    crypto::hash offer_id{};

    BEGIN_SERIALIZE_OBJECT()
        FIELD(offer_id)
    END_SERIALIZE()

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

  struct create_account_data : public command_data
  {
    std::vector<uint8_t> username{};
    crypto::public_key pkey;
    std::vector<uint8_t> account_data{};

    create_account_data() {}
    create_account_data(const std::string &_username, const crypto::public_key &_pkey, const std::vector<uint8_t> &_account_data): username(_username.begin(), _username.end()), pkey{_pkey}, account_data{_account_data}
    {

    }

    BEGIN_SERIALIZE_OBJECT()
      FIELD(username)
      FIELD(pkey)
      FIELD(account_data)
    END_SERIALIZE()
  };

  struct edit_account_data : public command_data
  {
    std::vector<uint8_t> username{};
    std::vector<uint8_t> account_data{};

    edit_account_data() {}

    edit_account_data(const std::string &_username, const std::vector<uint8_t> &_account_data): username(_username.begin(), _username.end()), account_data{_account_data}
    {

    }


    BEGIN_SERIALIZE_OBJECT()
      FIELD(username)
      FIELD(account_data)
    END_SERIALIZE()
  };

    struct create_offer_data : public command_data
    {
        crypto::hash offer_id{};
        std::vector<uint8_t> seller{};
        std::vector<uint8_t> title{};
        uint64_t quantity;
        uint64_t price;
        std::vector<uint8_t> description{};
        bool active{false};

        create_offer_data() {}
        create_offer_data(const safex::safex_offer& offer): offer_id{offer.offer_id}, description{offer.description},quantity{offer.quantity},price{offer.price},seller(offer.seller.begin(),offer.seller.end()),active{offer.active},title{offer.title.begin(),offer.title.end()}
        {
        }
        create_offer_data(const crypto::hash &_offer_id, const std::vector<uint8_t> &_seller, const std::vector<uint8_t> &_title, const uint64_t &_quantity, const uint64_t &_price, const std::vector<uint8_t> &_offer_data,const bool &_active):
                                    offer_id{_offer_id},seller{_seller},title{_title},quantity{_quantity},price{_price},description{_offer_data},active{_active}{}

        BEGIN_SERIALIZE_OBJECT()
            FIELD(offer_id)
            FIELD(seller)
            FIELD(title)
            FIELD(price)
            FIELD(quantity)
            FIELD(active)
            FIELD(description)
        END_SERIALIZE()
    };

    struct edit_offer_data : public command_data
    {
        crypto::hash offer_id{};
        std::vector<uint8_t> seller{};
        std::vector<uint8_t> title{};
        uint64_t quantity;
        uint64_t price;
        std::vector<uint8_t> description{};
        bool active{false};

        edit_offer_data() {}
        edit_offer_data(const safex::safex_offer& offer): offer_id{offer.offer_id},title{offer.title.begin(),offer.title.end()}, description{offer.description},quantity{offer.quantity},price{offer.price},seller(offer.seller.begin(),offer.seller.end()),active{offer.active}
        {
        }
        edit_offer_data(const crypto::hash &_offer_id, const std::vector<uint8_t> &_seller, const std::vector<uint8_t> &_title, const uint64_t &_quantity, const uint64_t &_price, const std::vector<uint8_t> &_offer_data,const bool &_active):
                offer_id{_offer_id},seller{_seller},title{_title},quantity{_quantity},price{_price},description{_offer_data},active{_active}{}

        BEGIN_SERIALIZE_OBJECT()
            FIELD(offer_id)
            FIELD(seller)
            FIELD(title)
            FIELD(price)
            FIELD(quantity)
            FIELD(active)
            FIELD(description)
        END_SERIALIZE()
    };

    struct close_offer_data : public command_data
    {
        crypto::hash offer_id{};
        crypto::public_key safex_account_pkey{};
        std::vector<uint8_t> seller{};
        close_offer_data() {}
        close_offer_data(const safex::safex_offer& offer): offer_id{offer.offer_id},seller{offer.seller.begin(),offer.seller.end()}
        {
        }
        close_offer_data(const crypto::hash &_offer_id, const crypto::public_key& _safex_account_pkey, const std::string &_seller = {}):
                            offer_id{_offer_id},safex_account_pkey{_safex_account_pkey},seller{_seller.begin(),_seller.end()}{}

        BEGIN_SERIALIZE_OBJECT()
            FIELD(offer_id)
            FIELD(seller)
            FIELD(safex_account_pkey)
        END_SERIALIZE()
    };

    struct create_purchase_data : public command_data
    {
        crypto::hash offer_id{}; //unique id of the offer
        uint64_t quantity{};
        uint64_t price;
        bool shipping{};

        create_purchase_data() {}
        create_purchase_data(const safex::safex_purchase& purchase): offer_id{purchase.offer_id},quantity{purchase.quantity},price{purchase.price},
                                                                     shipping{purchase.shipping}
        {
        }
        create_purchase_data(const crypto::hash &_offer_id, const uint64_t &_quantity, const uint64_t &_price):
                offer_id{_offer_id},quantity{_quantity},price{_price}{}

        BEGIN_SERIALIZE_OBJECT()
            FIELD(offer_id)
            FIELD(quantity)
            FIELD(price)
            FIELD(shipping)
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
      virtual execution_status validate(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) = 0;

      uint32_t get_version() const
      { return version; }

      command_t get_command_type() const
      { return command_type; }

      virtual ~command() = default;

      BEGIN_SERIALIZE_OBJECT()
        VARINT_FIELD(version)
        VARINT_FIELD(command_type)
      END_SERIALIZE()

    private:

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
      virtual execution_status validate(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override {return execution_status::ok;};

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
      token_stake(const uint32_t _version, const uint64_t _token_amount) : command(_version, command_t::token_stake), stake_token_amount(_token_amount) {

     }

      token_stake() : command(0, command_t::token_stake), stake_token_amount(0) {

      }

      uint64_t get_staked_token_amount() const { return stake_token_amount; }

      virtual token_stake_result* execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;
      virtual execution_status validate(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;

      BEGIN_SERIALIZE_OBJECT()
        FIELDS(*static_cast<command *>(this))
        CHECK_COMMAND_TYPE(this->get_command_type(), command_t::token_stake);
        VARINT_FIELD(stake_token_amount)
      END_SERIALIZE()

    private:

      uint64_t stake_token_amount;
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
              staked_token_output_index(_staked_token_output_index) {

      }

      token_unstake() : command(0, command_t::token_unstake), staked_token_output_index(0) {

      }

      uint64_t get_staked_token_output_index() const { return staked_token_output_index; }

      virtual token_unstake_result* execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;
      virtual execution_status validate(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;

      BEGIN_SERIALIZE_OBJECT()
        FIELDS(*static_cast<command*>(this))
        CHECK_COMMAND_TYPE(this->get_command_type(), command_t::token_unstake);
        VARINT_FIELD(staked_token_output_index)
      END_SERIALIZE()

    private:

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
      virtual execution_status validate(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;

      BEGIN_SERIALIZE_OBJECT()
        FIELDS(*static_cast<command *>(this))
        CHECK_COMMAND_TYPE(this->get_command_type(), command_t::token_collect);
        VARINT_FIELD(staked_token_output_index)
      END_SERIALIZE()

    private:

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
      virtual execution_status validate(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;

      BEGIN_SERIALIZE_OBJECT()
        FIELDS(*static_cast<command *>(this))
        CHECK_COMMAND_TYPE(this->get_command_type(),  command_t::donate_network_fee);
        VARINT_FIELD(donation_safex_cash_amount)
      END_SERIALIZE()

    private:

      uint64_t donation_safex_cash_amount;
  };

  class simple_purchase : public command
  {
    public:
      friend class safex_command_serializer;

      /**
       * @param _version Safex command protocol version
       * @param _simple_purchase_price Simple purschase cash amount
      * */
      simple_purchase(const uint32_t _version, const safex::create_purchase_data &sfx_purchase) : command(_version, command_t::simple_purchase),
                                                                                                  offer_id(sfx_purchase.offer_id),quantity{sfx_purchase.quantity},
                                                                                                  price{sfx_purchase.price},shipping{sfx_purchase.shipping}{}

      simple_purchase() : command(0, command_t::simple_purchase) {}


      virtual simple_purchase_result* execute(const cryptonote::BlockchainDB &blockchain, const cryptonote::txin_to_script &txin) override;
      virtual execution_status validate(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;

      BEGIN_SERIALIZE_OBJECT()
        FIELDS(*static_cast<command *>(this))
        CHECK_COMMAND_TYPE(this->get_command_type(),  command_t::simple_purchase);
        FIELD(offer_id)
        FIELD(quantity)
        FIELD(price)
        FIELD(shipping)
      END_SERIALIZE()

    private:

      crypto::hash offer_id{}; //unique id of the offer
      uint64_t quantity{};
      uint64_t price{};
      bool shipping{};
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
      virtual execution_status validate(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;

      BEGIN_SERIALIZE_OBJECT()
        FIELDS(*static_cast<command *>(this))
        CHECK_COMMAND_TYPE(this->get_command_type(),  command_t::distribute_network_fee);
        VARINT_FIELD(safex_cash_amount)
      END_SERIALIZE()

    private:

      uint64_t safex_cash_amount;
  };

  class create_account : public command
  {
    public:
      friend class safex_command_serializer;

      /**
       * @param _version Safex command protocol version
       * @param _username //new account username
       * @param _pkey //public account key, that is used to verify signatures of account owner actions
       * @param _account_data //account description
      * */
      create_account(const uint32_t _version, std::vector<uint8_t> &_username, const crypto::public_key &_pkey, const std::vector<uint8_t> &_account_data) :
      command(_version, command_t::create_account), username(_username), pkey{_pkey}, account_data{_account_data} {}

      create_account() : command(0, command_t::create_account), username{}, pkey{}, account_data{} {}

      std::string get_username() const { return std::string(std::begin(username), std::end(username)); }
      crypto::public_key get_account_key() const { return pkey; }
      std::vector<uint8_t> get_account_data() const { return account_data; }

      virtual create_account_result* execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;
      virtual execution_status validate(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;

      BEGIN_SERIALIZE_OBJECT()
        FIELDS(*static_cast<command *>(this))
        CHECK_COMMAND_TYPE(this->get_command_type(),  command_t::create_account);
        FIELD(username)
        FIELD(pkey)
        FIELD(account_data)
      END_SERIALIZE()

    private:

      std::vector<uint8_t> username{};
      crypto::public_key pkey;
      std::vector<uint8_t> account_data{};
  };

  class edit_account : public command
  {
    public:
      friend class safex_command_serializer;

      /**
       * @param _version Safex command protocol version
       * @param _username //new account username
       * @param _account_data //new account description data
      * */
      edit_account(const uint32_t _version, const std::vector<uint8_t> _username, const std::vector<uint8_t> _new_account_data) :
              command(_version, command_t::edit_account), username(_username), new_account_data{_new_account_data} {}

      edit_account() : command(0, command_t::edit_account), username{}, new_account_data{} {}

      std::string get_username() const { return std::string(username.begin(), username.end()); }
      std::vector<uint8_t> get_new_account_data() const { return new_account_data; }

      virtual edit_account_result* execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;
      virtual execution_status validate(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;

      BEGIN_SERIALIZE_OBJECT()
        FIELDS(*static_cast<command *>(this))
        CHECK_COMMAND_TYPE(this->get_command_type(),  command_t::edit_account);
        FIELD(username)
        FIELD(new_account_data)
      END_SERIALIZE()

    private:

      std::vector<uint8_t> username{};
      std::vector<uint8_t> new_account_data{};
  };

class create_offer : public command
{
public:
    friend class safex_command_serializer;

    /**
     * @param _version Safex command protocol version
     * @param _offerid //ID of the offer
     * @param _offer_data //offer data
    * */
    create_offer(const uint32_t _version, const safex::create_offer_data &offer) :
            command(_version, command_t::create_offer), offer_id(offer.offer_id), description{offer.description},
            seller{offer.seller},title{offer.title},price{offer.price},quantity{offer.quantity},active{offer.active}{
    }

    create_offer() : command(0, command_t::create_offer), offer_id{}, description{} {}

    crypto::hash get_offerid() const { return offer_id; }
    std::vector<uint8_t> get_seller() const { return seller; }
    std::vector<uint8_t> get_title() const { return title; }
    uint64_t get_price() const { return price; }
    uint64_t get_quantity() const { return quantity; }
    bool get_active() const { return active; }
    std::vector<uint8_t> get_description() const { return description; }

    virtual create_offer_result* execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;
    virtual execution_status validate(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;

    BEGIN_SERIALIZE_OBJECT()
        FIELDS(*static_cast<command *>(this))
        CHECK_COMMAND_TYPE(this->get_command_type(),  command_t::create_offer);
        FIELD(offer_id)
        FIELD(seller)
        FIELD(title)
        FIELD(price)
        FIELD(quantity)
        FIELD(active)
        FIELD(description)
    END_SERIALIZE()

private:
    crypto::hash offer_id{};
    std::vector<uint8_t> seller{};
    std::vector<uint8_t> title{};
    uint64_t quantity{};
    uint64_t price;
    std::vector<uint8_t> description{};
    bool active{};
};

class edit_offer : public command
{
public:
    friend class safex_command_serializer;

    /**
     * @param _version Safex command protocol version
     * @param _offerid //ID of the offer
     * @param _offer_data //offer data
    * */
    edit_offer(const uint32_t _version, const safex::edit_offer_data &offer) :
            command(_version, command_t::edit_offer), offer_id(offer.offer_id), title{offer.title}, description{offer.description},
            seller{offer.seller},price{offer.price},quantity{offer.quantity},active{offer.active}{
    }

    edit_offer() : command(0, command_t::edit_offer), offer_id{}, description{} {}

    crypto::hash get_offerid() const { return offer_id; }
    std::vector<uint8_t> get_seller() const { return seller; }
    uint64_t get_price() const { return price; }
    uint64_t get_quantity() const { return quantity; }
    bool get_active() const { return active; }
    std::vector<uint8_t> get_title() const { return title; };
    std::vector<uint8_t> get_description() const { return description; }

    virtual edit_offer_result* execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;
    virtual execution_status validate(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;

    BEGIN_SERIALIZE_OBJECT()
        FIELDS(*static_cast<command *>(this))
        CHECK_COMMAND_TYPE(this->get_command_type(),  command_t::edit_offer);
        FIELD(offer_id)
        FIELD(seller)
        FIELD(title)
        FIELD(price)
        FIELD(quantity)
        FIELD(active)
        FIELD(description)
    END_SERIALIZE()

private:
    crypto::hash offer_id{};
    std::vector<uint8_t> seller{};
    std::vector<uint8_t> title{};
    uint64_t quantity{};
    uint64_t price{};
    std::vector<uint8_t> description{};
    bool active{};
};

class close_offer : public command
{
public:
    friend class safex_command_serializer;

    /**
     * @param _version Safex command protocol version
     * @param _offerid //ID of the offer
    * */
    close_offer(const uint32_t _version, const safex::close_offer_data &offer) :
            command(_version, command_t::close_offer), offer_id(offer.offer_id), safex_account_pkey(offer.safex_account_pkey), seller{offer.seller}{
    }

    close_offer() : command(0, command_t::close_offer), offer_id{},safex_account_pkey{}{}

    crypto::hash get_offerid() const { return offer_id; }
    crypto::public_key get_safex_account_pkey() const { return safex_account_pkey; }
    std::vector<uint8_t> get_seller() const { return seller; }

    virtual close_offer_result* execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;
    virtual execution_status validate(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;

    BEGIN_SERIALIZE_OBJECT()
        FIELDS(*static_cast<command *>(this))
        CHECK_COMMAND_TYPE(this->get_command_type(),  command_t::close_offer);
        FIELD(offer_id)
        FIELD(safex_account_pkey)
        FIELD(seller)
    END_SERIALIZE()

private:
    crypto::hash offer_id{};
    crypto::public_key safex_account_pkey{};
    std::vector<uint8_t> seller{};
};

  bool execute_safex_command(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin);
  /* Validation is like execution, but without effects on the database */
  bool validate_safex_command(const cryptonote::BlockchainDB &blockchain, const cryptonote::txin_to_script &txin);



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

      template<typename CMD>
      static std::unique_ptr <CMD> parse_safex_command(const std::vector <uint8_t> &buffer)
      {
        return std::unique_ptr<CMD>(parse_safex_object<CMD>(buffer));
      }

      static std::unique_ptr<command> parse_safex_object(const std::vector<uint8_t> &buffer, const safex::command_t command_type)
      {

        switch(command_type) {
          case safex::command_t::token_stake:
            return std::unique_ptr<command>(parse_safex_object<token_stake>(buffer));
            break;
          case safex::command_t::token_unstake:
            return std::unique_ptr<command>(parse_safex_object<token_unstake>(buffer));
            break;
          case safex::command_t::token_collect:
            return std::unique_ptr<command>(parse_safex_object<token_collect>(buffer));
            break;
          case safex::command_t::distribute_network_fee:
            return std::unique_ptr<command>(parse_safex_object<distribute_fee>(buffer));
            break;
          case safex::command_t::donate_network_fee:
            return std::unique_ptr<command>(parse_safex_object<donate_fee>(buffer));
            break;
          case safex::command_t::simple_purchase:
            return std::unique_ptr<command>(parse_safex_object<simple_purchase>(buffer));
            break;
          case safex::command_t::create_account:
            return std::unique_ptr<command>(parse_safex_object<create_account>(buffer));
            break;
          case safex::command_t::edit_account:
            return std::unique_ptr<command>(parse_safex_object<edit_account>(buffer));
            break;
          case safex::command_t::create_offer:
            return std::unique_ptr<command>(parse_safex_object<create_offer>(buffer));
            break;
          case safex::command_t::edit_offer:
             return std::unique_ptr<command>(parse_safex_object<edit_offer>(buffer));
             break;
          case safex::command_t::close_offer:
              return std::unique_ptr<command>(parse_safex_object<close_offer>(buffer));
              break;
          default:
            SAFEX_COMMAND_ASSERT_MES_AND_THROW("Unknown safex command type", safex::command_t::invalid_command);
            break;
        }
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

    private:

      template<typename CommandOrData>
      static CommandOrData* parse_safex_object(const std::vector<uint8_t> &buffer)
      {
        cryptonote::blobdata command_blob;
        const uint8_t* serialized_buffer_ptr = &buffer[0];
        std::copy(serialized_buffer_ptr, serialized_buffer_ptr + buffer.size(), std::back_inserter(command_blob));

        std::stringstream ss;
        ss << command_blob;
        binary_archive<false> ba(ss);

        CommandOrData* commandOrData = new CommandOrData();
        bool r = ::serialization::serialize(ba, *commandOrData);
        SAFEX_COMMAND_CHECK_AND_ASSERT_THROW_MES(r, "Failed to parse command or data from blob", command_t::invalid_command);
        return commandOrData;
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
  };


} //namespace safex


#endif //SAFEX_COMMAND_H
