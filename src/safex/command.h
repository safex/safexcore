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
#include "safex_feedback.h"

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
    // Safex stake token
    error_stake_token_amount_not_matching = 2,
    error_stake_token_not_whole_amount = 3,
    // Safex account
    error_account_data_too_big = 10,
    error_account_already_exists = 11,
    error_invalid_account_name = 12,
    error_account_non_existant = 13,
    error_account_no_tokens = 14,
    // Safex purchase
    error_offer_non_existant = 20,
    error_purchase_out_of_stock = 21,
    error_purchase_not_enough_funds = 23,
    error_purchase_offer_not_active = 24,
    error_purchase_quantity_zero = 25,
    // Safex offer
    error_offer_price_too_big = 30,
    error_offer_price_too_small = 31,
    error_offer_data_too_big = 32,
    error_offer_price_peg_not_existant = 33,
    // Safex feedback
    error_feedback_invalid_rating = 40,
    error_feedback_data_too_big = 41,
    // Safex price peg
    error_price_peg_bad_currency_format = 51,
    error_price_peg_data_too_big = 52,
    error_price_peg_not_existant = 53,
    error_price_peg_rate_zero = 54,
    // Safex unstake token
    error_unstake_token_output_not_found = 60,
    error_unstake_token_minimum_period = 61,
    error_unstake_token_network_fee_not_matching = 62,
    error_unstake_token_offset_not_one = 63,
    error_unstake_token_output_not_matching = 64
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

  struct create_account_result : public execution_result
  {

    create_account_result(){}

    create_account_result(const std::vector<uint8_t> &_username, const crypto::public_key &_pkey, const std::vector<uint8_t>& _account_data):
            username{_username}, pkey{_pkey}, account_data{_account_data}{
    }

    std::vector<uint8_t> username{};
    crypto::public_key pkey{};
    std::vector<uint8_t> account_data{};

      BEGIN_SERIALIZE_OBJECT()
          FIELD(username)
          FIELD(pkey)
          FIELD(account_data)
      END_SERIALIZE()
  };

  struct edit_account_result : public execution_result
  {
    edit_account_result(const std::vector<uint8_t> &_username, std::vector<uint8_t>& _account_data):
            username{_username}, account_data{_account_data} {
    }
    std::vector<uint8_t> username{};
    std::vector<uint8_t> account_data{};

      BEGIN_SERIALIZE_OBJECT()
          FIELD(username)
          FIELD(account_data)
      END_SERIALIZE()
  };

struct create_offer_result : public execution_result
{

    create_offer_result(){}

    create_offer_result(crypto::hash _offer_id, std::vector<uint8_t> _seller, uint64_t _price, uint64_t _quantity,
            bool _active): offer_id{_offer_id},seller{_seller},price{_price},quantity{_quantity},active{_active} {
    }

    crypto::hash offer_id{};
    std::vector<uint8_t> seller{};
    uint64_t quantity{};
    uint64_t price;
    bool active{};
    uint64_t output_id{};
    uint64_t output_id_creation{};
    bool edited{false};

    BEGIN_SERIALIZE_OBJECT()
        FIELD(offer_id)
        FIELD(seller)
        FIELD(price)
        FIELD(quantity)
        FIELD(active)
        FIELD(output_id)
        FIELD(output_id_creation)
        FIELD(edited)
    END_SERIALIZE()

};

struct edit_offer_result : public execution_result
{

    edit_offer_result(){}

    edit_offer_result(crypto::hash _offer_id, std::vector<uint8_t> _seller, uint64_t _price, uint64_t _quantity,
                        bool _active): offer_id{_offer_id},seller{_seller},price{_price},quantity{_quantity},active{_active} {

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

struct create_feedback_result : public execution_result
{

    create_feedback_result(){}

    create_feedback_result(crypto::hash _offer_id, std::vector<uint8_t> _comment, uint8_t _stars_given): offer_id{_offer_id},comment{_comment},stars_given{_stars_given} {

    }

    crypto::hash offer_id{}; //unique id of the offer
    uint8_t stars_given;
    std::vector<uint8_t> comment{};

    BEGIN_SERIALIZE_OBJECT()
        FIELD(offer_id)
        FIELD(stars_given)
        FIELD(comment)
    END_SERIALIZE()

};

struct create_price_peg_result : public execution_result
{

    create_price_peg_result(){}

    create_price_peg_result(crypto::hash _price_peg_id, std::vector<uint8_t> _title, std::vector<uint8_t> _creator, std::vector<uint8_t> _description, std::vector<uint8_t> _currency,uint64_t _rate)
      :price_peg_id{_price_peg_id},title{_title},creator{_creator}, description{_description}, currency{_currency},rate{_rate} {
      output_ids.clear();
    }

    std::vector<uint8_t> title; //title of the price peg
    crypto::hash price_peg_id; //unique id of the price peg
    std::vector<uint8_t> creator; // username of the price peg
    std::vector<uint8_t> description; //description of price peg
    std::vector<uint8_t> currency;
    uint64_t rate;
    std::vector<uint64_t> output_ids{};

    BEGIN_SERIALIZE_OBJECT()
      FIELD(title)
      FIELD(price_peg_id)
      FIELD(creator)
      FIELD(description)
      FIELD(currency)
      FIELD(rate)
      FIELD(output_ids)
    END_SERIALIZE()

};

    struct update_price_peg_result : public execution_result
    {

        update_price_peg_result(){}

        update_price_peg_result(crypto::hash _price_peg_id,uint64_t _rate)
                :price_peg_id{_price_peg_id},rate{_rate} {
          output_ids.clear();
        }

        crypto::hash price_peg_id; //unique id of the price peg
        uint64_t rate;
        std::vector<uint64_t> output_ids{};

        BEGIN_SERIALIZE_OBJECT()
          FIELD(price_peg_id)
          FIELD(rate)
          FIELD(output_ids)
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
        crypto::hash price_peg_id{};
        std::vector<uint8_t> seller{};
        std::vector<uint8_t> title{};
        uint64_t quantity;
        uint64_t price;
        uint64_t min_sfx_price;
        std::vector<uint8_t> description{};
        bool active{false};
        bool price_peg_used{false};
        crypto::secret_key seller_private_view_key;
        cryptonote::account_public_address seller_address;

        create_offer_data() {}
        create_offer_data(const safex::safex_offer& offer): offer_id{offer.offer_id}, description{offer.description},quantity{offer.quantity},price{offer.price},seller(offer.seller.begin(),offer.seller.end()),active{offer.active},title{offer.title.begin(),offer.title.end()},seller_address{offer.seller_address},seller_private_view_key{offer.seller_private_view_key},
                                                            price_peg_id{offer.price_peg_id},min_sfx_price{offer.min_sfx_price},price_peg_used{offer.price_peg_used}
        {
        }
        create_offer_data(const crypto::hash &_offer_id, const std::vector<uint8_t> &_seller, const std::vector<uint8_t> &_title, const uint64_t &_quantity, const uint64_t &_price, const std::vector<uint8_t> &_offer_data,const bool &_active, const cryptonote::account_public_address& _seller_address, const crypto::secret_key& _seller_private_view_key, const crypto::hash& _price_peg_id, const uint64_t _min_sfx_price, const bool _price_peg_used):
                                    offer_id{_offer_id},seller{_seller},title{_title},quantity{_quantity},price{_price},description{_offer_data},active{_active},seller_address{_seller_address},seller_private_view_key{_seller_private_view_key},price_peg_id{_price_peg_id},min_sfx_price{_min_sfx_price},price_peg_used{_price_peg_used}{}

        BEGIN_SERIALIZE_OBJECT()
            FIELD(offer_id)
            FIELD(price_peg_id)
            FIELD(seller)
            FIELD(title)
            FIELD(price)
            FIELD(min_sfx_price)
            FIELD(quantity)
            FIELD(active)
            FIELD(price_peg_used)
            FIELD(description)
            FIELD(seller_private_view_key)
            FIELD(seller_address)
        END_SERIALIZE()
    };

    struct edit_offer_data : public command_data
    {
        crypto::hash offer_id{};
        crypto::hash price_peg_id{};
        std::vector<uint8_t> seller{};
        std::vector<uint8_t> title{};
        uint64_t quantity;
        uint64_t price;
        uint64_t min_sfx_price;
        std::vector<uint8_t> description{};
        bool active{false};
        bool price_peg_used{false};

        edit_offer_data() {}
        edit_offer_data(const safex::safex_offer& offer): offer_id{offer.offer_id},title{offer.title.begin(),offer.title.end()}, description{offer.description},quantity{offer.quantity},price{offer.price},seller(offer.seller.begin(),offer.seller.end()),active{offer.active},
                                                          price_peg_id{offer.price_peg_id},min_sfx_price{offer.min_sfx_price},price_peg_used{offer.price_peg_used}
        {
        }
        edit_offer_data(const crypto::hash &_offer_id, const std::vector<uint8_t> &_seller, const std::vector<uint8_t> &_title, const uint64_t &_quantity, const uint64_t &_price, const std::vector<uint8_t> &_offer_data,const bool &_active, const crypto::hash& _price_peg_id, const uint64_t _min_sfx_price, const bool _price_peg_used):
                offer_id{_offer_id},seller{_seller},title{_title},quantity{_quantity},price{_price},description{_offer_data},active{_active},price_peg_id{_price_peg_id},min_sfx_price{_min_sfx_price},price_peg_used{_price_peg_used}{}

        BEGIN_SERIALIZE_OBJECT()
            FIELD(offer_id)
            FIELD(price_peg_id)
            FIELD(seller)
            FIELD(title)
            FIELD(price)
            FIELD(min_sfx_price)
            FIELD(quantity)
            FIELD(active)
            FIELD(price_peg_used)
            FIELD(description)
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

    struct create_feedback_token_data : public command_data
    {
        crypto::hash offer_id{}; //unique id of the offer


        create_feedback_token_data() {}
        create_feedback_token_data(const safex::safex_purchase& purchase): offer_id{purchase.offer_id}
        {
        }
        create_feedback_token_data(const safex::safex_feedback_token& feedback_token): offer_id{feedback_token.offer_id}
        {
        }

        BEGIN_SERIALIZE_OBJECT()
            FIELD(offer_id)
        END_SERIALIZE()
    };

    struct create_feedback_data : public command_data
    {
        crypto::hash offer_id{}; //unique id of the offer
        uint8_t stars_given;
        std::vector<uint8_t> comment{};

        create_feedback_data() {}
        create_feedback_data(const safex::safex_feedback& feedback): offer_id{feedback.offer_id},stars_given{feedback.stars_given},comment{feedback.comment.begin(),feedback.comment.end()}{
        }
        create_feedback_data(const crypto::hash &_offer_id, const uint8_t &_stars_given, const std::vector<uint8_t> _comment):
                offer_id{_offer_id},stars_given{_stars_given},comment{_comment}{}

        BEGIN_SERIALIZE_OBJECT()
            FIELD(offer_id)
            FIELD(stars_given)
            FIELD(comment)
        END_SERIALIZE()
    };


    struct create_price_peg_data : public command_data
    {
        std::vector<uint8_t> title; //title of the price peg
        crypto::hash price_peg_id; //unique id of the price peg
        std::vector<uint8_t> creator; // username of the price peg
        std::vector<uint8_t> description; //description of price peg
        std::vector<uint8_t> currency;
        uint64_t rate;

        create_price_peg_data() {}
        create_price_peg_data(const safex::safex_price_peg& price_peg): title{price_peg.title.begin(),price_peg.title.end()}, description{price_peg.description},price_peg_id{price_peg.price_peg_id},creator{price_peg.creator.begin(),price_peg.creator.end()},currency(price_peg.currency.begin(),price_peg.currency.end()),rate{price_peg.rate}
        {
        }

        create_price_peg_data(const  std::vector<uint8_t>& _title, const crypto::hash& _price_peg_id, const std::vector<uint8_t>& _creator, const std::vector<uint8_t>& _description, const std::vector<uint8_t>& _currency, const uint64_t& _rate):
                          title{_title},price_peg_id{_price_peg_id}, creator{_creator},description{_description},currency{_currency},rate{_rate}
        {
        }

        BEGIN_SERIALIZE_OBJECT()
          FIELD(title)
          FIELD(price_peg_id)
          FIELD(creator)
          FIELD(description)
          FIELD(currency)
          FIELD(rate)
        END_SERIALIZE()
    };

    struct update_price_peg_data : public command_data
    {
        crypto::hash price_peg_id; //unique id of the price peg
        uint64_t rate;

        update_price_peg_data() {}
        update_price_peg_data(const safex::safex_price_peg& price_peg): price_peg_id{price_peg.price_peg_id},rate{price_peg.rate}
        {
        }

        update_price_peg_data(const crypto::hash& _price_peg_id, const uint64_t& _rate):
                price_peg_id{_price_peg_id}, rate{_rate}
        {
        }

        BEGIN_SERIALIZE_OBJECT()
          FIELD(price_peg_id)
          FIELD(rate)
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

      crypto::hash get_offerid(){ return offer_id; }
      uint64_t get_quantity(){ return quantity; }
      uint64_t get_price(){ return price; }
      bool get_shipping() { return shipping; }

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

      create_account(const uint32_t _version, const std::string &_username, const crypto::public_key &_pkey, const std::string &_account_data) :
      command(_version, command_t::create_account), username(_username.begin(), _username.end()), pkey{_pkey}, account_data(_account_data.begin(), _account_data.end()) {}

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
     * @param offer //offer data
    * */
    create_offer(const uint32_t _version, const safex::create_offer_data &offer) :
            command(_version, command_t::create_offer), offer_id(offer.offer_id), description{offer.description},
            seller{offer.seller},title{offer.title},price{offer.price},quantity{offer.quantity},active{offer.active},seller_address{offer.seller_address},seller_private_view_key{offer.seller_private_view_key},
            min_sfx_price{offer.min_sfx_price},price_peg_id{offer.price_peg_id},price_peg_used{offer.price_peg_used}{
    }

    create_offer() : command(0, command_t::create_offer), offer_id{}, description{} {}

    crypto::hash get_offerid() const { return offer_id; }
    crypto::hash get_price_peg_id() const { return price_peg_id; }
    std::vector<uint8_t> get_seller() const { return seller; }
    std::vector<uint8_t> get_title() const { return title; }
    uint64_t get_price() const { return price; }
    uint64_t get_min_sfx_price() const { return min_sfx_price; }
    uint64_t get_quantity() const { return quantity; }
    bool get_active() const { return active; }
    bool get_price_peg_used() const { return price_peg_used; }
    std::vector<uint8_t> get_description() const { return description; }
    cryptonote::account_public_address get_seller_address() const { return seller_address; }
    crypto::secret_key get_seller_private_view_key() const { return seller_private_view_key; }

    virtual create_offer_result* execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;
    virtual execution_status validate(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;

    BEGIN_SERIALIZE_OBJECT()
        FIELDS(*static_cast<command *>(this))
        CHECK_COMMAND_TYPE(this->get_command_type(),  command_t::create_offer);
        FIELD(offer_id)
        FIELD(price_peg_id)
        FIELD(seller)
        FIELD(title)
        FIELD(price)
        FIELD(min_sfx_price)
        FIELD(quantity)
        FIELD(active)
        FIELD(price_peg_used)
        FIELD(description)
        FIELD(seller_private_view_key)
        FIELD(seller_address)
    END_SERIALIZE()

private:
    crypto::hash offer_id{};
    crypto::hash price_peg_id{};
    std::vector<uint8_t> seller{};
    std::vector<uint8_t> title{};
    uint64_t quantity{};
    uint64_t price;
    uint64_t min_sfx_price;
    std::vector<uint8_t> description{};
    bool active{};
    bool price_peg_used{}; // is offer using price peg
    crypto::secret_key seller_private_view_key;
    cryptonote::account_public_address seller_address;
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
            seller{offer.seller},price{offer.price},quantity{offer.quantity},active{offer.active},
            min_sfx_price{offer.min_sfx_price},price_peg_id{offer.price_peg_id},price_peg_used{offer.price_peg_used}{
    }

    edit_offer() : command(0, command_t::edit_offer), offer_id{}, description{} {}

    crypto::hash get_offerid() const { return offer_id; }
    crypto::hash get_price_peg_id() const { return price_peg_id; }
    std::vector<uint8_t> get_seller() const { return seller; }
    uint64_t get_price() const { return price; }
    uint64_t get_min_sfx_price() const { return min_sfx_price; }
    uint64_t get_quantity() const { return quantity; }
    bool get_active() const { return active; }
    bool get_price_peg_used() const { return price_peg_used; }
    std::vector<uint8_t> get_title() const { return title; };
    std::vector<uint8_t> get_description() const { return description; }

    virtual edit_offer_result* execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;
    virtual execution_status validate(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;

    BEGIN_SERIALIZE_OBJECT()
        FIELDS(*static_cast<command *>(this))
        CHECK_COMMAND_TYPE(this->get_command_type(),  command_t::edit_offer);
        FIELD(offer_id)
        FIELD(price_peg_id)
        FIELD(seller)
        FIELD(title)
        FIELD(price)
        FIELD(min_sfx_price)
        FIELD(quantity)
        FIELD(active)
        FIELD(price_peg_used)
        FIELD(description)
    END_SERIALIZE()

private:
    crypto::hash offer_id{};
    crypto::hash price_peg_id{};
    std::vector<uint8_t> seller{};
    std::vector<uint8_t> title{};
    uint64_t quantity{};
    uint64_t price{};
    uint64_t min_sfx_price;
    std::vector<uint8_t> description{};
    bool active{};
    bool price_peg_used{}; // is offer using price peg
};

class create_feedback : public command
{
public:
    friend class safex_command_serializer;

    /**
     * @param _version Safex command protocol version
     * @param _offerid //ID of the offer
    * */
    create_feedback(const uint32_t _version, const safex::create_feedback_data &feedback) :
            command(_version, command_t::create_feedback), offer_id(feedback.offer_id), comment{feedback.comment}, stars_given{feedback.stars_given}{
    }

    create_feedback() : command(0, command_t::create_feedback), offer_id{}, stars_given{}, comment{} {}

    crypto::hash get_offerid() const { return offer_id; }
    std::vector<uint8_t> get_comment() const { return comment; }
    uint8_t get_stars_given() const { return stars_given; }

    virtual create_feedback_result* execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;
    virtual execution_status validate(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;

    BEGIN_SERIALIZE_OBJECT()
        FIELDS(*static_cast<command *>(this))
        CHECK_COMMAND_TYPE(this->get_command_type(),  command_t::create_feedback);
        FIELD(offer_id)
        FIELD(stars_given)
        FIELD(comment)
    END_SERIALIZE()

private:
    crypto::hash offer_id{}; //unique id of the offer
    uint8_t stars_given;
    std::vector<uint8_t> comment{};
};

class create_price_peg : public command
{
public:
    friend class safex_command_serializer;

    /**
     * @param _version Safex command protocol version
     * @param _price_peg_data //price peg data
    * */
    create_price_peg(const uint32_t _version, const safex::create_price_peg_data &price_peg) :
            command(_version, command_t::create_price_peg), title(price_peg.title), description{price_peg.description},
            price_peg_id{price_peg.price_peg_id},creator{price_peg.creator},currency{price_peg.currency},rate{price_peg.rate}{
    }

    create_price_peg() : command(0, command_t::create_price_peg), price_peg_id{}, description{} {}

    crypto::hash get_price_peg_id() const { return price_peg_id; }
    std::vector<uint8_t> get_creator() const { return creator; }
    std::vector<uint8_t> get_title() const { return title; }
    std::vector<uint8_t> get_description() const { return description; }
    std::vector<uint8_t> get_currency() const { return currency; }
    uint64_t get_rate() const { return rate; }

    virtual create_price_peg_result* execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;
    virtual execution_status validate(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;

    BEGIN_SERIALIZE_OBJECT()
      FIELDS(*static_cast<command *>(this))
      CHECK_COMMAND_TYPE(this->get_command_type(),  command_t::create_price_peg);
      FIELD(title)
      FIELD(price_peg_id)
      FIELD(creator)
      FIELD(description)
      FIELD(currency)
      FIELD(rate)
    END_SERIALIZE()

private:
    std::vector<uint8_t> title; //title of the price peg
    crypto::hash price_peg_id; //unique id of the price peg
    std::vector<uint8_t> creator; // username of the price peg
    std::vector<uint8_t> description; //description of price peg
    std::vector<uint8_t> currency;
    uint64_t rate;
};

class update_price_peg : public command
{
public:
    friend class safex_command_serializer;

    /**
     * @param _version Safex command protocol version
     * @param _price_peg_data //price peg data
    * */
    update_price_peg(const uint32_t _version, const safex::update_price_peg_data &price_peg) :
            command(_version, command_t::update_price_peg),
            price_peg_id{price_peg.price_peg_id},rate{price_peg.rate}{
    }

    update_price_peg() : command(0, command_t::update_price_peg), price_peg_id{}{}

    crypto::hash get_price_peg_id() const { return price_peg_id; }
    uint64_t get_rate() const { return rate; }

    virtual update_price_peg_result* execute(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;
    virtual execution_status validate(const cryptonote::BlockchainDB &blokchain, const cryptonote::txin_to_script &txin) override;

    BEGIN_SERIALIZE_OBJECT()
      FIELDS(*static_cast<command *>(this))
      CHECK_COMMAND_TYPE(this->get_command_type(),  command_t::update_price_peg);
      FIELD(price_peg_id)
      FIELD(rate)
    END_SERIALIZE()

private:
    crypto::hash price_peg_id; //unique id of the price peg
    uint64_t rate;
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
          case safex::command_t::create_feedback:
             return std::unique_ptr<command>(parse_safex_object<create_feedback>(buffer));
             break;
          case safex::command_t::create_price_peg:
            return std::unique_ptr<command>(parse_safex_object<create_price_peg>(buffer));
            break;
          case safex::command_t::update_price_peg:
            return std::unique_ptr<command>(parse_safex_object<update_price_peg>(buffer));
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
