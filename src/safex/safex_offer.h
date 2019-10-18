//
// Created by amarko on 22.7.19..
//

#ifndef SAFEX_SAFEX_OFFER_H
#define SAFEX_SAFEX_OFFER_H


#include <string>
#include <cryptonote_basic/cryptonote_basic.h>

#include "device/device.hpp"
#include "crypto/crypto.h"
#include "serialization/keyvalue_serialization.h"
#include "cryptonote_basic/cryptonote_format_utils.h"


#include "safex_core.h"

#undef SAFEX_DEFAULT_LOG_CATEGORY
#define SAFEX_DEFAULT_LOG_CATEGORY "safex_offer"

namespace safex
{

  struct safex_price
  {
    safex_price() : cost{}, price{}, percent{}
    {

    }

    safex_price(uint64_t _cost, uint64_t _price, uint64_t _percent) : cost{_cost}, price{_price}, percent{_percent}
    {

    }

    BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE(cost)
    KV_SERIALIZE(price)
    KV_SERIALIZE(percent)
    END_KV_SERIALIZE_MAP()

      BEGIN_SERIALIZE_OBJECT()
          FIELD(cost)
          FIELD(price)
          FIELD(percent)
      END_SERIALIZE()

    template<class t_archive>
    inline void serialize(t_archive &a, const unsigned int /*ver*/)
      {
        a & cost;
        a & price;
        a & percent;
    }

    uint64_t cost;
    uint64_t price;
    uint64_t percent;
  };


  struct safex_offer
  {
    public:
      safex_offer(): title{}, quantity{}, price{}, description{}, description_sig{}, active{false}, shipping{}, offer_id{0}, version{0}, seller{} {

      }

      safex_offer(const std::string &_title, const uint64_t _quantity, const safex_price& _price, const std::vector<uint8_t> &_description,
                  bool _active, crypto::hash _id, std::string seller_username):title{_title},quantity{_quantity},price{_price},
                                                             description{_description},offer_id{_id},seller{seller_username},active{_active}
      {
      }

      safex_offer(const std::string &_title, const uint64_t _quantity, const safex_price& _price, const std::vector<uint8_t> &_description,
      bool _active, const crypto::signature &_sig, crypto::hash _id, std::string seller_username):
              title{_title}, quantity{_quantity}, price{_price}, description{_description},
              description_sig{_sig}, active{_active}, shipping{}, offer_id{_id}, version{0}, seller{seller_username}{

      }


      safex_offer(const std::string &_title, const uint64_t _quantity, const safex_price& _price, std::string& _description,
                  bool _active, const safex_account_keys& keys, std::string seller_username):
              title{_title}, quantity{_quantity}, price{_price}, active{_active}, shipping{}, version{0}, seller{seller_username} {

          description = std::vector<uint8_t>(_description.begin(),_description.end());
          description_sig = generate_description_signature(keys);

          offer_id = create_offer_id(seller_username);

      }

    BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(title)
        KV_SERIALIZE(quantity)
        KV_SERIALIZE(price)
        KV_SERIALIZE(description)
        KV_SERIALIZE(description_sig)
        KV_SERIALIZE(active)
        KV_SERIALIZE(shipping)
        KV_SERIALIZE(offer_id)
        KV_SERIALIZE(seller)
        KV_SERIALIZE(version)
      END_KV_SERIALIZE_MAP()

      BEGIN_SERIALIZE_OBJECT()
        FIELD(title)
        VARINT_FIELD(quantity)
        FIELD(price)
        FIELD(description)
        FIELD(description_sig)
        FIELD(active)
        FIELD(shipping)
        FIELD(offer_id)
        FIELD(seller)
        FIELD(version)
      END_SERIALIZE()

      template<class t_archive>
      inline void serialize(t_archive &a, const unsigned int /*ver*/)
      {
        a & title;
        a & quantity;
        a & price;
        a & description;
        a & description_sig;
        a & active;
        a & shipping;
        a & offer_id;
        a & seller;
        a & version;
      }


      std::string title; //title of the offer
      uint64_t quantity;
      safex_price price;
      std::vector<uint8_t> description; //description of offer, JSON or other format TBD.
      crypto::signature description_sig; //signature of description, from the account that created offer
      bool active; //is offer active
      std::vector<uint8_t> shipping;
      crypto::hash offer_id; //unique id of the offer
      std::string seller; // username of the seller
      uint64_t version; //offer can be updated, increment version in that case

  private:
      crypto::hash create_offer_id(std::string& username);

      crypto::signature generate_description_signature(const safex_account_keys& keys);

  };
}


#endif //SAFEX_SAFEX_OFFER_H
