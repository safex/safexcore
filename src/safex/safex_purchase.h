//
// Created by Igor Grkavac on 21.10.19..
//

#ifndef SAFEX_SAFEX_PURCHASE_H
#define SAFEX_SAFEX_PURCHASE_H


#include <string>
#include <cryptonote_basic/cryptonote_basic.h>

#include "device/device.hpp"
#include "crypto/crypto.h"
#include "serialization/keyvalue_serialization.h"
#include "cryptonote_basic/cryptonote_format_utils.h"


#include "safex_core.h"

#undef SAFEX_DEFAULT_LOG_CATEGORY
#define SAFEX_DEFAULT_LOG_CATEGORY "simple_purchase"

namespace safex
{

  struct safex_purchase
  {

    public:
      safex_purchase(): quantity{}, price{}, shipping{}, offer_id{0}, offer_hash{}{

      }

      safex_purchase(const uint64_t _quantity, const uint64_t _price, crypto::hash &_id, crypto::hash _offer_hash, bool _shipping):quantity{_quantity},price{_price},
                                                                                            offer_id{_id}, offer_hash{_offer_hash}, shipping{_shipping}
      {
      }


    BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(offer_id)
        KV_SERIALIZE(offer_hash)
        KV_SERIALIZE(quantity)
        KV_SERIALIZE(price)
        KV_SERIALIZE(shipping)
      END_KV_SERIALIZE_MAP()

      BEGIN_SERIALIZE_OBJECT()
        FIELD(offer_id)
        FIELD(offer_hash)
        FIELD(quantity)
        FIELD(price)
        FIELD(shipping)
      END_SERIALIZE()

      template<class t_archive>
      inline void serialize(t_archive &a, const unsigned int /*ver*/)
      {
        a & offer_id;
        a & offer_hash;
        a & quantity;
        a & price;
        a & shipping;
      }

      crypto::hash offer_id;
      crypto::hash offer_hash;
      uint64_t quantity;
      uint64_t price;
      bool shipping;
  private:


  };
}


#endif //SAFEX_SAFEX_PURCHASE_H
