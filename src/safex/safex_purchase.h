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

    enum safex_purchase_status
    {
        safex_purchase_started,
        safex_purchase_shipped,
        safex_purchase_need_feedback,
        safex_purchase_done,
    };

    public:
      safex_purchase(): quantity{}, price{}, shipping{}, offer_id{0}, version{0},status{safex_purchase_status::safex_purchase_started}{

      }

      safex_purchase(const uint64_t _quantity, const safex_price& _price, crypto::hash &_id, bool _shipping, uint64_t _version, safex_purchase_status _status = safex_purchase_started):quantity{_quantity},price{_price},
                                                                                            offer_id{_id},shipping{_shipping},version{_version},status{_status}
      {
      }


    BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(offer_id)
        KV_SERIALIZE(quantity)
        KV_SERIALIZE(price)
        KV_SERIALIZE(shipping)
        KV_SERIALIZE(version)
        KV_SERIALIZE(status)
      END_KV_SERIALIZE_MAP()

      BEGIN_SERIALIZE_OBJECT()
        FIELD(offer_id)
        FIELD(quantity)
        FIELD(price)
        FIELD(shipping)
        FIELD(version)
        FIELD(status)
      END_SERIALIZE()

      template<class t_archive>
      inline void serialize(t_archive &a, const unsigned int /*ver*/)
      {
        a & offer_id;
        a & quantity;
        a & price;
        a & shipping;
        a & version;
        a & status;
      }

      crypto::hash offer_id;
      uint64_t quantity;
      safex_price price;
      bool shipping;
      uint64_t version;
      safex_purchase_status status;
  private:


  };
}


#endif //SAFEX_SAFEX_PURCHASE_H
