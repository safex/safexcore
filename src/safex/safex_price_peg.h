//
// Created by Igor Grkavac on 04.02.20.
//

#ifndef SAFEX_SAFEX_PRICE_PEG_H
#define SAFEX_SAFEX_PRICE_PEG_H


#include <string>
#include <cryptonote_basic/cryptonote_basic.h>

#include "device/device.hpp"
#include "crypto/crypto.h"
#include "serialization/keyvalue_serialization.h"
#include "cryptonote_basic/cryptonote_format_utils.h"


#include "safex_core.h"

#undef SAFEX_DEFAULT_LOG_CATEGORY
#define SAFEX_DEFAULT_LOG_CATEGORY "safex_price_peg"

namespace safex
{


  struct safex_price_peg
  {
    public:
      safex_price_peg(): title{}, creator{}, currency{}, description{}, rate{}, price_peg_id{0} {

      }

      safex_price_peg(const std::string &_title, const std::string _creator, const std::string _currency, const std::vector<uint8_t> &_description, crypto::hash _price_peg_id, uint64_t _rate):
                            title{_title},creator{_creator}, currency{_currency}, description{_description},price_peg_id{_price_peg_id},rate{_rate}
      {
      }

      safex_price_peg(const std::vector<uint8_t> &_title, const std::vector<uint8_t> _creator, const std::vector<uint8_t> _currency, const std::vector<uint8_t> &_description, crypto::hash _price_peg_id, uint64_t _rate):
              title{_title.begin(),_title.end()},creator{_creator.begin(),_creator.end()}, currency{_currency.begin(),_currency.end()}, description{_description},price_peg_id{_price_peg_id},rate{_rate}
      {
      }


      safex_price_peg(const std::string &_title, std::string _creator, const std::string _currency, const std::string &_description, uint64_t _rate):
              title{_title},creator{_creator}, currency{_currency}, rate{_rate}
      {

          description = std::vector<uint8_t>(_description.begin(),_description.end());
          price_peg_id = create_price_peg_id(_creator);

      }
    BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(title)
        KV_SERIALIZE(price_peg_id)
        KV_SERIALIZE(creator)
        KV_SERIALIZE(description)
        KV_SERIALIZE(currency)
        KV_SERIALIZE(rate)
      END_KV_SERIALIZE_MAP()

      BEGIN_SERIALIZE_OBJECT()
        FIELD(title)
        VARINT_FIELD(price_peg_id)
        FIELD(creator)
        FIELD(description)
        FIELD(currency)
        FIELD(rate)
      END_SERIALIZE()

      template<class t_archive>
      inline void serialize(t_archive &a, const unsigned int /*ver*/)
      {
        a & title;
        a & price_peg_id;
        a & creator;
        a & description;
        a & currency;
        a & rate;
      }


      std::string title; //title of the price peg
      crypto::hash price_peg_id; //unique id of the price peg
      std::string creator; // username of the price peg
      std::vector<uint8_t> description; //description of price peg
      std::string currency;
      uint64_t rate;

  private:
      crypto::hash create_price_peg_id(std::string& username);

  };
}


#endif //SAFEX_SAFEX_PRICE_PEG_H
