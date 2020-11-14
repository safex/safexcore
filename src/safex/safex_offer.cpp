//
// Created by amarko on 22.7.19..
//

#include <vector>
#include <iostream>
#include <stdint.h>
#include <chrono>

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_core.h"
#include "safex/command.h"
#include "safex_offer.h"



namespace safex
{

    crypto::hash safex_offer::create_offer_id(std::string& username){

        crypto::hash id{};
        std::string offer_id_string = username;

        auto time_now = std::chrono::system_clock::now();
        auto nanosec = time_now.time_since_epoch();
        std::string time_now_string{std::to_string(nanosec.count())};

        offer_id_string.append(time_now_string);

        bool res = cryptonote::get_object_hash(std::vector<uint8_t>{offer_id_string.begin(),offer_id_string.end()},id);

        if(!res){
            //error
        }
        return id;
    }

    crypto::hash safex_offer::get_hash(){

      crypto::hash offer_hash{};

      std::vector<uint8_t> offer_scalar;

      std::vector<uint8_t> title_vec{std::begin(title),std::end(title)};

      offer_scalar.insert(offer_scalar.end(),std::begin(offer_id.data),std::end(offer_id.data));
      offer_scalar.insert(offer_scalar.end(),title_vec.begin(),title_vec.end());
      offer_scalar.insert(offer_scalar.end(),description.begin(),description.end());

      bool res = cryptonote::get_object_hash(offer_scalar,offer_hash);

      if(!res)
        return {};

      return offer_hash;

    }

    void safex_offer::set_price_peg(crypto::hash& _price_peg_id, uint64_t _price, uint64_t _min_sfx_price){
      price_peg_used = true;
      price_peg_id = _price_peg_id;
      price = _price;
      min_sfx_price = _min_sfx_price;
    }

}
