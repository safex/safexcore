//
// Created by amarko on 22.7.19..
//

#include <vector>
#include <iostream>
#include <stdint.h>

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

}
