//
// Created by Igor Grkavac on 24.01.20.
//

#ifndef SAFEX_SAFEX_FEEDBACK_H
#define SAFEX_SAFEX_FEEDBACK_H


#include <string>
#include <cryptonote_basic/cryptonote_basic.h>

#include "device/device.hpp"
#include "crypto/crypto.h"
#include "serialization/keyvalue_serialization.h"
#include "cryptonote_basic/cryptonote_format_utils.h"


#include "safex_core.h"

#undef SAFEX_DEFAULT_LOG_CATEGORY
#define SAFEX_DEFAULT_LOG_CATEGORY "safex_feedback"

namespace safex
{

  struct safex_feedback
  {

    public:
      safex_feedback(): comment{}, stars_given{}, offer_id{0}{
      }

      safex_feedback(const uint64_t _stars_given, const std::string _comment, crypto::hash &_id):stars_given{_stars_given},comment{_comment},
                                                                                            offer_id{_id}
      {
      }


    BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(offer_id)
        KV_SERIALIZE(stars_given)
        KV_SERIALIZE(comment)
      END_KV_SERIALIZE_MAP()

      BEGIN_SERIALIZE_OBJECT()
        FIELD(offer_id)
        FIELD(stars_given)
        FIELD(comment)
      END_SERIALIZE()

      template<class t_archive>
      inline void serialize(t_archive &a, const unsigned int /*ver*/)
      {
        a & offer_id;
        a & stars_given;
        a & comment;
      }

      crypto::hash offer_id{}; //unique id of the offer
      uint64_t stars_given;
      std::string comment{};
  private:


  };
}


#endif //SAFEX_SAFEX_FEEDBACK_H
