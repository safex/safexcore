//
// Created by stefan on 14.2.19..
//

// Wrappers around protobuf classes. Logic for converting cryptonote objects to protobuf object representation.

#ifndef SAFEX_CRYPTONOTE_TO_PROTOBUF_H
#define SAFEX_CRYPTONOTE_TO_PROTOBUF_H

#include "transactions.pb.h"
#include "../cryptonote_basic/cryptonote_basic.h"
#include <google/protobuf/text_format.h>

namespace safex {

    class transactions_protobuf {
    public:
        transactions_protobuf();

        ~transactions_protobuf();

        safex::Transaction* add_transaction(const cryptonote::transaction &tx);

        safex::Transaction *last();

        void add_missed_tx(const std::string& missed);

        const std::string string();

    private:
        safex::Transactions m_txs;
        safex::Transaction *m_last;
    };
}

#endif //SAFEX_CRYPTONOTE_TO_PROTOBUF_H
