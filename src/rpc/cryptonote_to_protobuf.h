//
// Created by stefan on 14.2.19..
//

// Wrappers around protobuf classes. Logic for converting cryptonote objects to protobuf object representation.

#ifndef SAFEX_CRYPTONOTE_TO_PROTOBUF_H
#define SAFEX_CRYPTONOTE_TO_PROTOBUF_H

#include "transactions.pb.h"
#include "blocks.pb.h"
#include "../cryptonote_basic/cryptonote_basic.h"
#include <google/protobuf/text_format.h>
#include <string>

namespace safex {

    // Base class for protobuf endpoint.
    // @todo Add stream support.
    class protobuf_endpoint {
    public:
        virtual std::string string() const = 0;
    };

    class transactions_protobuf : public protobuf_endpoint {
    public:
        transactions_protobuf();

        ~transactions_protobuf();

        safex::Transaction* add_transaction(const cryptonote::transaction &tx);

        safex::Transaction *last();

        static void fill_proto_tx(safex::Transaction* prototx, const cryptonote::transaction& tx);

        void add_missed_tx(const std::string& missed);

        std::string string() const;

    private:
        safex::Transactions m_txs;
        safex::Transaction *m_last;
    };


    class blocks_protobuf : public protobuf_endpoint {
    public:
        blocks_protobuf();
        ~blocks_protobuf();

        void add_block(const cryptonote::block& blck, const std::list<cryptonote::transaction>& txs);
        void add_error(const std::string& err);


        std::string string() const;
    private:
        safex::Blocks m_blcks;

        safex::BlockHeader* proto_block_header(const cryptonote::block& blck);

    };

}

#endif //SAFEX_CRYPTONOTE_TO_PROTOBUF_H
