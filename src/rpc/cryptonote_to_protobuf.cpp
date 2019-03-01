//
// Created by stefan on 14.2.19..
//

#include "cryptonote_to_protobuf.h"
#include <algorithm>
#include <memory>

#include "string_tools.h"

namespace {
    // Visitor for serializing tx inputs to protobuf tx structure.
    class add_to_protobuf_txin_visitor : public boost::static_visitor<>
    {
    public:
        add_to_protobuf_txin_visitor(safex::Transaction* in) : tx(in) {}


        void operator()(const cryptonote::txin_to_script& in){} // Not used
        void operator()(const cryptonote::txin_to_scripthash& in){} // Not used

        void operator()(const cryptonote::txin_gen& in){
            safex::txin_v* item = tx->add_vin();
            safex::txin_gen* tx_gen = new safex::txin_gen();

            tx_gen->set_height(in.height);

            item->set_allocated_txin_gen(tx_gen);
        }

        void operator()(const cryptonote::txin_to_key& in){
            safex::txin_v* vin = tx->add_vin();
            safex::txin_to_key* item = new safex::txin_to_key();

            item->set_amount(in.amount);
            item->set_k_image(epee::string_tools::pod_to_hex(in.k_image));

            for(uint64_t offset : in.key_offsets) {
                item->add_key_offsets(offset);
            }


            vin->set_allocated_txin_to_key(item);
        }

        void operator()(const cryptonote::txin_token_migration& in) {
            safex::txin_v* vin = tx->add_vin();
            safex::txin_token_migration* item = new safex::txin_token_migration();

            item->set_token_amount(in.token_amount);
            item->set_bitcoin_burn_transaction(epee::string_tools::pod_to_hex(in.bitcoin_burn_transaction));
            item->set_k_image(epee::string_tools::pod_to_hex(in.k_image));

            vin->set_allocated_txin_token_migration(item);
        }

        void operator()(const cryptonote::txin_token_to_key& in) {
            safex::txin_v* vin = tx->add_vin();
            safex::txin_token_to_key* item = new safex::txin_token_to_key();

            item->set_token_amount(in.token_amount);
            item->set_k_image(epee::string_tools::pod_to_hex(in.k_image));

            for(uint64_t offset : in.key_offsets) {
                item->add_key_offsets(offset);
            }

            vin->set_allocated_txin_token_to_key(item);
        }


    private:
        safex::Transaction* tx;

    };

    class add_to_protobuf_txout_target_visitor : public boost::static_visitor<> {
    public:
        add_to_protobuf_txout_target_visitor(safex::txout* in) : txout(in) {}

        void operator()(const cryptonote::txout_to_script& in) {} // Not used
        void operator()(const cryptonote::txout_to_scripthash& in) {} // Not used

        void operator()(const cryptonote::txout_to_key& in) {
            safex::txout_target_v* target = new safex::txout_target_v();
            safex::txout_to_key* item = new safex::txout_to_key();

            item->set_key(epee::string_tools::pod_to_hex(in.key));

            target->set_allocated_txout_to_key(item);
            txout->set_allocated_target(target);
        }

        void operator()(const cryptonote::txout_token_to_key& in) {
            safex::txout_target_v* target = new safex::txout_target_v();
            safex::txout_token_to_key* item = new safex::txout_token_to_key();

            item->set_key(epee::string_tools::pod_to_hex(in.key));

            target->set_allocated_txout_token_to_key(item);
            txout->set_allocated_target(target);
        }

    private:
        safex::txout* txout;
    };
}

namespace safex {
    transactions_protobuf::transactions_protobuf() {
        GOOGLE_PROTOBUF_VERIFY_VERSION;
    }

    transactions_protobuf::~transactions_protobuf() {
        // See what is going to be here.
    }

    safex::Transaction* transactions_protobuf::add_transaction(const cryptonote::transaction &tx) {
        m_last = m_txs.add_tx();
        m_last->set_version(tx.version);
        m_last->set_unlock_time(tx.unlock_time);

        for(uint8_t extra : tx.extra)
            m_last->add_extra(extra);

        // Handling tx inputs
        ::add_to_protobuf_txin_visitor visitor(m_last);
        std::for_each(tx.vin.begin(), tx.vin.end(), boost::apply_visitor(visitor));

        // Handling tx outputs
        for(const cryptonote::tx_out& txout : tx.vout) {
            safex::txout* curr_out = m_last->add_vout();
            curr_out->set_amount(txout.amount);
            curr_out->set_token_amount(txout.token_amount);

            ::add_to_protobuf_txout_target_visitor visitor_out (curr_out);
            boost::apply_visitor(visitor_out, txout.target);
        }

        for(auto& signatures : tx.signatures) {
            safex::Signature* sigs = m_last->add_signatures();
            for(auto& sig : signatures) {
                sigs->add_signature(epee::string_tools::pod_to_hex(sig));
            }
        }

        return m_last;
    }

    safex::Transaction* transactions_protobuf::last() {
        return m_last;
    }

    const std::string transactions_protobuf::string() {
        return m_txs.SerializeAsString();
    }

    void transactions_protobuf::add_missed_tx(const std::string& missed) {
        m_txs.add_missed_txs(missed);
    }

    blocks_protobuf::blocks_protobuf() {

    }

    blocks_protobuf::~blocks_protobuf() {

    }

    safex::Block blocks_protobuf::add_block(const cryptonote::block& blck) {

    }

    safex::Block* blocks_protobuf::last() {

    }

    void blocks_protobuf::add_error(const std::string& err) {

    }


    std::string blocks_protobuf::string() const {

    }

}