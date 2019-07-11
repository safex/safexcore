//
// Created by stefan on 14.2.19..
//

#include "cryptonote_to_protobuf.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include <algorithm>
#include <memory>

#include <numeric>

#include "string_tools.h"

// Anonymous namespace for visitor used to recover data from variants.
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
            item->set_k_image(in.k_image.data, 32*sizeof(char));

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
            item->set_k_image(in.k_image.data, 32*sizeof(char));

            vin->set_allocated_txin_token_migration(item);
        }

        void operator()(const cryptonote::txin_token_to_key& in) {
            safex::txin_v* vin = tx->add_vin();
            safex::txin_token_to_key* item = new safex::txin_token_to_key();

            item->set_token_amount(in.token_amount);
            item->set_k_image(in.k_image.data, 32*sizeof(char));

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

            item->set_key(in.key.data, 32*sizeof(char));

            target->set_allocated_txout_to_key(item);
            txout->set_allocated_target(target);
        }

        void operator()(const cryptonote::txout_token_to_key& in) {
            safex::txout_target_v* target = new safex::txout_target_v();
            safex::txout_token_to_key* item = new safex::txout_token_to_key();

            item->set_key(in.key.data, 32*sizeof(char));

            target->set_allocated_txout_token_to_key(item);
            txout->set_allocated_target(target);
        }

    private:
        safex::txout* txout;
    };
}

namespace safex {

    transactions_protobuf::transactions_protobuf() : protobuf_endpoint() {
        GOOGLE_PROTOBUF_VERIFY_VERSION;
    }

    transactions_protobuf::~transactions_protobuf() {
        // See what is going to be here.
    }

    safex::Transaction* transactions_protobuf::add_transaction(const cryptonote::transaction &tx) {
        m_last = m_txs.add_tx();
        transactions_protobuf::fill_proto_tx(m_last, tx);
        return m_last;
    }

    void transactions_protobuf::fill_proto_tx(safex::Transaction* prototx, const cryptonote::transaction& tx) {
        prototx->set_version(tx.version);
        prototx->set_unlock_time(tx.unlock_time);

        prototx->set_tx_hash(epee::string_tools::pod_to_hex(tx.hash));

        prototx->set_extra(std::string{std::begin(tx.extra), std::end(tx.extra)});

        // Handling tx inputs
        ::add_to_protobuf_txin_visitor visitor(prototx);
        std::for_each(tx.vin.begin(), tx.vin.end(), boost::apply_visitor(visitor));

        // Handling tx outputs
        for(const cryptonote::tx_out& txout : tx.vout) {
            safex::txout* curr_out = prototx->add_vout();
            curr_out->set_amount(txout.amount);
            curr_out->set_token_amount(txout.token_amount);

            ::add_to_protobuf_txout_target_visitor visitor_out (curr_out);
            boost::apply_visitor(visitor_out, txout.target);
        }

        for(auto& signatures : tx.signatures) {
            safex::Signature* sigs = prototx->add_signatures();
            for(auto& sig : signatures) {
                sigs->add_signature(epee::string_tools::pod_to_hex(sig));
            }
        }

    }

    safex::Transaction* transactions_protobuf::last() {
        return m_last;
    }

    std::string transactions_protobuf::string() const {
        return m_txs.SerializeAsString();
    }

    void transactions_protobuf::add_missed_tx(const std::string& missed) {
        m_txs.add_missed_txs(missed);
    }

    blocks_protobuf::blocks_protobuf() : protobuf_endpoint() {
        GOOGLE_PROTOBUF_VERIFY_VERSION;
    }

    blocks_protobuf::~blocks_protobuf() {

    }

    void blocks_protobuf::add_block(const cryptonote::block& blck,  crypto::hash& hash) {
        safex::Block* proto_blck = m_blcks.add_block();
        proto_blck->set_allocated_header(proto_block_header(blck, hash));

        proto_blck->set_miner_tx(epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(blck.miner_tx)));

        for(const auto& tx : blck.tx_hashes) {
            proto_blck->add_txs(epee::string_tools::pod_to_hex(tx));
        }
    }

    void blocks_protobuf::add_error(const std::string& err) {
        m_blcks.set_error(err);
    }


    std::string blocks_protobuf::string() const {
        return m_blcks.SerializeAsString();
    }

    safex::BlockHeader* blocks_protobuf::proto_block_header(const cryptonote::block& blck,  crypto::hash& hash) {
        safex::BlockHeader* hdr = new safex::BlockHeader{};

        hdr->set_major_version(blck.major_version);
        hdr->set_minor_version(blck.minor_version);
        hdr->set_prev_hash(epee::string_tools::pod_to_hex(blck.prev_id));
        hdr->set_hash(epee::string_tools::pod_to_hex(hash));
        hdr->set_depth(boost::get<cryptonote::txin_gen>(blck.miner_tx.vin.front()).height);

        return hdr;
    }

    output_histograms_protobuf::output_histograms_protobuf() : protobuf_endpoint() {
        GOOGLE_PROTOBUF_VERIFY_VERSION;
    }
    output_histograms_protobuf::~output_histograms_protobuf() {}

    void output_histograms_protobuf::add_histogram( uint64_t amount, const cryptonote::tx_out_type out_type, 
                                                    uint64_t recent_instances, uint64_t total_instances, 
                                                    uint64_t unlocked_instances) 
    {
        safex::Histogram* histogram = m_histograms.add_histograms();

        histogram->set_amount(amount);
        histogram->set_out_type(static_cast<uint64_t>(out_type));
        histogram->set_recent_instances(recent_instances);
        histogram->set_total_instances(total_instances);
        histogram->set_unlocked_instances(unlocked_instances);
    }

    std::string output_histograms_protobuf::string() const
    {
        return m_histograms.SerializeAsString();
    }

    void output_histograms_protobuf::set_status(const std::string& status)
    {
        m_histograms.set_status(status);
    }

    outputs_protobuf::outputs_protobuf() : protobuf_endpoint() 
    {
        GOOGLE_PROTOBUF_VERIFY_VERSION;
    }

    outputs_protobuf::~outputs_protobuf() {}

    void outputs_protobuf::add_out_entry(const crypto::public_key key, bool unlocked, const uint64_t height, const crypto::hash& txid) 
    {
        std::cout << "*****************" << std::endl;
        safex::Out_entry* entry = m_outs.add_outs();
        entry->set_key(key.data, 32*sizeof(char));
        entry->set_txid(txid.data, 32*sizeof(char));
        entry->set_unlocked(unlocked);
        entry->set_height(height);
    }

    void outputs_protobuf::set_status(const std::string& status) 
    {
        m_outs.set_status(status);
    }

    std::string outputs_protobuf::string() const 
    {
        return m_outs.SerializeAsString();
    }

}