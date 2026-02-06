#ifndef GIGAMONKEY_TERANODE
#define GIGAMONKEY_DERANODE

#include <data/net/HTTP_client.hpp>

#include <gigamonkey/timechain.hpp>

namespace Gigamonkey {
    using JSON = data::JSON;
    namespace HTTP = data::net::HTTP;

    using URL = data::net::URL;
    using ASCII = data::ASCII;
    using unicode = data::unicode;
    using UTF8 = data::UTF8;
    using ip_address = data::net::IP::address;

    template <typename X> using awaitable = boost::asio::awaitable<X>;
}

namespace Gigamonkey::teranode {

    struct alive_request;
    struct alive_response;

    struct health_request;
    struct health_response;

    struct get_tx_request;
    struct get_tx_response;

    struct post_txs_request;
    struct post_txs_response;

    struct txmeta_request;
    struct txmeta_response;

    struct header_request;
    struct header_response;

    struct headers_request;
    struct headers_response;

    struct best_header_request;
    struct best_header_response;

    struct block_request;
    struct block_response;

    struct block_forks_request;
    struct block_forks_response;

    struct block_subtrees_request;
    struct block_subtrees_response;

    struct blocks_request;
    struct blocks_response;

    struct lastblocks_request;
    struct lastblocks_response;

    struct blockstats_request;
    struct blockstats_response;

    struct blockgraphdata_request;
    struct blockgraphdata_response;

    struct header_request;
    struct header_response;

    struct headers_request;
    struct headers_response;

    struct headers_to_common_ancestor_request;
    struct headers_to_common_ancestor_response;

    struct headers_from_common_ancestor_request;
    struct headers_from_common_ancestor_response;

    struct block_locator_request;
    struct block_locator_response;

    struct bestblockheader_request;
    struct bestblockheader_response;

    struct utxo_request;
    struct utxo_response;

    struct utxos_request;
    struct utxos_response;

    struct subtree_request;
    struct subtree_response;

    struct subtree_data_request;
    struct subtree_data_response;

    struct subtree_txs_request;
    struct subtree_txs_response;

    struct search_request;
    struct search_response;

    struct client : HTTP::client {

        using HTTP::client::client;

        // =========================
        // operator() overloads
        // =========================

        alive_response operator () (const alive_request &);
        health_response operator () (const health_request &);

        get_tx_response operator () (const get_tx_request &);

        post_txs_response operator () (const post_txs_request &);

        txmeta_response operator () (const txmeta_request &);

        header_response operator () (const header_request &);
        headers_response operator () (const headers_request &);
        best_header_response operator () (const best_header_request &);

        block_response operator () (const block_request &);
        blocks_response operator () (const blocks_request &);
        lastblocks_response operator () (const lastblocks_request &);

        block_forks_response operator () (const block_forks_request &);
        block_subtrees_response operator () (const block_subtrees_request &);

        header_response operator () (const header_request);

        headers_response operator () (const headers_request);

        headers_to_common_ancestor_response operator () (const headers_to_common_ancestor_request);

        headers_from_common_ancestor_response operator () (const headers_from_common_ancestor_request);

        block_locator_response operator () (const block_locator_request &);

        utxo_response operator () (const utxo_request &);

        utxos_response operator () (const utxos_request &);

        subtree_response operator () (const subtree_request &);
        subtree_data_response operator () (const subtree_data_request &);
        subtree_txs_response operator () (const subtree_txs_request &);

        blockstats_response operator () (const blockstats_request &);
        blockgraphdata_response operator () (const blockgraphdata_request &);

        search_response operator () (const search_request &);

        // =========================
        // Convenience API
        // =========================

        // --- liveness ---
        JSON alive ();
        JSON health ();

        // --- transactions ---
        maybe<Bitcoin::transaction> transaction (const digest256 &txid);

        JSON transaction_metadata (const digest256 &txid);

        // --- blocks ---
        maybe<Bitcoin::block> block (const digest256 &hash);

        cross<Bitcoin::block> blocks (const cross<digest256> &hashes);

        cross<Bitcoin::block> blocks_from (const digest256 &start, std::size_t limit);

        cross<Bitcoin::block> last_blocks (std::size_t count);
/*
        // --- headers ---
        maybe<Bitcoin::block_header> header (const digest256 &hash);

        cross<Bitcoin::block_header> headers (const digest256 &start, std::size_t limit);

        Bitcoin::block_header best_header ();

        cross<digest256> block_locator ();

        // --- UTXOs ---
        maybe<Bitcoin::outpoint> utxo (const Bitcoin::outpoint &out);

        cross<Bitcoin::outpoint> utxos_for_transaction (const digest256 &txid);

        // --- subtrees ---
        JSON subtree (const digest256 &hash);

        bytes subtree_data (const digest256 &hash);

        cross<Bitcoin::transaction> subtree_transactions (const digest256 &hash);

        // --- merkle ---
        maybe<Merkle::proof> merkle_proof (const digest256 &txid, const digest256 &block_hash);

        // --- analytics / stats ---
        JSON block_stats (const digest256 &block_hash);

        JSON block_graph_data ();

        // --- search ---
        JSON search (const std::string &query);*/
    };

    // teranode offers three formats for responses.
    // we will use raw bytes.
    enum class format_type {
        bytes,
        hex,
        json
    };

    // =========================
    // Request / response types
    // =========================

    struct response : HTTP::response {
        using HTTP::response::response;

        response (HTTP::status, const std::string &error_msg);

        bool is_error () const {
            return this->Status != HTTP::status {200};
        }

        maybe<std::string> error_message () const {
            if (this->Status == HTTP::status {200}) return {};
            try {
                auto j = JSON::parse (string (this->Body));
                if (j.size () != 1) return {};
                return std::string (j["error"]);
            } catch (JSON::exception &) {
                return {};
            }
        }

        bool valid () const {
            return !is_error () && bool (error_message ());
        }

        const bytes &body () const {
            if (this->is_error ()) {
                maybe<std::string> msg = this->error_message ();
                if (!msg) throw exception {} << "could not read teranode response " << *this;
                // TODO provide more information;
                else throw exception {} << *msg;
            }
            return this->Body;
        }

    };

    struct alive_response : response {

        using response::response;

        JSON operator () () const {
            return JSON::parse (string (this->body ()));
        }
    };

    struct health_response : response {

        using response::response;

        JSON operator () () const {
            return JSON::parse (string (this->body ()));
        }
    };

    struct get_tx_request {

        digest256 TxID;
        format_type Format = format_type::bytes;

        explicit get_tx_request (const digest256 &txid): TxID {txid} {}

        operator HTTP::request () const {
            if (Format != format_type::bytes)
                throw data::method::unimplemented {"get_tx_request -> HTTP::request"};

            return HTTP::request {
                HTTP::method::get,
                string::write ("/api/v1/tx/", write_reverse_hex (TxID))
            };
        }
    };

    struct get_tx_response : response {

        using response::response;

        operator maybe<Bitcoin::transaction> () const {
            if (this->Status == HTTP::status {404}) return {};
            return Bitcoin::transaction {this->body ()};
        }
    };

    struct post_txs_request {

        stack<Bitcoin::transaction> Transactions;

        explicit post_txs_request (stack<Bitcoin::transaction> txs);

        operator HTTP::request () const;/* {
            return HTTP::request::make {}.method (
                HTTP::method::post
            ).target ("/api/v1/txs").body ( what goes here? );
        }*/
    };

    struct post_txs_response : response {

        using response::response;

        operator cross<Bitcoin::transaction> () const;
    };

}

#endif
