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
        txmeta_response operator () (const txmeta_request &);

        block_response operator () (const block_request &);
        blocks_response operator () (const blocks_request &);
        lastblocks_response operator () (const lastblocks_request &);

        header_response operator () (const header_request &);
        headers_response operator () (const headers_request &);
        best_header_response operator () (const best_header_request &);
        block_locator_response operator () (const block_locator_request &);

        utxo_response operator () (const utxo_request &);

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
        JSON alive () const;
        JSON health () const;

        // --- transactions ---
        maybe<Bitcoin::transaction>
        transaction(const digest256& txid) const;

        JSON
        transaction_metadata(const digest256& txid) const;

        // --- blocks ---
        maybe<Bitcoin::block>
        block(const digest256& hash) const;

        std::vector<Bitcoin::block>
        blocks(const std::vector<digest256>& hashes) const;

        std::vector<Bitcoin::block>
        blocks_from(const digest256& start, std::size_t limit) const;

        std::vector<Bitcoin::block>
        last_blocks(std::size_t count) const;

        // --- headers ---
        maybe<Bitcoin::block_header>
        header(const digest256& hash) const;

        std::vector<Bitcoin::block_header>
        headers(const digest256& start, std::size_t limit) const;

        Bitcoin::block_header
        best_header() const;

        std::vector<digest256>
        block_locator() const;

        // --- UTXOs ---
        maybe<Bitcoin::outpoint>
        utxo(const Bitcoin::outpoint& out) const;

        std::vector<Bitcoin::outpoint>
        utxos_for_transaction(const digest256& txid) const;

        // --- subtrees ---
        JSON
        subtree(const digest256& hash) const;

        bytes
        subtree_data(const digest256& hash) const;

        std::vector<Bitcoin::transaction>
        subtree_transactions(const digest256& hash) const;

        // --- merkle ---
        maybe<Merkle::proof>
        merkle_proof(const digest256& txid,
                    const digest256& block_hash) const;

        // --- analytics / stats ---
        JSON
        block_stats(const digest256& block_hash) const;

        JSON
        block_graph_data() const;

        // --- search ---
        JSON
        search(const std::string& query) const;
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

        bool is_error () const;
        std::string error_message () const;
    };

    // --- Get single header ---

    struct get_header_request : HTTP::request {

        explicit get_header_request (const digest256& hash);

        get_header_request &format (format);

    };

    struct get_header_response : response {

        using response::response;

        Bitcoin::block_header operator()() const;
    };

    // --- Get header chain ---

    struct get_headers_request : HTTP::request {

        get_headers_request(const digest256& start, std::size_t limit);

        get_headers_request& format(format);

    };

    struct get_headers_response : response {

        using response::response;

        std::vector<Bitcoin::block_header> operator () () const;
    };

    // --- Best header ---

    struct best_header_request : HTTP::request {

        best_header_request();

        best_header_request& format (format);

        format_type Format = format::raw;
    };

    struct best_header_response : response {

        using response::response;

        maybe<Bitcoin::block_header> operator () () const;
    };


}

#endif
