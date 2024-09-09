// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_PAY_ARC
#define GIGAMONKEY_PAY_ARC

#include <gigamonkey/pay/extended.hpp>

// https://bitcoin-sv.github.io/arc/api.html
namespace Gigamonkey::ARC {

    struct policy_response;
    struct health_response;
    using status_request = Bitcoin::txid;
    struct status_response;
    struct submit_request;
    struct submit_response;
    using submit_txs_request = status_response;
    struct submit_txs_response;

    struct client : net::HTTP::client_blocking {
        using net::HTTP::client_blocking::client_blocking;

        // there are five calls in ARC
        policy_response policy ();
        health_response health ();
        status_response status (const status_request &);
        submit_response submit (const submit_request &);
        submit_txs_response submit_txs (const submit_txs_request &);
    };

    struct common_response : net::HTTP::response {
        maybe<string> timestamp () const;

        bool valid () const;
        common_response (net::HTTP::response &&);
        ~common_response () = 0;
    };

    struct health : JSON {
        bool healthy () const;
        string reason () const;

        health (JSON &&);
        bool valid () const;
    };

    struct health_response : common_response {
        maybe<ARC::health> health () const;
        health_response (net::HTTP::response &&);
    };

    struct policy : JSON {
        uint64 max_script_size_policy () const;
        uint64 max_tx_sigops_count_policy () const;
        uint64 max_tx_size_policy () const;
        satoshis_per_byte mining_fee () const;

        policy (JSON &&);
        bool valid () const;
    };

    struct policy_response : common_response {
        maybe<ARC::policy> policy () const;
        policy_response (net::HTTP::response &&);
    };

    enum status_value : uint32 {
        RECEIVED = 2,
        STORED = 3,
        ANNOUNCED_TO_NETWORK = 4,
        REQUESTED_BY_NETWORK = 5,
        SENT_TO_NETWORK = 6,
        ACCEPTED_BY_NETWORK = 7,
        SEEN_ON_NETWORK = 8
    };

    struct error : JSON {
        string type () const;
        string title () const;
        net::HTTP::status status () const;
        string detail () const;
        string instance () const;
        string txid () const;
        string extra_info () const;

        error (JSON &&);
        bool valid () const;
    };

    struct status : JSON {
        string timestamp () const;
        Bitcoin::TXID block_hash () const;
        N block_height () const;
        string txid () const;
        string Merkle_path () const;
        status_value tx_status () const;
        string extra_info () const;

        status (JSON &&);
        bool valid () const;
    };

    struct status_response : common_response {
        status_response (net::HTTP::response &&);
        maybe<ARC::error> error () const;
        maybe<ARC::status> status () const;
    };

    enum content_type_option {text, json, octet};

    struct submit_tx_request : net::HTTP::request {
        submit_tx_request (net::HTTP::request &&);
        submit_tx_request (const extended::transaction &);

        bool valid () const;

        submit_tx_request content_type (content_type_option) const;
        submit_tx_request callback_url (const net::URL &) const;
        submit_tx_request full_status_updates (bool) const;
        submit_tx_request max_timeout (int) const;
        submit_tx_request skip_fee_validation (bool) const;
        submit_tx_request skip_script_validation (bool) const;
        submit_tx_request callback_token (const string &) const;
        submit_tx_request wait_for_token (status_value) const;

    };

    struct submit_txs_request : net::HTTP::request {
        submit_txs_request (net::HTTP::request &&);
        submit_txs_request (list<extended::transaction>);

        bool valid () const;

        submit_txs_request content_type (content_type_option) const;
        submit_txs_request callback_url (const net::URL &) const;
        submit_txs_request full_status_updates (bool) const;
        submit_txs_request max_timeout (int) const;
        submit_txs_request skip_fee_validation (bool) const;
        submit_txs_request skip_script_validation (bool) const;
        submit_txs_request callback_token (const string &) const;
        submit_txs_request wait_for_token (status_value) const;

    };

    struct submit_txs_response : common_response {
        submit_tx_response (net::HTTP::response &&);
        maybe<ARC::error> error () const;
        maybe<list<ARC::status>> status () const;
    };

    inline common_response::common_response (net::HTTP::response &&r): net::HTTP::response (r) {}

    inline ~common_response () {}

    inline health::health (JSON &&j): JSON (j) {}

    inline health_response::health_response (net::HTTP::response &&r): net::HTTP::response (r) {}

    inline policy::policy (JSON &&j): JSON (j) {}

    inline policy_response::policy_response (net::HTTP::response &&r): net::HTTP::response (r) {}

    inline error::error (JSON &&j): JSON (j) {}

    inline status::status (JSON &&j): JSON (j) {}

    inline status_response::status_response (net::HTTP::response &&r): net::HTTP::response (r) {}

    inline submit_tx_request::submit_tx_request (net::HTTP::request &&r): net::HTTP::response (r) {}

    inline submit_txs_request::submit_txs_request (net::HTTP::request &&r): net::HTTP::response (r) {}

    inline submit_txs_response::submit_tx_response (net::HTTP::response &&r): net::HTTP::response (r) {}

}

#endif
