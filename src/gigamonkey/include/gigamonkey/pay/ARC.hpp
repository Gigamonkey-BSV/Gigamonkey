// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_PAY_ARC
#define GIGAMONKEY_PAY_ARC

#include <data/net/error.hpp>
#include <data/net/HTTP_client.hpp>
#include <gigamonkey/pay/extended.hpp>
#include <data/net/JSON.hpp>

// https://bitcoin-sv.github.io/arc/api.html
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

namespace Gigamonkey::ARC {

    struct policy_response;
    struct health_response;
    struct status_response;
    struct submit_request;
    struct submit_response;
    struct submit_txs_request;
    struct submit_txs_response;

    struct client : HTTP::client {
        using HTTP::client::client;

        // there are five calls in ARC
        awaitable<policy_response> policy ();
        awaitable<health_response> health ();
        awaitable<status_response> status (const Bitcoin::TXID &);
        awaitable<submit_response> submit (const submit_request &);
        awaitable<submit_txs_response> submit_txs (const submit_txs_request &);
    };

    // failed queries may contain errors.
    struct error : data::net::error {
        using ::data::net::error::error;
        maybe<Bitcoin::TXID> txid () const;
        maybe<string> extra_info () const;
    };

    struct response : HTTP::response {
        maybe<JSON> body () const;
        bool is_error () const;
        // return an error if there is one.
        ARC::error error () const;

        // a response is valid if the body is empty and the status is 401
        // or if the body is JSON and Content-Type is set to "application/json"
        bool valid () const;

        operator bool () const {
            return !is_error ();
        }

        using HTTP::response::response;
        response (HTTP::response &&);

        static maybe<JSON> body (const HTTP::response &r);

        static bool valid (const HTTP::response &r);
        static bool is_error (const HTTP::response &r);
        static ARC::error error (const HTTP::response &r);
    };

    struct health : JSON {
        bool healthy () const;
        string reason () const;
        string version () const;

        bool valid () const;

        health (JSON &&);
        health (const JSON &j);

        static bool valid (const JSON &);

        static bool healthy (const JSON &);
        static string reason (const JSON &);
        static string version (const JSON &);
    };

    struct health_response : response {
        using response::response;
        ARC::health health () const;

        bool valid () const;
        static bool valid (const HTTP::response &r);
        static ARC::health health (const HTTP::response &r);
    };

    // the body of a successful query other than health.
    struct success : JSON {
        string timestamp () const;
        bool valid () const;

        success (JSON &&);
        success (const JSON &);
        static bool valid (const JSON &);
        static string timestamp (const JSON &);
    };

    struct policy : JSON {
        uint64 max_script_size_policy () const;
        uint64 max_tx_sigops_count_policy () const;
        uint64 max_tx_size_policy () const;
        satoshis_per_byte mining_fee () const;
        bool valid () const;

        policy (JSON &&);
        policy (const JSON &);
        static bool valid (const JSON &);
        static uint64 max_script_size_policy (const JSON &);
        static uint64 max_tx_sigops_count_policy (const JSON &);
        static uint64 max_tx_size_policy (const JSON &);
        static satoshis_per_byte mining_fee (const JSON &);

        // does a transaction satisfy the policy?
        bool satisfies (const extended::transaction &) const;
    };

    struct policy_response : response {
        using response::response;

        bool valid () const;
        string timestamp () const;
        ARC::policy policy () const;

        static bool valid (const HTTP::response &r);
        static string timestamp (const HTTP::response &r);
        static ARC::policy policy (const HTTP::response &r);
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

    struct status : success {
        Bitcoin::TXID block_hash () const;
        N block_height () const;
        string txid () const;
        string Merkle_path () const;
        status_value tx_status () const;
        JSON extra_info () const;
        JSON competing_txs () const;
        bool valid () const;

        using success::success;

        static bool valid (const JSON &);
        static Bitcoin::TXID block_hash (const JSON &);
        static N block_height (const JSON &);
        static string txid (const JSON &);
        static string Merkle_path (const JSON &);
        static status_value tx_status (const JSON &);
        static JSON extra_info (const JSON &);
        static JSON competing_txs (const JSON &);
    };

    struct status_response : response {
        using response::response;
        ARC::status status () const;
        bool valid () const;

        static ARC::status status (const HTTP::response &r);
        static bool valid (const HTTP::response &r);
    };

    enum content_type_option {text, json, octet};

    // parameters for submit methods.
    struct submit {
        content_type_option ContentType {octet};
        maybe<URL> CallbackURL {};
        maybe<bool> FullStatusUpdates {};
        maybe<int> MaxTimeout {};
        maybe<bool> SkipFeeValidation {};
        maybe<bool> SkipScriptValidation {};
        maybe<bool> SkipTxValidation {};
        maybe<bool> CumulativeFeeValidation {};
        maybe<ASCII> CallbackToken {};
        maybe<status_value> WaitFor {};

        dispatch<HTTP::header, ASCII> headers () const;
    };

    struct submit_request {
        submit_request (const extended::transaction &x) : submit_request {x, submit {}} {}
        submit_request (const extended::transaction &tx, submit x): Transaction {tx}, Submit {x} {}

        extended::transaction Transaction;
        submit Submit;
    };

    struct submit_response : response {
        using response::response;
        bool valid () const;
        ARC::status status () const;

        static bool valid (const HTTP::response &);
        static ARC::status status (const HTTP::response &);
    };

    struct submit_txs_request {
        submit_txs_request (list<extended::transaction> x) : submit_txs_request {x, submit {}} {}
        submit_txs_request (list<extended::transaction> txs, submit x): Transactions {txs}, Submit {x} {}

        list<extended::transaction> Transactions;
        submit Submit;
    };

    struct submit_txs_response : response {
        using response::response;
        bool valid () const;
        list<ARC::status> status () const;
        static bool valid (const HTTP::response &);
        static list<ARC::status> status (const HTTP::response &);
    };

    struct exception : HTTP::exception {
        using HTTP::exception::exception;
    };

    inline response::response (HTTP::response &&r): HTTP::response (r) {}

    maybe<JSON> inline response::body () const {
        return body (*this);
    }

    bool inline response::is_error () const {
        return is_error (*this);
    }

    bool inline response::valid () const {
        return valid (*this);
    }

    bool inline response::is_error (const HTTP::response &r) {
        return r.Status != HTTP::status::ok;
    }

    ARC::error inline response::error () const {
        return error (*this);
    }

    inline success::success (JSON &&j): JSON (j) {}
    inline success::success (const JSON &j): JSON (j) {}

    bool inline success::valid () const {
        return valid (*this);
    }

    string inline success::timestamp () const {
        return timestamp (*this);
    }

    bool inline success::valid (const JSON &j) {
        return j.is_object () && j.contains ("timestamp");
    }

    string inline success::timestamp (const JSON &j) {
        return std::string (j["timestamp"]);
    }

    inline health::health (JSON &&j): JSON (j) {}
    inline health::health (const JSON &j): JSON (j) {}

    bool inline health::valid () const {
        return valid (*this);
    }

    bool inline health::valid (const JSON &j) {
        return j.is_object () && j.contains ("healthy") && j["healthy"].is_boolean () && j.contains ("version") &&
            j["version"].is_string () && j.contains ("reason") && (j["reason"].is_string () || j["reason"].is_null ());
    }

    bool inline health::healthy () const {
        return healthy (*this);
    }

    string inline health::reason () const {
        return reason (*this);
    }

    string inline health::version () const {
        return version (*this);
    }

    bool inline health::healthy (const JSON &j) {
        return j["healthy"];
    }

    string inline health::reason (const JSON &j) {
        auto &r = j["reason"];
        if (!r.is_string ()) return "";
        return r;
    }

    string inline health::version (const JSON &j) {
        return j["version"];
    }

    health inline health_response::health () const {
        return health (*this);
    }

    health inline health_response::health (const HTTP::response &r) {
        if (response::is_error (r)) return JSON (nullptr);
        else return *response::body (r);
    }

    bool inline health_response::valid () const {
        return valid (*this);
    }

    inline policy::policy (JSON &&j): JSON (j) {}
    inline policy::policy (const JSON &j): JSON (j) {}

    bool inline policy::valid () const {
        return valid (*this);
    }

    uint64 inline policy::max_script_size_policy () const {
        return max_script_size_policy (*this);
    }

    uint64 inline policy::max_tx_sigops_count_policy () const {
        return max_tx_sigops_count_policy (*this);
    }

    uint64 inline policy::max_tx_size_policy () const {
        return max_tx_size_policy (*this);
    }

    satoshis_per_byte inline policy::mining_fee () const {
        return mining_fee (*this);
    }

    uint64 inline policy::max_script_size_policy (const JSON &j) {
        return j["maxscriptsizepolicy"];
    }

    uint64 inline policy::max_tx_sigops_count_policy (const JSON &j) {
        return j["maxtxsigopscountspolicy"];
    }

    uint64 inline policy::max_tx_size_policy (const JSON &j) {
        return j["maxtxsizepolicy"];
    }

    Gigamonkey::satoshis_per_byte inline policy::mining_fee (const JSON &j) {
        auto &spb = j["miningFee"];
        return Gigamonkey::satoshis_per_byte {Bitcoin::satoshi {int64 (spb["satoshis"])}, spb["bytes"]};
    }

    bool inline policy_response::valid () const {
        return valid (*this);
    }

    string inline policy_response::timestamp () const {
        return timestamp (*this);
    }

    ARC::policy inline policy_response::policy () const {
        return policy (*this);
    }

    ARC::policy inline policy_response::policy (const HTTP::response &r) {
        return (*response::body (r))["policy"];
    }

    string inline policy_response::timestamp (const HTTP::response &r) {
        return (*response::body (r))["timestamp"];
    }

    bool inline status::valid () const {
        return valid (*this);
    }

    Bitcoin::TXID inline status::block_hash () const {
        return block_hash (*this);
    }

    N inline status::block_height () const {
        return block_height (*this);
    }

    string inline status::txid () const {
        return txid (*this);
    }

    string inline status::Merkle_path () const {
        return Merkle_path (*this);
    }

    status_value inline status::tx_status () const {
        return tx_status (*this);
    }

    JSON inline status::extra_info () const {
        return extra_info (*this);
    }

    ARC::status inline status_response::status () const {
        return status (*this);
    }

    ARC::status inline status_response::status (const HTTP::response &r) {
        return *response::body (r);
    }

    bool inline status_response::valid () const {
        return valid (*this);
    }

    ARC::status inline submit_response::status () const {
        return status (*this);
    }

    ARC::status inline submit_response::status (const HTTP::response &r) {
        return *response::body (r);
    }

    list<ARC::status> inline submit_txs_response::status () const {
        return status (*this);
    }

}

#endif
