// Copyright (c) 2021-2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_PAY_MAPI
#define GIGAMONKEY_PAY_MAPI

#include <data/net/HTTP_client.hpp>
#include <data/net/TCP.hpp>
#include <gigamonkey/pay/envelope.hpp>
#include <gigamonkey/fees.hpp>

// https://github.com/bitcoin-sv-specs/brfc-merchantapi 
namespace Gigamonkey {
    namespace HTTP = data::net::HTTP;

    using unicode = data::unicode;
    using UTF8 = data::UTF8;
    using ip_address = data::net::IP::address;

    template <typename X> using awaitable = boost::asio::awaitable<X>;
}

namespace Gigamonkey::MAPI {

    template <typename T> struct response;

    struct get_policy_quote;
    struct get_fee_quote;
    struct transaction_status;
    struct submit_transaction;
    struct submit_transactions;

    using get_policy_quote_response = response<get_policy_quote>;

    using get_fee_quote_response = response<get_fee_quote>;

    using transaction_status_response = response<transaction_status>;

    struct submit_transactions_request;
    using submit_transaction_response = response<submit_transaction>;

    struct submit_transaction_request;
    using submit_transactions_response = response<submit_transactions>;

    struct client : HTTP::client {
        using HTTP::client::client;
        // there are five calls in MAPI
        awaitable<get_policy_quote_response> get_policy_quote ();
        awaitable<get_fee_quote_response> get_fee_quote ();
        awaitable<transaction_status_response> get_transaction_status (const Bitcoin::TXID &);
        awaitable<submit_transaction_response> submit_transaction (const submit_transaction_request &);
        awaitable<submit_transactions_response> submit_transactions (const submit_transactions_request &);

    private:
        HTTP::request get_policy_quote_HTTP_request () const;
        HTTP::request get_fee_quote_HTTP_request () const;
        HTTP::request transaction_status_HTTP_request (const Bitcoin::TXID &) const;
        HTTP::request submit_transaction_HTTP_request (const submit_transaction_request &) const;
        HTTP::request submit_transactions_HTTP_request (const submit_transactions_request &) const;
        awaitable<JSON> call (const HTTP::request &r);
    };

    enum service {
        mine,
        relay
    };

    struct fee {
        satoshis_per_byte MiningFee;
        satoshis_per_byte RelayFee;

        bool valid () const;

        bool operator == (const fee &v) const;

        fee ();
        fee (satoshis_per_byte mining, satoshis_per_byte relay);

        satoshis_per_byte get_fee (service z) const;
    };

    struct get_fee_quote {

        string APIVersion;
        string Timestamp;
        string ExpiryTime;
        secp256k1::pubkey MinerID;
        digest256 CurrentHighestBlockHash;
        uint64 CurrentHighestBlockHeight;
        map<string, fee> Fees;

        bool valid () const;

        get_fee_quote (
            const string &apiVersion,
            const string &timestamp,
            const string &expiryTime,
            const secp256k1::pubkey &minerId,
            const digest256 &currentHighestBlockHash,
            uint64 currentHighestBlockHeight,
            map<string, fee> fees);

        get_fee_quote (const JSON &j);
        operator JSON () const;

        get_fee_quote ();
    };

    struct get_policy_quote : get_fee_quote {
        list<ip_address> Callbacks;
        JSON Policies;

        get_policy_quote (
            const string &apiVersion,
            const string &timestamp,
            const string &expiryTime,
            const secp256k1::pubkey &minerId,
            const digest256 &currentHighestBlockHash,
            uint64 currentHighestBlockHeight,
            map<string, fee> fees,
            list<ip_address> callbacks,
            const JSON &policies);

        bool valid ();

        get_policy_quote (const JSON &);
        operator JSON () const;

        get_policy_quote ();
    };

    // whether a transaction was processed or not.
    enum return_result {
        failure,
        success
    };

    // to indicate a double spend.
    struct conflicted_with {

        Bitcoin::TXID TXID;
        uint64 Size;
        bytes Transaction;

        bool valid () const;

        conflicted_with (const JSON &);
        operator JSON () const;

        conflicted_with () : TXID {}, Size {}, Transaction {} {}

    };

    struct status {

        digest256 TXID;
        return_result ReturnResult;
        string ResultDescription;
        list<conflicted_with> ConflictedWith;

        bool valid () const;

        status (
            const digest256 &txid,
            return_result returnResult,
            const string &resultDescription,
            list<conflicted_with> conflicted = {});

        status () = default;
        operator JSON () const;

    };

    struct transaction_status : status {

        string APIVersion;
        string Timestamp;
        secp256k1::pubkey MinerID;
        uint32 TxSecondMempoolExpiry;

        // maybe fields included for txs that have been mined.
        maybe<digest256> BlockHash;
        maybe<uint32> BlockHeight;
        maybe<uint32> Confirmations;

        bool valid () const;

        transaction_status (
            const string &apiVersion,
            const string &timestamp,
            const digest256 &txid,
            return_result returnResult,
            const string &resultDescription,
            const secp256k1::pubkey &minerId,
            uint32 txSecondMempoolExpiry);

        transaction_status (
            const string &apiVersion,
            const string &timestamp,
            const digest256 &txid,
            return_result returnResult,
            const string &resultDescription,
            const secp256k1::pubkey &minerId,
            uint32 txSecondMempoolExpiry,
            const digest256 blockHash,
            uint32 blockHeight,
            uint32 confirmations);

        transaction_status (const JSON &);
        operator JSON () const;

        transaction_status () = default;

    };

    enum content_type {
        application_JSON,
        application_octet_stream,
    };

    struct submit_transaction_parameters {

        maybe<string> CallbackURL;
        maybe<string> CallbackToken;
        maybe<bool> MerkleProof;
        maybe<string> MerkleFormat;
        maybe<bool> DSCheck;
        maybe<string> CallbackEncryption;

        submit_transaction_parameters () = default;

        submit_transaction_parameters &set_CallbackURL (const string &);
        submit_transaction_parameters &set_CallbackToken (const string &);
        submit_transaction_parameters &set_MerkleProof (bool);
        submit_transaction_parameters &set_DSCheck (bool);
        submit_transaction_parameters &set_CallbackEncryption (const string &key);
        submit_transaction_parameters &set_MerkleFormat ();

    };

    struct transaction_submission {

        bytes Transaction;
        submit_transaction_parameters Parameters;

        bool valid () const;

        transaction_submission (const JSON &);
        operator JSON () const;

        transaction_submission (const bytes raw, const submit_transaction_parameters &p = {});

    };

    struct submit_transaction_request : transaction_submission {

        content_type ContentType;

        submit_transaction_request (
            const bytes tx,
            const submit_transaction_parameters &params = {},
            content_type ct = application_octet_stream) : transaction_submission {tx, params}, ContentType {ct} {}

    };

    struct submit_transaction : status {

        string APIVersion;
        string Timestamp;
        secp256k1::pubkey MinerID;
        uint32 TxSecondMempoolExpiry;
        digest256 CurrentHighestBlockHash;
        uint64 CurrentHighestBlockHeight;

        submit_transaction (
            const string &apiVersion,
            const string &timestamp,
            const digest256 &txid,
            return_result returnResult,
            const string &resultDescription,
            const secp256k1::pubkey &minerId,
            uint32 txSecondMempoolExpiry,
            const digest256 &currentHighestBlockHash,
            uint64 currentHighestBlockHeight,
            list<conflicted_with> conflictedWith = {});

        submit_transaction (const JSON &);
        operator JSON () const;

        submit_transaction () :
            status {}, APIVersion {}, Timestamp {}, MinerID {},
            TxSecondMempoolExpiry {0}, CurrentHighestBlockHash {}, CurrentHighestBlockHeight {0} {}

    };

    struct submit_transactions_request {

        list<transaction_submission> Submissions;

        submit_transaction_parameters DefaultParameters;

        bool valid () const;

    };

    struct submit_transactions {

        string APIVersion;
        string Timestamp;
        secp256k1::pubkey MinerID;
        digest256 CurrentHighestBlockHash;
        uint64 CurrentHighestBlockHeight;
        uint32 TxSecondMempoolExpiry;
        list<status> Transactions;
        uint32 FailureCount;

        bool valid () const;

        submit_transactions ();

        submit_transactions (const JSON &);
        operator JSON () const;

    };

    // every MAPI response comes in a JSON_envelope with a signature.
    template <typename T> struct response : T {

        maybe<secp256k1::pubkey> PublicKey;
        maybe<secp256k1::signature> Signature;

        response (const JSON &j);
        response (const T &t);
        response (const T &t, secp256k1::pubkey p, secp256k1::signature x);

        // verify signature
        bool verify () const;

        operator JSON () const;
        explicit operator JSON_JSON_envelope () const;

    };

    struct exception : HTTP::exception {
        using HTTP::exception::exception;
    };

    HTTP::request inline client::get_policy_quote_HTTP_request () const {
        return this->REST.GET ("/mapi/policyQuote");
    }

    HTTP::request inline client::get_fee_quote_HTTP_request () const {
        return this->REST.GET ("/mapi/feeQuote");
    }
    
    awaitable<get_policy_quote_response> inline client::get_policy_quote () {
        co_return co_await call (get_policy_quote_HTTP_request ());
    }
    
    awaitable<get_fee_quote_response> inline client::get_fee_quote () {
        co_return co_await call (get_fee_quote_HTTP_request ());
    }
    
    awaitable<transaction_status_response> inline client::get_transaction_status (const Bitcoin::TXID &txid) {
        co_return co_await call (transaction_status_HTTP_request (txid));
    }
    
    awaitable<submit_transaction_response> inline client::submit_transaction (const submit_transaction_request &r) {
        co_return co_await call (submit_transaction_HTTP_request (r));
    }
    
    awaitable<submit_transactions_response> inline client::submit_transactions (const submit_transactions_request &r) {
        co_return co_await call (submit_transactions_HTTP_request (r));
    }

    inline fee::fee (satoshis_per_byte mining, satoshis_per_byte relay) :
        MiningFee {mining}, RelayFee {relay} {}

    inline fee::fee () : MiningFee {0, 0}, RelayFee {0, 0} {}

    bool inline fee::operator == (const fee &v) const {
        return MiningFee == v.MiningFee && RelayFee == v.RelayFee;
    }
    
    bool inline fee::valid () const {
        return MiningFee.valid () && RelayFee.valid ();
    }
    
    satoshis_per_byte inline fee::get_fee (service z) const {
        return z == mine ? MiningFee : RelayFee;
    }
            
    bool inline conflicted_with::valid () const {
        return TXID.valid () && Size == Transaction.size ();
    }
    
    bool inline status::valid () const {
        return TXID.valid ();
    }
    
    bool inline get_fee_quote::valid () const {
        return Timestamp != "" && ExpiryTime != "" && MinerID.valid () &&
            CurrentHighestBlockHash.valid () && CurrentHighestBlockHeight != 0 && data::valid(Fees);
    }
    
    inline get_fee_quote::get_fee_quote (
        const string &v, 
        const string &t, 
        const string &ex, 
        const secp256k1::pubkey &id, 
        const digest256 &hx,
        uint64 cx, 
        map<string, fee> f) : 
        APIVersion {v}, Timestamp {t}, ExpiryTime {ex}, MinerID {id},
        CurrentHighestBlockHash {hx}, CurrentHighestBlockHeight {cx}, Fees {f} {}
            
    inline get_fee_quote::get_fee_quote () :
        APIVersion {}, Timestamp {}, ExpiryTime {}, MinerID {},
        CurrentHighestBlockHash {}, CurrentHighestBlockHeight {0}, Fees {} {}
            
    inline get_policy_quote::get_policy_quote (
        const string &apiVersion, 
        const string &timestamp, 
        const string &expiryTime, 
        const secp256k1::pubkey &minerId, 
        const digest256 &currentHighestBlockHash,
        uint64 currentHighestBlockHeight, 
        map<string, fee> fees, 
        list<ip_address> callbacks,
        const JSON &policies) :
        get_fee_quote {
            apiVersion, timestamp, expiryTime, minerId, 
            currentHighestBlockHash, currentHighestBlockHeight, fees}, 
        Callbacks {callbacks}, Policies {policies} {}
            
    bool inline get_policy_quote::valid () {
        return get_fee_quote::valid () && data::valid (Fees);
    }
            
    inline get_policy_quote::get_policy_quote () :
        get_fee_quote {}, Callbacks {}, Policies {} {}
    
    bool inline transaction_submission::valid () const {
        return Transaction.size () > 0;
    }

    inline transaction_submission::transaction_submission (const bytes raw, const submit_transaction_parameters &p):
        Transaction {raw}, Parameters {p} {}

    inline status::status (
        const digest256 &txid,
        return_result returnResult,
        const string &resultDescription,
        list<conflicted_with> conflicted) :
        TXID {txid}, ReturnResult {returnResult},
        ResultDescription {resultDescription}, ConflictedWith {conflicted} {}
        
    bool inline transaction_status::valid () const {
        return APIVersion != "" && Timestamp != "" && MinerID != secp256k1::pubkey {};
    }

    bool inline submit_transactions::valid () const {
        return Timestamp != "" && MinerID.valid () &&
            CurrentHighestBlockHash.valid () && CurrentHighestBlockHeight != 0 &&
            TxSecondMempoolExpiry != 0 && Transactions.valid ();
    }

    inline submit_transactions::submit_transactions () :
        APIVersion {}, Timestamp {}, MinerID {},
        CurrentHighestBlockHash {},
        CurrentHighestBlockHeight {0},
        TxSecondMempoolExpiry {0}, Transactions {}, FailureCount {0} {}
    
    bool inline submit_transactions_request::valid () const {
        return Submissions.size () > 0 && data::valid (Submissions);
    }

    template <typename T>
    inline response<T>::response (const T &t) : T {t}, PublicKey {}, Signature {} {}

    template <typename T>
    inline response<T>::response (const T &t, secp256k1::pubkey p, secp256k1::signature x) : T {t}, PublicKey {p}, Signature {x} {}

    template <typename T>
    bool inline response<T>::verify () const {
        return verify (JSON_JSON_envelope (*this));
    }

    template <typename T>
    response<T>::response (const JSON &j) : T {} {
        JSON_JSON_envelope e (j);
        if (!e.valid ()) return;
        static_cast<T> (*this) = T {e.payload ()};
        PublicKey = e.PublicKey;
        Signature = e.Signature;
    }

    template <typename T>
    inline response<T>::operator JSON () const {
        return JSON (JSON_JSON_envelope (*this));
    }

    template <typename T>
    inline response<T>::operator JSON_JSON_envelope () const {
        return bool (PublicKey) && bool (Signature) ?
            JSON_JSON_envelope {JSON (static_cast<T> (*this)), *PublicKey, *Signature} :
            JSON_JSON_envelope {JSON (static_cast<T> (*this))};
    }
}

#endif
