// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_MAPI_MAPI
#define GIGAMONKEY_MAPI_MAPI

#include <data/net/HTTP_client.hpp>
#include <data/net/TCP.hpp>
#include <gigamonkey/mapi/envelope.hpp>
#include <gigamonkey/fees.hpp>

// https://github.com/bitcoin-sv-specs/brfc-merchantapi 

namespace Gigamonkey::BitcoinAssociation {
    
    struct MAPI : net::HTTP::client_blocking {
        using net::HTTP::client_blocking::client_blocking;
        
        // there are five calls in MAPI
        
        struct get_policy_quote_response;
        get_policy_quote_response get_policy_quote ();
        
        struct get_fee_quote_response;
        get_fee_quote_response get_fee_quote ();
        
        struct transaction_status_response;
        transaction_status_response get_transaction_status (const Bitcoin::txid &);
        
        struct submit_transaction_request;
        struct submit_transaction_response;
        submit_transaction_response submit_transaction (const submit_transaction_request &);
        
        struct submit_transactions_request;
        struct submit_transactions_response;
        submit_transactions_response submit_transactions (const submit_transactions_request &);
        
        enum service {
            mine, 
            relay
        };
        
        struct fee {
            satoshi_per_byte MiningFee;
            satoshi_per_byte RelayFee;
            
            bool valid () const;
            
            fee (satoshi_per_byte mining, satoshi_per_byte relay) :
                MiningFee {mining}, RelayFee {relay} {}
            
            satoshi_per_byte get_fee (service z) const;
            
            fee () : MiningFee {0, 0}, RelayFee {0, 0} {}
            
            bool operator == (const fee& v) const {
                return MiningFee == v.MiningFee && RelayFee == v.RelayFee;
            }
        };
    
        struct get_fee_quote_response {
            
            string APIVersion;
            string Timestamp;
            string ExpiryTime;
            secp256k1::pubkey MinerID;
            digest256 CurrentHighestBlockHash;
            uint64 CurrentHighestBlockHeight;
            map<string, fee> Fees;
            
            bool valid () const;
            
            get_fee_quote_response(
                const string &apiVersion, 
                const string &timestamp, 
                const string &expiryTime, 
                const secp256k1::pubkey &minerId, 
                const digest256 &currentHighestBlockHash,
                uint64 currentHighestBlockHeight, 
                map<string, fee> fees);
            
            get_fee_quote_response (const JSON &j);
            operator JSON () const;
            
            get_fee_quote_response ();
        };
        
        struct get_policy_quote_response : get_fee_quote_response {
            list<net::IP::address> Callbacks;
            JSON Policies;
            
            get_policy_quote_response (
                const string &apiVersion, 
                const string &timestamp, 
                const string &expiryTime, 
                const secp256k1::pubkey &minerId, 
                const digest256 &currentHighestBlockHash,
                uint64 currentHighestBlockHeight, 
                map<string, fee> fees, 
                list<net::IP::address> callbacks,
                const JSON &policies);
            
            bool valid ();
            
            get_policy_quote_response (const JSON &);
            operator JSON () const;
            
            get_policy_quote_response ();
        };
        
        // whether a transaction was processed or not. 
        enum return_result {
            failure, 
            success
        };
        
        // to indicate a double spend. 
        struct conflicted_with {
            
            Bitcoin::txid TXID;
            uint64 Size;
            bytes Transaction;
            
            bool valid () const;
            
            conflicted_with (const JSON &);
            operator JSON () const;
            
            conflicted_with () : TXID {}, Size {}, Transaction {} {}
            
        };
        
        struct transaction_status {
            
            digest256 TXID;
            return_result ReturnResult;
            string ResultDescription;
            list<conflicted_with> ConflictedWith;
            
            bool valid () const;
            
            transaction_status (
                const digest256 &txid, 
                return_result returnResult,
                const string &resultDescription,
                list<conflicted_with> conflicted = {}) :
                TXID {txid}, ReturnResult {returnResult},
                ResultDescription {resultDescription}, ConflictedWith {conflicted} {}
            
            transaction_status () = default;
            operator JSON () const;
            
        };
        
        struct transaction_status_response : transaction_status {
            
            string APIVersion;
            string Timestamp;
            secp256k1::pubkey MinerID;
            uint32 TxSecondMempoolExpiry;
            
            // maybe fields included for txs that have been mined.
            maybe<digest256> BlockHash;
            maybe<uint32> BlockHeight;
            maybe<uint32> Confirmations;
            
            bool valid () const;
            
            transaction_status_response (
                const string &apiVersion, 
                const string &timestamp, 
                const digest256 &txid, 
                return_result returnResult, 
                const string &resultDescription, 
                const secp256k1::pubkey &minerId, 
                uint32 txSecondMempoolExpiry);
            
            transaction_status_response (
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
            
            transaction_status_response (const JSON &);
            operator JSON () const;
            
            transaction_status_response () = default;
            
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
            
            transaction_submission (const bytes raw, const submit_transaction_parameters &p = {}):
                Transaction {raw}, Parameters {p} {}
            
        };
    
        struct submit_transaction_request : transaction_submission {
            
            content_type ContentType;
            
            submit_transaction_request (
                const bytes tx, 
                const submit_transaction_parameters &params = {}, 
                content_type ct = application_octet_stream) : transaction_submission {tx, params}, ContentType {ct} {}
            
            operator net::HTTP::REST::request () const;
            
        };
        
        struct submit_transaction_response : transaction_status {
            
            string APIVersion;
            string Timestamp;
            secp256k1::pubkey MinerID;
            uint32 TxSecondMempoolExpiry;
            digest256 CurrentHighestBlockHash;
            uint64 CurrentHighestBlockHeight;
            
            submit_transaction_response (
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
            
            submit_transaction_response (const JSON &);
            operator JSON () const;
            
            submit_transaction_response () :
                transaction_status {}, APIVersion {}, Timestamp {}, MinerID {},
                TxSecondMempoolExpiry {0}, CurrentHighestBlockHash {}, CurrentHighestBlockHeight {0} {}
            
        };
        
        struct submit_transactions_request {
            
            list<transaction_submission> Submissions;
            
            submit_transaction_parameters DefaultParameters;
            
            bool valid () const;
            
            operator net::HTTP::REST::request () const;
            
        };
        
        struct submit_transactions_response {
            
            string APIVersion;
            string Timestamp;
            secp256k1::pubkey MinerID;
            digest256 CurrentHighestBlockHash;
            uint64 CurrentHighestBlockHeight;
            uint32 TxSecondMempoolExpiry;
            list<transaction_status> Transactions;
            uint32 FailureCount;
            
            bool valid () const {
                return Timestamp != "" && MinerID.valid () &&
                    CurrentHighestBlockHash.valid () && CurrentHighestBlockHeight != 0 &&
                    TxSecondMempoolExpiry != 0 && Transactions.valid(); 
            }
            
            submit_transactions_response () :
                APIVersion {}, Timestamp {}, MinerID {},
                CurrentHighestBlockHash {},
                CurrentHighestBlockHeight {0},
                TxSecondMempoolExpiry {0}, Transactions {}, FailureCount {0} {}
            
            submit_transactions_response (const JSON&);
            operator JSON () const;
            
        };
        
    private:
        net::HTTP::request get_policy_quote_HTTP_request () const {
            return this->REST.GET ("/mapi/policyQuote");
        }
        
        net::HTTP::request get_fee_quote_HTTP_request () const {
            return this->REST.GET ("/mapi/feeQuote");
        }
        
        net::HTTP::request transaction_status_HTTP_request (const Bitcoin::txid&) const;
        net::HTTP::request submit_transaction_HTTP_request (const submit_transaction_request &) const;
        net::HTTP::request submit_transactions_HTTP_request (const submit_transactions_request &) const;
        
        JSON call (const net::HTTP::request &r);
    };
    
    MAPI::get_policy_quote_response inline MAPI::get_policy_quote () {
        return call (get_policy_quote_HTTP_request ());
    }
    
    MAPI::get_fee_quote_response inline MAPI::get_fee_quote () {
        return call (get_fee_quote_HTTP_request());
    }
    
    MAPI::transaction_status_response inline MAPI::get_transaction_status (const Bitcoin::txid &txid) {
        return call (transaction_status_HTTP_request (txid));
    }
    
    MAPI::submit_transaction_response inline MAPI::submit_transaction (const submit_transaction_request &r) {
        return call (submit_transaction_HTTP_request (r));
    }
    
    MAPI::submit_transactions_response inline MAPI::submit_transactions (const submit_transactions_request &r) {
        return call (submit_transactions_HTTP_request (r));
    }
    
    bool inline MAPI::fee::valid () const {
        return MiningFee.valid () && RelayFee.valid ();
    }
    
    satoshi_per_byte inline MAPI::fee::get_fee (service z) const {
        return z == mine ? MiningFee : RelayFee;
    }
            
    bool inline MAPI::conflicted_with::valid () const {
        return TXID.valid () && Size == Transaction.size ();
    }
    
    bool inline MAPI::transaction_status::valid () const {
        return TXID.valid ();
    }
    
    bool inline MAPI::get_fee_quote_response::valid () const {
        return Timestamp != "" && ExpiryTime != "" && MinerID.valid () &&
            CurrentHighestBlockHash.valid () && CurrentHighestBlockHeight != 0 && data::valid(Fees);
    }
    
    inline MAPI::get_fee_quote_response::get_fee_quote_response (
        const string &v, 
        const string &t, 
        const string &ex, 
        const secp256k1::pubkey &id, 
        const digest256 &hx,
        uint64 cx, 
        map<string, fee> f) : 
        APIVersion {v}, Timestamp {t}, ExpiryTime {ex}, MinerID {id},
        CurrentHighestBlockHash {hx}, CurrentHighestBlockHeight {cx}, Fees {f} {}
            
    inline MAPI::get_fee_quote_response::get_fee_quote_response () :
        APIVersion {}, Timestamp {}, ExpiryTime {}, MinerID {},
        CurrentHighestBlockHash {}, CurrentHighestBlockHeight {0}, Fees {} {}
            
    inline MAPI::get_policy_quote_response::get_policy_quote_response(
        const string &apiVersion, 
        const string &timestamp, 
        const string &expiryTime, 
        const secp256k1::pubkey &minerId, 
        const digest256 &currentHighestBlockHash,
        uint64 currentHighestBlockHeight, 
        map<string, fee> fees, 
        list<net::IP::address> callbacks,
        const JSON &policies) : 
        get_fee_quote_response{
            apiVersion, timestamp, expiryTime, minerId, 
            currentHighestBlockHash, currentHighestBlockHeight, fees}, 
        Callbacks {callbacks}, Policies {policies} {}
            
    bool inline MAPI::get_policy_quote_response::valid () {
        return get_fee_quote_response::valid () && data::valid (Fees);
    }
            
    inline MAPI::get_policy_quote_response::get_policy_quote_response () :
        get_fee_quote_response {}, Callbacks {}, Policies {} {}
    
    bool inline MAPI::transaction_submission::valid () const {
        return Transaction.size () > 0;
    }
        
    bool inline MAPI::transaction_status_response::valid () const {
        return APIVersion != "" && Timestamp != "" && MinerID != secp256k1::pubkey {};
    }
    
    bool inline MAPI::submit_transactions_request::valid () const {
        return Submissions.size () > 0 && data::valid (Submissions);
    }
            
}

#endif
