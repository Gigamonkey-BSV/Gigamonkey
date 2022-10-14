// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_MAPI_MAPI
#define GIGAMONKEY_MAPI_MAPI

#include <boost/asio/ip/address.hpp>
#include <data/networking/HTTP_client.hpp>
#include <gigamonkey/fees.hpp>

// https://github.com/bitcoin-sv-specs/brfc-merchantapi 

namespace Gigamonkey {
    using ip_address = boost::asio::ip::address;
}

namespace Gigamonkey::BitcoinAssociation {

    struct MAPI : networking::HTTP_client {
        MAPI(networking::HTTP_client &client) : networking::HTTP_client{client} {}
        
        // there are five calls in MAPI
        
        struct get_policy_quote_response;
        get_policy_quote_response get_policy_quote();
        
        struct get_fee_quote_response;
        get_fee_quote_response get_fee_quote();
        
        struct transaction_status_response;
        transaction_status_response get_transaction_status(const Bitcoin::txid&);
        
        struct submit_transaction_request;
        struct submit_transaction_response;
        submit_transaction_response submit_transaction(const submit_transaction_request &);
        
        struct submit_transactions_request;
        struct submit_transactions_response;
        submit_transactions_response submit_transactions(const submit_transactions_request &);
        
        enum service {
            mine, 
            relay
        };
        
        struct fee {
            string feeType;
            satoshi_per_byte miningFee;
            satoshi_per_byte relayFee;
            
            bool valid() const;
            
            fee(string type, satoshi_per_byte mining, satoshi_per_byte relay) : 
                feeType{type}, miningFee{mining}, relayFee{relay} {}
                
            fee(const json &j);
            operator json() const;
            
            satoshi_per_byte get_fee(service z) const;
            
            fee() : feeType{}, miningFee{0, 0}, relayFee{0, 0} {}
        };
    
        struct get_fee_quote_response {
            
            string apiVersion;
            string timestamp;
            string expiryTime;
            secp256k1::pubkey minerId;
            digest256 currentHighestBlockHash;
            uint64 currentHighestBlockHeight;
            list<fee> fees;
            
            bool valid() const;
            
            get_fee_quote_response(
                const string& apiVersion, 
                const string& timestamp, 
                const string& expiryTime, 
                const secp256k1::pubkey& minerId, 
                const digest256& currentHighestBlockHash,
                uint64 currentHighestBlockHeight, 
                list<fee> fees);
            
            get_fee_quote_response(const json &j);
            operator json() const;
            
            get_fee_quote_response();
        };
        
        struct policies {
            
            list<uint32> skipscriptflags;
            uint64 maxtxsizepolicy;
            uint64 datacarriersize;
            uint64 maxscriptsizepolicy;
            uint64 maxscriptnumlengthpolicy;
            uint64 maxstackmemoryusagepolicy;
            uint64 limitancestorcount;
            uint64 limitcpfpgroupmemberscount;
            bool acceptnonstdoutputs;
            bool datacarrier;
            uint64 maxstdtxvalidationduration;
            uint64 maxnonstdtxvalidationduration;
            optional<uint64> dustrelayfee;
            optional<uint64> dustlimitfactor;
            
            static bool valid(const json &);
            
            policies(const json &);
            operator json() const;
            
            policies();
        
        };
        
        struct get_policy_quote_response : get_fee_quote_response {
            list<ip_address> callbacks;
            MAPI::policies policies;
            
            get_policy_quote_response(
                const string& apiVersion, 
                const string& timestamp, 
                const string& expiryTime, 
                const secp256k1::pubkey& minerId, 
                const digest256& currentHighestBlockHash,
                uint64 currentHighestBlockHeight, 
                list<fee> fees, 
                list<ip_address> callbacks, 
                const MAPI::policies& policies);
            
            bool valid();
            
            get_policy_quote_response(const json &);
            operator json() const;
            
            get_policy_quote_response();
        };
        
        // whether a transaction was processed or not. 
        enum return_result {
            failure, 
            success
        };
        
        // to indicate a double spend. 
        struct conflicted_with {
            
            Bitcoin::txid txid;
            uint64 size;
            encoding::hex::string hex;
            
            bool valid() const;
            
            conflicted_with(const json &);
            operator json() const;
            
            conflicted_with() : txid{}, size{}, hex{} {}
            
        };
        
        struct transaction_status {
            
            digest256 txid;
            return_result returnResult;
            string resultDescription;
            list<conflicted_with> conflictedWith;
            
            bool valid() const;
            
            transaction_status(
                const digest256& Txid, 
                return_result ReturnResult,
                const string& ResultDescription,
                list<conflicted_with> Conflicted = {}) :
                txid{Txid}, returnResult{ReturnResult}, 
                resultDescription{ResultDescription}, conflictedWith{Conflicted} {}
            
            transaction_status();
            
        };
        
        struct transaction_status_response : transaction_status {
            
            string apiVersion;
            string timestamp;
            secp256k1::pubkey minerId;
            uint32 txSecondMempoolExpiry;
            
            // optional fields included for txs that have been mined. 
            optional<digest256> blockHash;
            optional<uint32> blockHeight;
            optional<uint32> confirmations;
            
            bool valid() const;
            
            transaction_status_response(
                const string& apiVersion, 
                const string& timestamp, 
                const digest256& txid, 
                return_result returnResult, 
                const string& resultDescription, 
                const secp256k1::pubkey& minerId, 
                uint32 txSecondMempoolExpiry);
            
            transaction_status_response(
                const string& apiVersion, 
                const string& timestamp, 
                const digest256& txid, 
                return_result returnResult, 
                const string& resultDescription, 
                const secp256k1::pubkey& minerId, 
                uint32 txSecondMempoolExpiry, 
                const digest256 blockHash, 
                uint32 blockHeight, 
                uint32 confirmations);
            
            transaction_status_response(const json &);
            operator json() const;
            
            transaction_status_response();
            
        };
    
        enum content_type {
            application_json,
            application_octet_stream,
        };
    
        struct submit_transaction_parameters {
            
            optional<string> callbackUrl;
            optional<string> callbackToken;
            optional<bool> merkleProof;
            optional<string> merkleFormat;
            optional<bool> dsCheck;
            optional<string> callbackEncryption;
            
            submit_transaction_parameters();
            
            submit_transaction_parameters &set_callbackUrl(const string &);
            submit_transaction_parameters &set_callbackToken(const string &);
            submit_transaction_parameters &set_merkleProof(bool);
            submit_transaction_parameters &set_dsCheck(bool);
            submit_transaction_parameters &set_callbackEncryption(const string &key);
            submit_transaction_parameters &set_merkleFormat();
            
        };
    
        struct transaction_submission {
            
            bytes rawtx;
            submit_transaction_parameters Parameters;
            
            bool valid() const;
            
            transaction_submission(const json &);
            operator json() const;
            
            transaction_submission(const bytes raw, const submit_transaction_parameters &);
            
        };
    
        struct submit_transaction_request : transaction_submission {
            
            content_type contentType() const;
            
            bool valid() const;
            
            submit_transaction_request(
                const bytes tx, 
                content_type ContentType, 
                const string &callbackUrl, 
                const string &callbackToken, 
                bool merkleProof, 
                bool dsCheck);
            
            operator networking::REST::request() const;
            
            submit_transaction_request &set_callbackEncryption(const string &key);
            submit_transaction_request &set_merkleFormat();
            
        };
        
        struct submit_transaction_response : transaction_status {
            
            string apiVersion;
            string timestamp;
            secp256k1::pubkey minerId;
            uint32 txSecondMempoolExpiry;
            digest256 currentHighestBlockHash;
            uint64 currentHighestBlockHeight;
            
            submit_transaction_response(
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
            
            submit_transaction_response(const json &);
            operator json() const;
            
            submit_transaction_response();
            
        };
        
        struct submit_transactions_request {
            
            content_type ContentType;
            list<transaction_submission> Submissions;
            
            submit_transaction_parameters DefaultParameters;
            
            bool valid() const;
            
            operator networking::REST::request() const;
            
        };
        
        struct submit_transactions_response {
            
            string apiVersion;
            string timestamp;
            secp256k1::pubkey minerId;
            digest256 currentHighestBlockHash;
            uint64 currentHighestBlockHeight;
            uint32 txSecondMempoolExpiry;
            list<transaction_status> txs;
            uint32 failureCount;
            
            bool valid() const {
                return apiVersion != "" && timestamp != "" && minerId.valid() && 
                    currentHighestBlockHash.valid() && currentHighestBlockHeight != 0 && 
                    txSecondMempoolExpiry != 0 && txs.valid(); 
            }
            
            submit_transactions_response() : 
                apiVersion{}, timestamp{}, minerId{}, 
                currentHighestBlockHash{}, 
                currentHighestBlockHeight{0}, 
                txSecondMempoolExpiry{0}, txs{}, failureCount{0} {}
            
            submit_transactions_response(const json&);
            operator json() const;
            
        };
        
    private:
        networking::HTTP::request get_policy_quote_HTTP_request() const {
            return this->Rest.GET("/mapi/policyQuote");
        }
        
        networking::HTTP::request get_fee_quote_HTTP_request() const {
            return this->Rest.GET("/mapi/feeQuote");
        }
        
        networking::HTTP::request transaction_status_HTTP_request(const Bitcoin::txid&) const;
        networking::HTTP::request submit_transaction_HTTP_request(const submit_transaction_request &) const;
        networking::HTTP::request submit_transactions_HTTP_request(const submit_transactions_request &) const;
        
        static json read_MAPI_response(const networking::HTTP::response &r);
    };
    
    MAPI::get_policy_quote_response inline MAPI::get_policy_quote() {
        return read_MAPI_response((*this)(get_policy_quote_HTTP_request()));
    }
    
    MAPI::get_fee_quote_response inline MAPI::get_fee_quote() {
        return read_MAPI_response((*this)(get_fee_quote_HTTP_request()));
    }
    
    MAPI::transaction_status_response inline MAPI::get_transaction_status(const Bitcoin::txid &txid) {
        return read_MAPI_response((*this)(transaction_status_HTTP_request(txid)));
    }
    
    MAPI::submit_transaction_response inline MAPI::submit_transaction(const submit_transaction_request &r) {
        return read_MAPI_response((*this)(submit_transaction_HTTP_request(r)));
    }
    
    MAPI::submit_transactions_response inline MAPI::submit_transactions(const submit_transactions_request &r) {
        return read_MAPI_response((*this)(submit_transactions_HTTP_request(r)));
    }
    
    bool inline MAPI::fee::valid() const {
        return feeType != "" && miningFee.valid() && relayFee.valid();
    }
    
    satoshi_per_byte inline MAPI::fee::get_fee(service z) const {
        return z == mine ? miningFee : relayFee;
    }
            
    bool inline MAPI::conflicted_with::valid() const {
        return txid.valid() && size * 2 == hex.size();
    }
    
    bool inline MAPI::transaction_status::valid() const {
        return txid.valid();
    }
    
    bool inline MAPI::get_fee_quote_response::valid() const {
        return apiVersion != "" && timestamp != "" && expiryTime != "" && minerId.valid() && 
            currentHighestBlockHash.valid() && currentHighestBlockHeight != 0 && data::valid(fees);
    }
    
    inline MAPI::get_fee_quote_response::get_fee_quote_response(
        const string& v, 
        const string& t, 
        const string& ex, 
        const secp256k1::pubkey& id, 
        const digest256& hx,
        uint64 cx, 
        list<fee> f) : 
        apiVersion{v}, timestamp{t}, expiryTime{ex}, minerId{id}, 
        currentHighestBlockHash{hx}, currentHighestBlockHeight{cx}, fees{f} {}
            
    inline MAPI::get_fee_quote_response::get_fee_quote_response() : 
        apiVersion{}, timestamp{}, expiryTime{}, minerId{}, 
        currentHighestBlockHash{}, currentHighestBlockHeight{0}, fees{} {}
            
    inline MAPI::get_policy_quote_response::get_policy_quote_response(
        const string& apiVersion, 
        const string& timestamp, 
        const string& expiryTime, 
        const secp256k1::pubkey& minerId, 
        const digest256& currentHighestBlockHash,
        uint64 currentHighestBlockHeight, 
        list<fee> fees, 
        list<ip_address> Callbacks, 
        const MAPI::policies& Policies) : 
        get_fee_quote_response{
            apiVersion, timestamp, expiryTime, minerId, 
            currentHighestBlockHash, currentHighestBlockHeight, fees}, 
        callbacks{Callbacks}, policies{Policies} {}
            
    bool inline MAPI::get_policy_quote_response::valid() {
        return get_fee_quote_response::valid() && data::valid(fees);
    }
            
    inline MAPI::get_policy_quote_response::get_policy_quote_response() : 
        get_fee_quote_response{}, callbacks{}, policies{} {}
}

#endif
