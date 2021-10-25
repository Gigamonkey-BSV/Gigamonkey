// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_MAPI_MAPI
#define GIGAMONKEY_MAPI_MAPI

//#include <data/networking/http.hpp>
#include <gigamonkey/wallet.hpp>

namespace Gigamonkey::MAPI {
    
    struct get_fee_quote_response;
    struct submit_transaction_request;
    struct submit_transaction_response;
    struct query_transaction_status_response;
    struct submit_multiple_transactions_request;
    struct submit_multiple_transactions_response;
    
    std::ostream &operator<<(std::ostream &, const get_fee_quote_response &);
    std::ostream &operator<<(std::ostream &, const submit_transaction_request &);
    std::ostream &operator<<(std::ostream &, const submit_transaction_response &);
    std::ostream &operator<<(std::ostream &, const query_transaction_status_response &);
    std::ostream &operator<<(std::ostream &, const submit_multiple_transactions_request &);
    std::ostream &operator<<(std::ostream &, const submit_multiple_transactions_response &);
    
    using satoshi_per_byte = Bitcoin::satoshi_per_byte;
    
    enum service {
        mine, 
        relay
    };
    
    struct fee {
        string feeType;
        satoshi_per_byte miningFee;
        satoshi_per_byte relayFee;
        
        bool valid() const {
            return feeType != "" && miningFee.valid() && relayFee.valid();
        }
        
        fee() : feeType{}, miningFee{}, relayFee{} {}
        explicit fee(const json&);
        
        explicit operator json() const;
        
        satoshi_per_byte get(service z) const {
            return z == mine ? miningFee : relayFee;
        }
    };
    
    bool operator==(const fee &, const fee &);
    bool operator!=(const fee &, const fee &);
    
    struct get_fee_quote_response {
        
        string apiVersion;
        string timestamp;
        string expiryTime;
        Bitcoin::pubkey minerId;
        digest256 currentHighestBlockHash;
        uint64 currentHighestBlockHeight;
        list<fee> fees;
        
        bool valid() const {
            return apiVersion != "" && timestamp != "" && expiryTime != "" && 
                minerId.valid() && currentHighestBlockHash.valid() && 
                currentHighestBlockHeight != 0 && fees.size() != 0;
        }
        
        get_fee_quote_response() : 
            apiVersion{}, timestamp{}, expiryTime{}, minerId{}, 
            currentHighestBlockHash{}, currentHighestBlockHeight{0}, fees{} {}
        
        get_fee_quote_response(const string&);
        
        explicit operator json() const;
        
        Bitcoin::fee to(service) const;
        
    };
    
    enum content_type {
        application_json,
        application_octet_stream,
    };
    
    struct submission_parameters {
        
        optional<string> callbackUrl;
        optional<string> callbackToken;
        optional<bool> merkleProof;
        optional<bool> dsCheck;
        optional<string> callbackEncryption;
        
        std::map<string, string> http_parameters() const;
        
        bool empty() const {
            return !(callbackUrl.has_value() || 
                callbackToken.has_value() || 
                merkleProof.has_value() || 
                dsCheck.has_value() || 
                callbackEncryption.has_value());
        }
        
    };
    
    struct submission {
        
        ptr<bytes> rawtx;
        submission_parameters Parameters;
        
        explicit submission(ptr<bytes> p) : rawtx{p} {}
        
        bool valid() const {
            return rawtx != nullptr;
        }
        
        explicit operator json() const;
    };
    
    struct submit_transaction_request {
        
        content_type ContentType;
        submission Submission;
        
        bool valid() const {
            return Submission.valid();
        }
        
        explicit submit_transaction_request(ptr<bytes> tx) : ContentType{application_octet_stream}, Submission{tx} {}
        
    };
    
    enum return_result {
        failure, 
        success
    };
    
    struct conflicted_with {
        
        Bitcoin::txid txid;
        uint64 size;
        string hex;
        
        bool valid() const {
            return txid.valid() && size != 0 && hex != "";
        }
        
        conflicted_with() : txid{}, size{0}, hex{} {}
        
        conflicted_with(const json&);
        
    };
    
    struct submission_response {
        
        Bitcoin::txid txid;
        return_result returnResult;
        string resultDescription;
        optional<list<conflicted_with>> conflictedWith;
        
        bool valid() const {
            return txid.valid() && (!conflictedWith.has_value() || conflictedWith->valid());
        }
        
        submission_response() : txid{}, returnResult{failure}, resultDescription{}, conflictedWith{} {}
        
        submission_response(const json&);
        
        operator json() const;
        
    };
    
    struct submit_transaction_response {
        
        string apiVersion;
        string timestamp;
        Bitcoin::pubkey minerId;
        digest256 currentHighestBlockHash;
        uint64 currentHighestBlockHeight;
        uint32 txSecondMempoolExpiry;
        submission_response SubmissionResponse;
        
        bool valid() const {
            return apiVersion != "" && timestamp != "" && minerId.valid() && 
            currentHighestBlockHash.valid() && currentHighestBlockHeight != 0 && 
            txSecondMempoolExpiry != 0;
        }
        
        submit_transaction_response() : 
            apiVersion{}, timestamp{}, minerId{}, 
            currentHighestBlockHash{}, 
            currentHighestBlockHeight{0}, 
            txSecondMempoolExpiry{}, 
            SubmissionResponse{} {}
        
        submit_transaction_response(const string&);
        
        explicit operator json() const;
        
    };
    
    struct query_transaction_status_response {
        
        string apiVersion;
        string timestamp;
        Bitcoin::txid txid;
        return_result returnResult;
        string resultDescription;
        digest256 blockHash;
        uint64 blockHeight;
        Bitcoin::pubkey minerId;
        optional<uint64> confirmations;
        uint32 txSecondMempoolExpiry;
        
        bool valid() const {
            return apiVersion != "" && timestamp != "" && txid.valid() && resultDescription != "" && 
                blockHash.valid() && blockHeight != 0 && minerId.valid() && txSecondMempoolExpiry != 0;
        }
        
        query_transaction_status_response() : 
            apiVersion{}, timestamp{}, txid{}, returnResult{failure}, 
            resultDescription{}, blockHash{}, blockHeight{0}, 
            minerId{}, confirmations{}, txSecondMempoolExpiry{0} {}
        
        query_transaction_status_response(const string&);
        
        explicit operator json() const;
        
    };
    
    struct submit_multiple_transactions_request {
        
        content_type ContentType;
        list<submission> Submissions;
        
        submission_parameters DefaultParameters;
        
        bool valid() const {
            if (!Submissions.valid()) return false;
            if (ContentType == application_octet_stream) 
                for (const submission& x : Submissions) if(!x.Parameters.empty()) return false;
            return true;
        }
        
        submit_multiple_transactions_request(list<ptr<bytes>> txs);
        
    };
    
    struct submit_multiple_transactions_response {
        
        string apiVersion;
        string timestamp;
        Bitcoin::pubkey minerId;
        digest256 currentHighestBlockHash;
        uint64 currentHighestBlockHeight;
        uint32 txSecondMempoolExpiry;
        list<submission_response> txs;
        uint32 failureCount;
        
        bool valid() const {
            return apiVersion != "" && timestamp != "" && minerId.valid() && 
                currentHighestBlockHash.valid() && currentHighestBlockHeight != 0 && 
                txSecondMempoolExpiry != 0 && txs.valid(); 
        }
        
        submit_multiple_transactions_response() : 
            apiVersion{}, timestamp{}, minerId{}, 
            currentHighestBlockHash{}, 
            currentHighestBlockHeight{0}, 
            txSecondMempoolExpiry{0}, txs{}, failureCount{0} {}
        
        submit_multiple_transactions_response(const string&);
        
        explicit operator json() const;
        
    };
    /*
    struct merchant_api {
        using http = data::networking::http;
        
        string Host;
        ptr<http> Http;
        
        get_fee_quote_response get_fee_quote();
        
        submit_transaction_response submit_transaction(ptr<bytes> tx) {
            return submit_transaction(submit_transaction_request{tx});
        }
        
        submit_transaction_response submit_transaction(submit_transaction_request);
        
        query_transaction_status_response query_transaction_status(const Bitcoin::txid&);
        
        submit_multiple_transactions_response submit_multiple_transactions(list<ptr<bytes>> txs) {
            return submit_multiple_transactions(submit_multiple_transactions_request{txs});
        }
        
        submit_multiple_transactions_response submit_multiple_transactions(submit_multiple_transactions_request);
        
        constexpr static char get_fee_quote_path[] = "/mapi/feeQuote";
        constexpr static char submit_transaction_path[] = "/mapi/tx";
        constexpr static char query_transaction_status_path[] = "/mapi/tx/";
        constexpr static char submit_multiple_transactions_path[] = "/mapi/txs";
        
    };*/
    
    std::ostream inline &operator<<(std::ostream &o, const get_fee_quote_response& r) {
        return o << json(r);
    }
    
    std::ostream inline &operator<<(std::ostream &o, const submit_transaction_response& r) {
        return o << json(r);
    }
    
    std::ostream inline &operator<<(std::ostream &o, const query_transaction_status_response& r) {
        return o << json(r);
    }
    
    std::ostream inline &operator<<(std::ostream &o, const submit_multiple_transactions_response& r) {
        return o << json(r);
    }
    
    bool inline operator==(const fee &a, const fee &b) {
        return a.feeType == b.feeType && a.miningFee == b.miningFee && a.relayFee == b.relayFee;
    }
    
    bool inline operator!=(const fee &a, const fee &b) {
        return !(a == b);
    }
    
}

#endif
