// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_MAPI_MAPI
#define GIGAMONKEY_MAPI_MAPI

#include <data/networking/http.hpp>
#include <gigamonkey/timechain.hpp>
#include <gigamonkey/secp256k1.hpp>

namespace Gigamonkey {
    struct merchant_api {
        using http = data::networking::http;
        
        string Host;
        http Http;
        
        struct satoshi_per_byte {
            satoshi Satoshis;
            uint64 Bytes;
            
            bool valid() const {
                return Bytes != 0;
            }
            
            satoshi_per_byte() : Satoshis{0}, Bytes{0} {}
            explicit satoshi_per_byte(const string&);
        };
        
        struct fee {
            string feeType;
            satoshi_per_byte miningFee;
            satoshi_per_byte relayFee;
            
            bool valid() const {
                return feeType != "" && miningFee.valid() && relayFee.valid();
            }
            
            fee();
            explicit fee(const string&);
        };
        
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
            
            get_fee_quote_response();
            get_fee_quote_response(const string&);
        };
        
        get_fee_quote_response get_fee_quote();
        
        enum content_type {
            json,
            octet_stream,
        };
        
        struct submission_parameters {
            std::optional<string> callbackUrl;
            std::optional<string> callbackToken;
            std::optional<bool> merkleProof;
            std::optional<bool> dsCheck;
            std::optional<string> callbackEncryption;
            
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
            
            explicit submission(ptr<bytes>);
            
            bool valid() const {
                return rawtx != nullptr;
            }
        };
        
        struct submit_transaction_request {
            content_type ContentType;
            submission Submission;
            
            bool valid() const;
            
            explicit submit_transaction_request(ptr<bytes> tx) : ContentType{octet_stream}, Submission{tx} {}
            
            explicit operator Gigamonkey::json() const;
        };
        
        enum return_result {
            failure, 
            success
        };
        
        struct conflicted_with {
            Bitcoin::txid txid;
            uint64 size;
            string hex;
            
            bool valid() const;
            
        private:
            conflicted_with();
            conflicted_with(const string&);
        };
        
        struct submission_response {
            Bitcoin::txid txid;
            return_result returnResult;
            string resultDescription;
            std::optional<list<conflicted_with>> conflictedWith;
            
            bool valid() const;
            
            submission_response();
            submission_response(const string&);
        };
        
        struct submit_transaction_response {
            string apiVersion;
            string timestamp;
            Bitcoin::pubkey minerId;
            digest256 currentHighestBlockHash;
            uint64 currentHighestBlockHeight;
            uint32 txSecondMempoolExpiry;
            submission_response SubmissionResponse;
            
            bool valid() const;
            
            submit_transaction_response();
            submit_transaction_response(const string&);
        };
        
        submit_transaction_response submit_transaction(ptr<bytes> tx) {
            return submit_transaction(submit_transaction_request{tx});
        }
        
        submit_transaction_response submit_transaction(submit_transaction_request);
        
        struct query_transaction_status_response {
            string apiVersion;
            string timestamp;
            bool returnResult;
            string resultDescription;
            digest256 blockHash;
            uint64 blockHeight;
            Bitcoin::pubkey minerId;
            uint64 confirmations;
            uint32 txSecondMempoolExpiry;
            
            bool valid() const;
            
            query_transaction_status_response();
            query_transaction_status_response(const string&);
        };
        
        query_transaction_status_response query_transaction_status(const Bitcoin::txid&);
        
        struct submit_multiple_transactions_request {
            content_type ContentType;
            list<submission> Submissions;
            
            submission_parameters DefaultParameters;
            
            bool valid() const {
                if (!Submissions.valid()) return false;
                if (ContentType == octet_stream) for (const submission& x : Submissions) if(!x.Parameters.empty()) return false;
                return true;
            }
            
            submit_multiple_transactions_request(list<ptr<bytes>> txs);
            
            explicit operator Gigamonkey::json() const;
        };
        
        struct submit_multiple_transactions_response {
            string apiVersion;
            string timestamp;
            Bitcoin::pubkey minerId;
            digest256 currentHighestBlockHash;
            uint64 currentHighestBlockHeight;
            uint32 txSecondMempoolExpiry;
            list<submission_response> txs;
            
            bool valid() const; 
            
            submit_multiple_transactions_response();
            submit_multiple_transactions_response(const string&);
        };
        
        submit_multiple_transactions_response submit_multiple_transactions(list<ptr<bytes>> txs) {
            return submit_multiple_transactions(submit_multiple_transactions_request{txs});
        }
        
        submit_multiple_transactions_response submit_multiple_transactions(submit_multiple_transactions_request);
        
        constexpr static char get_fee_quote_path[] = "/mapi/feeQuote";
        constexpr static char submit_transaction_path[] = "/mapi/tx";
        constexpr static char query_transaction_status_path[] = "/mapi/tx/";
        constexpr static char submit_multiple_transactions_path[] = "/mapi/txs";
        
    };
    
}

#endif
