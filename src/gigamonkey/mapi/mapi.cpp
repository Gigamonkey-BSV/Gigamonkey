// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include<gigamonkey/mapi/envelope.hpp>
#include<gigamonkey/mapi/mapi.hpp>

namespace Gigamonkey {
    
    merchant_api::get_fee_quote_response::get_fee_quote_response(const string& r) : 
        get_fee_quote_response{} {
        
        Gigamonkey::json j{r};
        
        if (!(j.is_object() && 
            j.contains("apiVersion") && j["apiVersion"].is_string() && 
            j.contains("timestamp") && j["timestamp"].is_string() && 
            j.contains("expiryTime") && j["expiryTime"].is_string() && 
            j.contains("minerId") && j["minerId"].is_string() && 
            j.contains("currentHighestBlockHash") && j["currentHighestBlockHash"].is_string() && 
            j.contains("currentHighestBlockHeight") && j["currentHighestBlockHeight"].is_number_unsigned() && 
            j.contains("fees") && j["fees"].is_array())) return;
        
        list<fee> f;
        
        for (const Gigamonkey::json& jf : j["fees"]) {
            f = f << fee{jf};
            if (!f.first().valid()) return;
        }
        
        apiVersion = j["apiVersion"];
        timestamp = j["timestamp"];
        expiryTime = j["expiryTime"];
        minerId = Bitcoin::pubkey{string(j["minerId"])};
        currentHighestBlockHash = digest256{string(j["currentHighestBlockHash"])};
        currentHighestBlockHeight = j["currentHighestBlockHeight"];
        fees = f;
        
    }
    
    merchant_api::query_transaction_status_response::query_transaction_status_response(const string& r) : 
        query_transaction_status_response{} {
        
        Gigamonkey::json j{r};
        
        if (!(j.is_object() && 
            j.contains("apiVersion") && j["apiVersion"].is_string() && 
            j.contains("timestamp") && j["timestamp"].is_string() && 
            j.contains("returnResult") && j["returnResult"].is_string() && 
            j.contains("returnDescription") && j["returnDescription"].is_string() && 
            j.contains("blockHash") && j["blockHash"].is_string() && 
            j.contains("blockHeight") && j["blockHeight"].is_number_unsigned() && 
            j.contains("minerId") && j["minerId"].is_string() && 
            (!j.contains("confirmations") || j["confirmations"].is_number_unsigned()) && 
            j.contains("txSecondMempoolExpiry") && j["txSecondMempoolExpiry"].is_number_unsigned())) return;
        
        string rr = j["returnResult"];
        if (rr == "success") returnResult = success;
        else if (rr == "failure") returnResult = failure;
        else return;
        
        apiVersion = j["apiVersion"];
        timestamp = j["timestamp"];
        txid = Bitcoin::txid{string(j["minerId"])};
        resultDescription = j["resultDescription"];
        blockHash = digest256{string(j["blockHash"])};
        blockHeight = j["blockHeight"];
        minerId = Bitcoin::pubkey{string(j["minerId"])};
        txSecondMempoolExpiry = uint32(j["txSecondMempoolExpiry"]);
        
        if (j.contains("confirmations")) confirmations = uint64(j["confirmations"]);
        
    }
    
    json to_json(list<merchant_api::submission> subs) {
        json j = json::array();
        
        for (const merchant_api::submission& sub : subs) j.push_back(json(sub));
        
        return j;
    }
    
    std::map<string, string> merchant_api::submission_parameters::http_parameters() const {
        
        std::map<string, string> params;
            
        if (callbackUrl.has_value()) params["callbackUrl"] = *callbackUrl;
        if (callbackToken.has_value()) params["callbackToken"] = *callbackToken;
        if (merkleProof.has_value()) params["merkleProof"] = *merkleProof;
        if (dsCheck.has_value()) params["dsCheck"] = *dsCheck;
        if (callbackEncryption.has_value()) params["callbackEncryption"] = *callbackEncryption;
        
        return params;
        
    }
    
    merchant_api::get_fee_quote_response merchant_api::get_fee_quote() {
        
        JSONEnvelope envelope;
        try {
            envelope = JSONEnvelope{Http->GET(Host, string{get_fee_quote_path})};
        } catch (...) {
            return {};
        }
        
        if (!envelope.valid()) return {};
        
        return get_fee_quote_response{envelope.payload};
        
    }
    
    merchant_api::submit_transaction_response merchant_api::submit_transaction(submit_transaction_request request) {
        
        if (!request.valid()) return {};
        
        std::map<string, string> params;
        std::map<http::header, string> headers;
        string body;
        
        if (request.ContentType == json) {
            headers[http::header::content_type] = "application/json";
            body = string(Gigamonkey::json(request));
        } else {
            headers[http::header::content_type] = "application/octet-stream";
            body.resize(request.Submission.rawtx->size());
            std::copy(request.Submission.rawtx->begin(), request.Submission.rawtx->end(), body.begin());
            
            params = request.Submission.Parameters.http_parameters();
        }
        
        JSONEnvelope envelope;
        try {
            envelope = JSONEnvelope{Http->POST(Host, submit_transaction_path, params, headers, body)};
        } catch (...) {
            return {};
        }
        
        if (!envelope.valid()) return {};
        
        return submit_transaction_response{envelope.payload};
        
    }
    
    merchant_api::query_transaction_status_response merchant_api::query_transaction_status(const Bitcoin::txid& id) {
        
        JSONEnvelope envelope;
        try {
            envelope = JSONEnvelope{Http->GET(Host, 
                string{query_transaction_status_path} + string(id.Value).substr(2))};
        } catch (...) {
            return {};
        }
        
        if (!envelope.valid()) return {};
        
        return query_transaction_status_response{envelope.payload};
        
    }
    
    merchant_api::submit_multiple_transactions_response 
    merchant_api::submit_multiple_transactions(submit_multiple_transactions_request request) {
        
        if (!request.valid()) return {};
        
        std::map<string, string> params = request.DefaultParameters.http_parameters();
        std::map<http::header, string> headers;
        string body;
        
        if (request.ContentType == json) {
            headers[http::header::content_type] = "application/json";
            body = string(to_json(request.Submissions));
        } else {
            headers[http::header::content_type] = "application/octet-stream";
            uint64 total_size = 0;
            
            for (const submission& x : request.Submissions) {
                total_size += x.rawtx->size();
            }
            
            body.resize(total_size);
            
            auto it = body.begin();
            for (const submission& x : request.Submissions) {
                std::copy(x.rawtx->begin(), x.rawtx->end(), it);
            }
        }
        
        JSONEnvelope envelope;
        try {
            envelope = JSONEnvelope{Http->POST(Host, submit_multiple_transactions_path, params, headers, body)};
        } catch (...) {
            return {};
        }
        
        if (!envelope.valid()) return {};
        
        return submit_multiple_transactions_response{envelope.payload};
        
    }
    
}
