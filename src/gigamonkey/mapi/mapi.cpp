// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include<gigamonkey/mapi/envelope.hpp>
#include<gigamonkey/mapi/mapi.hpp>

namespace Gigamonkey::MAPI {
    
    satoshi_per_byte::satoshi_per_byte(const json& j) : satoshi_per_byte{} {
        
        if (!(j.is_object() && 
            j.contains("satoshis") && j["satoshis"].is_number_unsigned() && 
            j.contains("bytes") && j["bytes"].is_number_unsigned())) return;
        
        satoshis = uint64(j["satoshis"]);
        bytes = uint64(j["bytes"]);
        
    }
    
    fee::fee(const json& j) : fee{} {
        
        if (!(j.is_object() && 
            j.contains("feeType") && j["feeType"].is_string() && 
            j.contains("miningFee") && j.contains("relayFee"))) return;
        
        satoshi_per_byte mf{j["miningFee"]};
        
        if (!mf.valid()) return;
        
        satoshi_per_byte rf{j["relayFee"]};
        
        if (!rf.valid()) return;
        
        feeType = j["feeType"];
        miningFee = mf;
        relayFee = rf;
        
    }
    
    submission::operator json() const {
        if (!valid()) return {};
        
        json j{{"rawtx", encoding::hex::write(*rawtx)}};
        
        if (Parameters.callbackUrl.has_value()) j["callbackUrl"] = *Parameters.callbackUrl;
        if (Parameters.callbackToken.has_value()) j["callbackToken"] = *Parameters.callbackToken;
        if (Parameters.merkleProof.has_value()) j["merkleProof"] = *Parameters.merkleProof;
        if (Parameters.dsCheck.has_value()) j["dsCheck"] = *Parameters.dsCheck;
        if (Parameters.callbackEncryption.has_value()) j["callbackEncryption"] = *Parameters.callbackEncryption;
        
        return j;
    }
    
    get_fee_quote_response::get_fee_quote_response(const string& r) : 
        get_fee_quote_response{} {
        
        json j{r};
        
        if (!(j.is_object() && 
            j.contains("apiVersion") && j["apiVersion"].is_string() && 
            j.contains("timestamp") && j["timestamp"].is_string() && 
            j.contains("expiryTime") && j["expiryTime"].is_string() && 
            j.contains("minerId") && j["minerId"].is_string() && 
            j.contains("currentHighestBlockHash") && j["currentHighestBlockHash"].is_string() && 
            j.contains("currentHighestBlockHeight") && j["currentHighestBlockHeight"].is_number_unsigned() && 
            j.contains("fees") && j["fees"].is_array())) return;
        
        list<fee> f;
        
        for (const json& jf : j["fees"]) {
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
    
    conflicted_with::conflicted_with(const json& j) : conflicted_with{} {
        
        if (!(j.is_object() && 
            j.contains("txid") && j["txid"].is_string() && 
            j.contains("size") && j["size"].is_number_unsigned() && 
            j.contains("hex") && j["hex"].is_string())) return;
        
        txid = digest256{string(j["txid"])};
        size = uint64(j["size"]);
        hex = j["hex"];
        
    }
    
    submission_response::submission_response(const json& j) : submission_response{} {
        
        if (!(j.is_object() && 
            j.contains("txid") && j["txid"].is_string() && 
            j.contains("returnResult") && j["returnResult"].is_string() && 
            j.contains("returnDescription") && j["returnDescription"].is_string() && 
            (!j.contains("conflictedWith") || j["conflictedWith"].is_array()))) return;
        
        string rr = j["returnResult"];
        if (rr == "success") returnResult = success;
        else if (rr == "failure") returnResult = failure;
        else return;
        
        if (j.contains("conflictedWith")) {
            list<conflicted_with> cw;
            for (const json& w : j["conflictedWith"]) {
                cw = cw << conflicted_with{w};
                if (!cw.first().valid()) return;
            }
            conflictedWith = cw;
        }
        
        txid = digest256{string(j["txid"])};
        resultDescription = j["resultDescription"];
        
    }
    
    submit_transaction_response::submit_transaction_response(const string& r) : 
        submit_transaction_response{} {
        
        json j{r};
        
        if (!(j.is_object() && 
            j.contains("apiVersion") && j["apiVersion"].is_string() && 
            j.contains("timestamp") && j["timestamp"].is_string() && 
            j.contains("minerId") && j["minerId"].is_string() && 
            j.contains("currentHighestBlockHash") && j["currentHighestBlockHash"].is_string() && 
            j.contains("currentHighestBlockHeight") && j["currentHighestBlockHeight"].is_number_unsigned() && 
            j.contains("txSecondMempoolExpiry") && j["txSecondMempoolExpiry"].is_number_unsigned())) return;
        
        submission_response sub{j};
        
        if (!sub.valid()) return;
        
        apiVersion = j["apiVersion"];
        timestamp = j["timestamp"];
        minerId = Bitcoin::pubkey{string(j["minerId"])};
        currentHighestBlockHash = digest256{string(j["currentHighestBlockHash"])};
        currentHighestBlockHeight = j["currentHighestBlockHeight"];
        txSecondMempoolExpiry = uint32(j["txSecondMempoolExpiry"]);
        SubmissionResponse = sub;
        
    }
    
    query_transaction_status_response::query_transaction_status_response(const string& r) : 
        query_transaction_status_response{} {
        
        json j{r};
        
        if (!(j.is_object() && 
            j.contains("apiVersion") && j["apiVersion"].is_string() && 
            j.contains("timestamp") && j["timestamp"].is_string() && 
            j.contains("txid") && j["txid"].is_string() && 
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
        txid = Bitcoin::txid{string(j["txid"])};
        resultDescription = j["resultDescription"];
        blockHash = digest256{string(j["blockHash"])};
        blockHeight = j["blockHeight"];
        minerId = Bitcoin::pubkey{string(j["minerId"])};
        txSecondMempoolExpiry = uint32(j["txSecondMempoolExpiry"]);
        
        if (j.contains("confirmations")) confirmations = uint64(j["confirmations"]);
        
    }
    
    submit_multiple_transactions_response::submit_multiple_transactions_response(const string& r) : 
        submit_multiple_transactions_response{} {
        
        json j{r};
        
        if (!(j.is_object() && 
            j.contains("apiVersion") && j["apiVersion"].is_string() && 
            j.contains("timestamp") && j["timestamp"].is_string() && 
            j.contains("minerId") && j["minerId"].is_string() && 
            j.contains("currentHighestBlockHash") && j["currentHighestBlockHash"].is_string() && 
            j.contains("currentHighestBlockHeight") && j["currentHighestBlockHeight"].is_number_unsigned() && 
            j.contains("txSecondMempoolExpiry") && j["txSecondMempoolExpiry"].is_number_unsigned() && 
            j.contains("txs") && j["txs"].is_array() && 
            j.contains("failureCount") && j["failureCount"].is_number_unsigned())) return;
        
        list<submission_response> sr;
        for (const json& w : j["txs"]) {
            sr = sr << submission_response{w};
            if (!sr.first().valid()) return;
        }
        
        apiVersion = j["apiVersion"];
        timestamp = j["timestamp"];
        minerId = Bitcoin::pubkey{string(j["minerId"])};
        currentHighestBlockHash = digest256{string(j["currentHighestBlockHash"])};
        currentHighestBlockHeight = j["currentHighestBlockHeight"];
        txSecondMempoolExpiry = uint32(j["txSecondMempoolExpiry"]);
        txs = sr;
        failureCount = uint32(j["failureCount"]);
        
    }
    
    string to_json(return_result r) {
        return r == success ? "success" : "failure";
    }
    
    json to_json(list<submission> subs) {
        json j = json::array();
        
        for (const submission& sub : subs) j.push_back(json(sub));
        
        return j;
    }
    
    json to_json(list<fee> fees);
    
    get_fee_quote_response::operator json() const {
        return valid() ? json{
            {"apiVersion", apiVersion},
            {"timestamp", timestamp}, 
            {"expiryTime", expiryTime}, 
            {"minerId", string(minerId)}, 
            {"currentHighestBlockHash", string(currentHighestBlockHash.Value)}, 
            {"currentHighestBlockHeight", currentHighestBlockHeight}, 
            {"fees", to_json(fees)}} : json{};
    }
    
    submit_transaction_response::operator json() const {
        return valid() ? json{
            {"apiVersion", apiVersion},
            {"timestamp", timestamp},
            {"txid", string(SubmissionResponse.txid.Value)}, 
            {"returnResult", to_json(SubmissionResponse.returnResult)}, 
            {"resultDescription", SubmissionResponse.resultDescription}, 
            {"minerId", string(minerId)}, 
            {"currentHighestBlockHash", string(currentHighestBlockHash.Value)}, 
            {"currentHighestBlockHeight", currentHighestBlockHeight}, 
            {"txSecondMempoolExpiry", txSecondMempoolExpiry}} : json{};
    }
    
    query_transaction_status_response::operator json() const {
        if (!valid()) return {};
        
        json j{
            {"apiVersion", apiVersion}, 
            {"timestamp", timestamp}, 
            {"txid", string(txid.Value)}, 
            {"returnResult", to_json(returnResult)}, 
            {"resultDescription", resultDescription}, 
            {"minerId", string(minerId)}, 
            {"txSecondMempoolExpiry", txSecondMempoolExpiry}};
    
        if (confirmations.has_value()) j["confirmations"] = *confirmations; 
    
        return j;
    }
    
    submit_multiple_transactions_response::operator json() const {
        return valid() ? json{
            {"apiVersion", apiVersion}, 
            {"timestamp", timestamp}, 
            {"minerId", string(minerId)}, 
            {"currentHighestBlockHash", string(currentHighestBlockHash.Value)}, 
            {"currentHighestBlockHeight", currentHighestBlockHeight}, 
            {"txSecondMempoolExpiry", txSecondMempoolExpiry}, 
            {"txs", }, 
            {"failureCount", failureCount}} : json{};
    }
    
    std::map<string, string> submission_parameters::http_parameters() const {
        
        std::map<string, string> params;
            
        if (callbackUrl.has_value()) params["callbackUrl"] = *callbackUrl;
        if (callbackToken.has_value()) params["callbackToken"] = *callbackToken;
        if (merkleProof.has_value()) params["merkleProof"] = *merkleProof;
        if (dsCheck.has_value()) params["dsCheck"] = *dsCheck;
        if (callbackEncryption.has_value()) params["callbackEncryption"] = *callbackEncryption;
        
        return params;
        
    }
    
    get_fee_quote_response merchant_api::get_fee_quote() {
        
        JSONEnvelope envelope;
        try {
            envelope = JSONEnvelope{Http->GET(Host, string{get_fee_quote_path})};
        } catch (...) {
            return {};
        }
        
        if (!envelope.valid()) return {};
        
        return get_fee_quote_response{envelope.payload};
        
    }
    
    submit_transaction_response merchant_api::submit_transaction(submit_transaction_request request) {
        
        if (!request.valid()) return {};
        
        std::map<string, string> params;
        std::map<http::header, string> headers;
        string body;
        
        if (request.ContentType == application_json) {
            headers[http::header::content_type] = "application/json";
            body = string(json(request.Submission));
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
    
    query_transaction_status_response merchant_api::query_transaction_status(const Bitcoin::txid& id) {
        
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
    
    submit_multiple_transactions_response 
    merchant_api::submit_multiple_transactions(submit_multiple_transactions_request request) {
        
        if (!request.valid()) return {};
        
        std::map<string, string> params = request.DefaultParameters.http_parameters();
        std::map<http::header, string> headers;
        string body;
        
        if (request.ContentType == application_json) {
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
