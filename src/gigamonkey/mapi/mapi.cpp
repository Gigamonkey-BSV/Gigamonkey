// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/mapi/envelope.hpp>
#include <gigamonkey/mapi/mapi.hpp>

namespace Gigamonkey::BitcoinAssociation {
    using namespace Bitcoin;
    
    json MAPI::read_MAPI_response(const networking::HTTP::response &r) {
        if (static_cast<unsigned int>(r.Status) < 200 || 
            static_cast<unsigned int>(r.Status) >= 300) throw networking::HTTP::response{r};
        
        if (r.Headers[networking::HTTP::header::content_type] != "application/json") throw networking::HTTP::response{r};
        
        json_json_envelope envelope{json::parse(r.Body)};
        
        if (!envelope.valid() || !envelope.verify()) throw networking::HTTP::response{r};
        
        return envelope.payload();
    }
    
    networking::HTTP::request MAPI::transaction_status_HTTP_request(const Bitcoin::txid &request) const {
        if (!request.valid()) throw std::invalid_argument{"invalid txid"};
        std::stringstream ss;
        ss << "/mapi/tx/" << request;
        return this->Rest.GET(ss.str());
    }
    
    networking::HTTP::request MAPI::submit_transaction_HTTP_request(const submit_transaction_request &request) const {
        if (!request.valid()) throw std::invalid_argument{"invalid transaction submission request"};
        return this->Rest(networking::REST::request(request));
    }
    
    networking::HTTP::request MAPI::submit_transactions_HTTP_request(const submit_transactions_request &request) const {
        if (!request.valid()) throw std::invalid_argument{"invalid transactions submission request"};
        return this->Rest(networking::REST::request(request));
    }
    
    namespace {
    
        satoshi_per_byte spb_from_json(const json& j) {
            
            if (!(j.is_object() && 
                j.contains("satoshis") && j["satoshis"].is_number_unsigned() && 
                j.contains("bytes") && j["bytes"].is_number_unsigned())) return{};
            
            return satoshi_per_byte{satoshi{int64(j["satoshis"])}, uint64(j["bytes"])};
            
        }
        
        json to_json(const satoshi_per_byte v) {
            return json{{"satoshis", int64(v.Satoshis)}, {"bytes", v.Bytes}};
        }
    
        string to_json(MAPI::return_result r) {
            return r == MAPI::success ? "success" : "failure";
        }
        
        json to_json(list<MAPI::transaction_submission> subs) {
            json j = json::array();
            
            for (const MAPI::transaction_submission& sub : subs) j.push_back(json(sub));
            
            return j;
        }
        
        json to_json(list<MAPI::fee> fees) {
            json j = json::array();
            
            for (const MAPI::fee& f : fees) {
                j.push_back(json(f));
            }
            
            return j;
        }
        
        optional<list<ip_address>> read_ip_address_list(const json &); 
        
        json to_json(list<ip_address>);
    
        MAPI::transaction_status read_transaction_status(const json& j) {
            MAPI::transaction_status x;
            
            if (!(j.is_object() && 
                j.contains("txid") && j["txid"].is_string() && 
                j.contains("returnResult") && j["returnResult"].is_string() && 
                j.contains("returnDescription") && j["returnDescription"].is_string() && 
                (!j.contains("conflictedWith") || j["conflictedWith"].is_array()))) return {};
            
            string rr = j["returnResult"];
            if (rr == "success") x.returnResult = MAPI::success;
            else if (rr == "failure") x.returnResult = MAPI::failure;
            else return {};
            
            if (j.contains("conflictedWith")) {
                list<MAPI::conflicted_with> cw;
                for (const json& w : j["conflictedWith"]) {
                    cw = cw << MAPI::conflicted_with{w};
                    if (!cw.first().valid()) return {};
                }
                x.conflictedWith = cw;
            }
            
            x.txid = digest256{string{"0x"} + string(j["txid"])};
            if (!x.txid.valid()) return {};
            
            x.resultDescription = j["resultDescription"];
            
            return x;
        }
    
        json to_json(const MAPI::submit_transaction_parameters &x) {
            json j = json::object_t{};
            
            if (x.callbackUrl.has_value()) j["callbackUrl"] = *x.callbackUrl;
            if (x.callbackToken.has_value()) j["callbackToken"] = *x.callbackToken;
            if (x.merkleProof.has_value()) j["merkleProof"] = *x.merkleProof;
            if (x.dsCheck.has_value()) j["dsCheck"] = *x.dsCheck;
            if (x.callbackEncryption.has_value()) j["callbackEncryption"] = *x.callbackEncryption;
            
            return j;
        }
    
        json to_json(const MAPI::transaction_submission &x) {
            if (!x.valid()) return {};
            
            json j = to_json(x.Parameters);
            
            j["rawtx"] = encoding::hex::write(x.rawtx);
            
            return j;
        }
        
        json to_json(list<MAPI::conflicted_with>);
        
        json to_json(const MAPI::transaction_status &tst) {
            if (!tst.valid()) return {};
        
            json j{ 
                {"txid", string(tst.txid.Value)}, 
                {"returnResult", to_json(tst.returnResult)}, 
                {"resultDescription", tst.resultDescription}};
        
            if (tst.conflictedWith.size() > 0) j["conflictedWith"] = to_json(tst.conflictedWith);
            
            return j;
        }
        
    }
    
    MAPI::fee::fee(const json& j) : fee{} {
        
        if (!(j.is_object() && 
            j.contains("feeType") && j["feeType"].is_string() && 
            j.contains("miningFee") && j.contains("relayFee"))) return;
        
        satoshi_per_byte mf = spb_from_json(j["miningFee"]);
        
        if (!mf.valid()) return;
        
        satoshi_per_byte rf = spb_from_json(j["relayFee"]);
        
        if (!rf.valid()) return;
        
        feeType = j["feeType"];
        miningFee = mf;
        relayFee = rf;
        
    }
    
    MAPI::fee::operator json() const {
        return valid() ? json{
            {"feeType", feeType}, 
            {"miningFee", to_json(miningFee)}, 
            {"relayFee", to_json(relayFee)}} : json(nullptr);
    }
    
    MAPI::conflicted_with::conflicted_with(const json& j) : conflicted_with{} {
        
        if (!(j.is_object() && 
            j.contains("txid") && j["txid"].is_string() && 
            j.contains("size") && j["size"].is_number_unsigned() && 
            j.contains("hex") && j["hex"].is_string())) return;
        
        txid = digest256{string{"0x"} + string(j["txid"])};
        size = uint64(j["size"]);
        hex = j["hex"];
        
    }
    
    MAPI::get_fee_quote_response::get_fee_quote_response(const json& j) : get_fee_quote_response{} {
        
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
        
        auto pk_hex = encoding::hex::read(string(j["minerId"]));
        if (pk_hex == nullptr) return;
        
        digest256 last_block{string{"0x"} + string(j["currentHighestBlockHash"])};
        if (!last_block.valid()) return;
        
        apiVersion = j["apiVersion"];
        timestamp = j["timestamp"];
        expiryTime = j["expiryTime"];
        
        minerId = secp256k1::pubkey{*pk_hex};
        currentHighestBlockHash = last_block;
        currentHighestBlockHeight = j["currentHighestBlockHeight"];
        fees = f;
        
    }
    
    MAPI::get_fee_quote_response::operator json() const {
        std::stringstream ss;
        ss << currentHighestBlockHash;
        return valid() ? json{
            {"apiVersion", apiVersion},
            {"timestamp", timestamp}, 
            {"expiryTime", expiryTime}, 
            {"minerId", encoding::hex::write(minerId)}, 
            {"currentHighestBlockHash", ss.str().substr(2)}, 
            {"currentHighestBlockHeight", currentHighestBlockHeight}, 
            {"fees", to_json(fees)}} : json{};
    }
    
    MAPI::get_policy_quote_response::get_policy_quote_response(const json &j) : get_fee_quote_response{} {
        
        if (!j.contains("callbacks") || !j.contains("policies")) return;
        
        get_fee_quote_response parent{j};
        if (!parent.valid()) return;
        
        auto ips = read_ip_address_list(j["callbacks"]);
        if (!bool(ips)) return;
        
        if (!MAPI::policies::valid(j["policies"])) return;
        
        static_cast<get_fee_quote_response>(*this) = parent;
        
        policies = MAPI::policies{j["policies"]};
        callbacks = *ips;
    }
    
    MAPI::get_policy_quote_response::operator json() const {
        json j = get_fee_quote_response::operator json();
        
        if (j == nullptr) return nullptr;
        
        j["callbacks"] = to_json(callbacks);
        j["policies"] = json(policies);
        
        return j;
    }
    
    MAPI::submit_transaction_response::submit_transaction_response(const json& j) : 
        submit_transaction_response{} {
        
        if (!(j.is_object() && 
            j.contains("apiVersion") && j["apiVersion"].is_string() && 
            j.contains("timestamp") && j["timestamp"].is_string() && 
            j.contains("minerId") && j["minerId"].is_string() && 
            j.contains("currentHighestBlockHash") && j["currentHighestBlockHash"].is_string() && 
            j.contains("currentHighestBlockHeight") && j["currentHighestBlockHeight"].is_number_unsigned() && 
            j.contains("txSecondMempoolExpiry") && j["txSecondMempoolExpiry"].is_number_unsigned())) return;
        
        transaction_status sub = read_transaction_status(j);
        
        if (!sub.valid()) return;
        
        auto pk_hex = encoding::hex::read(string(j["minerId"]));
        if (pk_hex == nullptr) return;
        
        digest256 block_hash{string{"0x"} + string(j["currentHighestBlockHash"])};
        if (!block_hash.valid()) return;
        
        apiVersion = j["apiVersion"];
        timestamp = j["timestamp"];
        
        minerId = secp256k1::pubkey{*pk_hex};
        currentHighestBlockHash = block_hash;
        currentHighestBlockHeight = j["currentHighestBlockHeight"];
        txSecondMempoolExpiry = uint32(j["txSecondMempoolExpiry"]);
        static_cast<transaction_status>(*this) = sub;
        
    }
    
    MAPI::submit_transaction_response::operator json() const {
        if (!valid()) return nullptr;
        
        json j = to_json(static_cast<transaction_status>(*this));
        
        std::stringstream ss;
        ss << currentHighestBlockHash;
        
        j["apiVersion"] = apiVersion;
        j["timestamp"] = timestamp;
        j["minerId"] = encoding::hex::write(minerId);
        j["currentHighestBlockHash"] = ss.str().substr(2);
        j["currentHighestBlockHeight"] = currentHighestBlockHeight;
        j["txSecondMempoolExpiry"] = txSecondMempoolExpiry;
        
        return j;
    }
    
    MAPI::transaction_status_response::transaction_status_response(const json& j) : 
        transaction_status_response{} {
        
        if (!(j.is_object() && 
            j.contains("apiVersion") && j["apiVersion"].is_string() && 
            j.contains("timestamp") && j["timestamp"].is_string() && 
            j.contains("blockHash") && j["blockHash"].is_string() && 
            j.contains("blockHeight") && j["blockHeight"].is_number_unsigned() && 
            j.contains("minerId") && j["minerId"].is_string() && 
            (!j.contains("confirmations") || j["confirmations"].is_number_unsigned()) && 
            j.contains("txSecondMempoolExpiry") && j["txSecondMempoolExpiry"].is_number_unsigned())) return;
        
        transaction_status sub = read_transaction_status(j);
        if (!sub.valid()) return;
        
        auto pk_hex = encoding::hex::read(string(j["minerId"]));
        if (pk_hex == nullptr) return;
        
        digest256 block_hash{string{"0x"} + string(j["blockHash"])};
        if (!block_hash.valid()) return;
        
        minerId = secp256k1::pubkey{*pk_hex};
        blockHash = block_hash;
        
        static_cast<transaction_status>(*this) = sub;
        
        apiVersion = j["apiVersion"];
        timestamp = j["timestamp"];
        blockHeight = j["blockHeight"];
        txSecondMempoolExpiry = uint32(j["txSecondMempoolExpiry"]);
        
        if (j.contains("confirmations")) confirmations = uint64(j["confirmations"]);
        
    }
    
    MAPI::transaction_status_response::operator json() const {
        if (!valid()) return nullptr;
        
        json j = to_json(static_cast<transaction_status>(*this));
        
        j["apiVersion"] = apiVersion; 
        j["timestamp"] = timestamp; 
        j["minerId"] = encoding::hex::write(minerId); 
        j["txSecondMempoolExpiry"] = txSecondMempoolExpiry;
    
        if (confirmations.has_value()) j["confirmations"] = *confirmations; 
    
        return j;
    }
    
    MAPI::submit_transactions_response::submit_transactions_response(const json& j) : 
        submit_transactions_response{} {
        
        if (!(j.is_object() && 
            j.contains("apiVersion") && j["apiVersion"].is_string() && 
            j.contains("timestamp") && j["timestamp"].is_string() && 
            j.contains("minerId") && j["minerId"].is_string() && 
            j.contains("currentHighestBlockHash") && j["currentHighestBlockHash"].is_string() && 
            j.contains("currentHighestBlockHeight") && j["currentHighestBlockHeight"].is_number_unsigned() && 
            j.contains("txSecondMempoolExpiry") && j["txSecondMempoolExpiry"].is_number_unsigned() && 
            j.contains("txs") && j["txs"].is_array() && 
            j.contains("failureCount") && j["failureCount"].is_number_unsigned())) return;
        
        list<transaction_status> sr;
        for (const json& w : j["txs"]) {
            sr = sr << read_transaction_status(w);
            if (!sr.first().valid()) return;
        }
        
        auto pk_hex = encoding::hex::read(string(j["minerId"]));
        if (pk_hex == nullptr) return;
        
        digest256 block_hash{string{"0x"} + string(j["blockHash"])};
        if (!block_hash.valid()) return;
        
        minerId = secp256k1::pubkey{*pk_hex};
        currentHighestBlockHash = block_hash;
        
        apiVersion = j["apiVersion"];
        timestamp = j["timestamp"];
        currentHighestBlockHeight = j["currentHighestBlockHeight"];
        txSecondMempoolExpiry = uint32(j["txSecondMempoolExpiry"]);
        txs = sr;
        failureCount = uint32(j["failureCount"]);
        
    }
    
    MAPI::submit_transactions_response::operator json() const {
        std::stringstream ss;
        ss << currentHighestBlockHash;
        
        return valid() ? json{
            {"apiVersion", apiVersion}, 
            {"timestamp", timestamp}, 
            {"minerId", encoding::hex::write(minerId)}, 
            {"currentHighestBlockHash", ss.str().substr(2)}, 
            {"currentHighestBlockHeight", currentHighestBlockHeight}, 
            {"txSecondMempoolExpiry", txSecondMempoolExpiry}, 
            {"txs", }, 
            {"failureCount", failureCount}} : json{};
    }
    
}
