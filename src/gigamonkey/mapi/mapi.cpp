// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/mapi/mapi.hpp>

namespace Gigamonkey::BitcoinAssociation {
    using namespace Bitcoin;
    
    JSON MAPI::call(const networking::HTTP::request &q) {
        networking::HTTP::response r = (*this)(q);
        
        if (static_cast<unsigned int>(r.Status) < 200 || 
            static_cast<unsigned int>(r.Status) >= 300) 
            throw networking::HTTP::exception{q, r, "response code"};
        
        if (r.Headers[networking::HTTP::header::content_type] != "application/json") 
            throw networking::HTTP::exception{q, r, string{"content type is not JSON; it is "} +
                r.Headers[networking::HTTP::header::content_type]};
        
        auto envelope = JSON_JSON_envelope{JSON_envelope{JSON::parse(r.Body)}};
        
        if (!envelope.verify()) throw networking::HTTP::exception{q, r, "MAPI signature verify fail"};
        
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
    
        satoshi_per_byte spb_from_JSON(const JSON& j) {
            if (!(j.is_object() && 
                j.contains("satoshis") && j["satoshis"].is_number_unsigned() && 
                j.contains("bytes") && j["bytes"].is_number_unsigned())) return{};
            
            return satoshi_per_byte{satoshi{int64(j["satoshis"])}, uint64(j["bytes"])};
            
        }
        
        JSON to_JSON(const digest256 &v) {
            std::stringstream ss;
            ss << v;
            return ss.str().substr(9, 64);
        }
        
        JSON to_JSON(const satoshi_per_byte v) {
            return JSON{{"satoshis", int64(v.Satoshis)}, {"bytes", v.Bytes}};
        }
    
        string to_JSON(MAPI::return_result r) {
            return r == MAPI::success ? "success" : "failure";
        }
        
        JSON to_JSON(list<MAPI::transaction_submission> subs) {
            JSON j = JSON::array();
            
            for (const MAPI::transaction_submission& sub : subs) j.push_back(JSON(sub));
            
            return j;
        }
        
        JSON to_JSON(map<string, MAPI::fee> fees) {
            JSON j = JSON::array();
            
            for (const data::entry<string, MAPI::fee>& f : fees) 
                j.push_back(f.valid() ? JSON{
                    {"feeType", f.Key}, 
                    {"miningFee", to_JSON(f.Value.MiningFee)}, 
                    {"relayFee", to_JSON(f.Value.RelayFee)}} : JSON(nullptr));
            
            return j;
        }
        
        optional<list<networking::IP::address>> read_ip_address_list(const JSON &j) {
            if (!j.is_array()) return {};
            
            list<networking::IP::address> ips;
            
            for (const JSON &i : j) {
                if (!j.contains("ipAddress")) return {};
                ips = ips << networking::IP::address{string(j["ipAddress"])};
            }
            
            return ips;
        } 
        
        JSON ip_addresses_to_JSON(list<networking::IP::address> ips) {
            JSON::array_t ii;
            ii.resize(ips.size());
            
            int i = 0;
            for (const networking::IP::address &ip : ips) ii[i++] = string(ip);
            
            return ii;
        }
    
        MAPI::transaction_status read_transaction_status(const JSON& j) {
            MAPI::transaction_status x;
            
            if (!(j.is_object() && 
                j.contains("txid") && j["txid"].is_string() && 
                j.contains("returnResult") && j["returnResult"].is_string() && 
                j.contains("returnDescription") && j["returnDescription"].is_string() && 
                (!j.contains("conflictedWith") || j["conflictedWith"].is_array()))) return {};
            
            string rr = j["returnResult"];
            if (rr == "success") x.ReturnResult = MAPI::success;
            else if (rr == "failure") x.ReturnResult = MAPI::failure;
            else return {};
            
            if (j.contains("conflictedWith")) {
                list<MAPI::conflicted_with> cw;
                for (const JSON& w : j["conflictedWith"]) {
                    cw = cw << MAPI::conflicted_with{w};
                    if (!cw.first().valid()) return {};
                }
                x.ConflictedWith = cw;
            }
            
            x.TXID = digest256{string{"0x"} + string(j["txid"])};
            if (!x.TXID.valid()) return {};
            
            x.ResultDescription = j["resultDescription"];
            
            return x;
        }
    
        JSON to_JSON(const MAPI::submit_transaction_parameters &x) {
            JSON j = JSON::object_t{};
            
            if (x.CallbackURL.has_value()) j["callbackUrl"] = *x.CallbackURL;
            if (x.CallbackToken.has_value()) j["callbackToken"] = *x.CallbackToken;
            if (x.MerkleProof.has_value()) j["merkleProof"] = *x.MerkleProof;
            if (x.DSCheck.has_value()) j["dsCheck"] = *x.DSCheck;
            if (x.CallbackEncryption.has_value()) j["callbackEncryption"] = *x.CallbackEncryption;
            
            return j;
        }
        
        JSON to_JSON(const MAPI::transaction_submission &x) {
            if (!x.valid()) return {};
            
            JSON j = to_JSON(x.Parameters);
            
            j["rawtx"] = encoding::hex::write(x.Transaction);
            
            return j;
        }
        
        JSON to_JSON(list<MAPI::conflicted_with> cx) {
            JSON::array_t cf;
            cf.resize(cx.size());
            
            int i = 0;
            for (const MAPI::conflicted_with &c : cx) cf[i++] = JSON(c);
            
            return cf;
        }
        
        JSON to_JSON(const MAPI::transaction_status &tst) {
            if (!tst.valid()) return {};
        
            JSON j{ 
                {"txid", string(tst.TXID.Value)}, 
                {"returnResult", to_JSON(tst.ReturnResult)}, 
                {"resultDescription", tst.ResultDescription}};
        
            if (tst.ConflictedWith.size() > 0) j["conflictedWith"] = to_JSON(tst.ConflictedWith);
            
            return j;
        }
        
        list<data::entry<string, string>> to_url_params(const MAPI::submit_transaction_parameters &ts) {
            list<data::entry<string, string>> params;
            
            if (ts.CallbackURL) params = params << data::entry<string, string>{"callbackUrl", *ts.CallbackURL};
            if (ts.CallbackToken) params = params << data::entry<string, string>{"callbackToken", *ts.CallbackToken};
            if (ts.MerkleProof) params = params << data::entry<string, string>{"merkleProof", std::to_string(*ts.MerkleProof)};
            if (ts.MerkleFormat) params = params << data::entry<string, string>{"merkleFormat", *ts.MerkleFormat};
            if (ts.DSCheck) params = params << data::entry<string, string>{"dsCheck", std::to_string(*ts.DSCheck)};
            if (ts.CallbackEncryption) params = params << data::entry<string, string>{"callbackEncryption", *ts.CallbackEncryption};
            
            return params;
        }
        
    }
    
    MAPI::transaction_submission::operator JSON() const {
        JSON j{{"rawtx", encoding::hex::write(Transaction)}};
        
        if (this->Parameters.CallbackURL) j["callbackUrl"] = *this->Parameters.CallbackURL;
        if (this->Parameters.CallbackToken) j["callbackToken"] = *this->Parameters.CallbackToken;
        if (this->Parameters.MerkleProof) j["merkleProof"] = std::to_string(*this->Parameters.MerkleProof);
        if (this->Parameters.MerkleFormat) j["merkleFormat"] = *this->Parameters.MerkleFormat;
        if (this->Parameters.DSCheck) j["dsCheck"] = std::to_string(*this->Parameters.DSCheck);
        if (this->Parameters.CallbackEncryption) j["callbackEncryption"] = *this->Parameters.CallbackEncryption;
        
        return j;
    }
    
    MAPI::submit_transaction_request::operator networking::REST::request() const {
        if (ContentType == application_JSON) {
            return networking::REST::request{networking::HTTP::method::post, "/mapi/tx", {}, 
                {{networking::HTTP::header::content_type, "application/JSON"}}, 
                JSON(static_cast<const transaction_submission>(*this))};
        }
        
        std::string tx{};
        tx.resize(this->Transaction.size());
        std::copy(this->Transaction.begin(), this->Transaction.end(), tx.begin());
        
        return networking::REST::request{networking::HTTP::method::post, 
            "/mapi/tx", to_url_params(Parameters), 
            {{networking::HTTP::header::content_type, "application/octet-stream"}}, tx};
    }
    
    MAPI::submit_transactions_request::operator networking::REST::request() const {
        return networking::REST::request{networking::HTTP::method::post, "/mapi/tx", 
            to_url_params(DefaultParameters), 
            {{networking::HTTP::header::content_type, "application/JSON"}}, 
            to_JSON(Submissions)};
    }
    
    MAPI::conflicted_with::operator JSON() const {
        return JSON {
            {"txid", to_JSON(TXID)}, 
            {"size", Size}, 
            {"hex", encoding::hex::write(Transaction)}
        };
    }
    
    MAPI::conflicted_with::conflicted_with(const JSON& j) : conflicted_with{} {
        
        if (!(j.is_object() && 
            j.contains("txid") && j["txid"].is_string() && 
            j.contains("size") && j["size"].is_number_unsigned() && 
            j.contains("hex") && j["hex"].is_string())) return;
        
        auto tx = encoding::hex::read(string(j["hex"]));
        if (tx == nullptr) return;
        
        TXID = digest256{string{"0x"} + string(j["txid"])};
        Size = uint64(j["size"]);
        Transaction = *tx;
        
    }
    
    MAPI::get_fee_quote_response::get_fee_quote_response(const JSON& j) : get_fee_quote_response{} {
        
        if (!(j.is_object() && 
            j.contains("apiVersion") && j["apiVersion"].is_string() && 
            j.contains("timestamp") && j["timestamp"].is_string() && 
            j.contains("expiryTime") && j["expiryTime"].is_string() && 
            j.contains("minerId") && j["minerId"].is_string() && 
            j.contains("currentHighestBlockHash") && j["currentHighestBlockHash"].is_string() && 
            j.contains("currentHighestBlockHeight") && j["currentHighestBlockHeight"].is_number_unsigned() && 
            j.contains("fees") && j["fees"].is_array())) return;
        
        map<string, fee> f;
        
        for (const JSON& jf : j["fees"]) {
            
            if (!(jf.is_object() && 
                jf.contains("feeType") && jf["feeType"].is_string() && 
                jf.contains("miningFee") && jf.contains("relayFee"))) return;
            
            satoshi_per_byte mf = spb_from_JSON(jf["miningFee"]);
            
            if (!mf.valid()) return;
            
            satoshi_per_byte rf = spb_from_JSON(jf["relayFee"]);
            
            if (!rf.valid()) return;
            
            f = f.insert(jf["feeType"], MAPI::fee{mf, rf});
            
        }
        
        auto pk_hex = encoding::hex::read(string(j["minerId"]));
        if (pk_hex == nullptr) return;
        
        digest256 last_block{string{"0x"} + string(j["currentHighestBlockHash"])};
        if (!last_block.valid()) return;
        
        APIVersion = j["apiVersion"];
        Timestamp = j["timestamp"];
        ExpiryTime = j["expiryTime"];
        
        MinerID = secp256k1::pubkey{*pk_hex};
        CurrentHighestBlockHash = last_block;
        CurrentHighestBlockHeight = j["currentHighestBlockHeight"];
        Fees = f;
        
    }
    
    MAPI::get_fee_quote_response::operator JSON() const {
        std::stringstream ss;
        ss << CurrentHighestBlockHash;
        return valid() ? JSON{
            {"apiVersion", APIVersion},
            {"timestamp", Timestamp}, 
            {"expiryTime", ExpiryTime}, 
            {"minerId", encoding::hex::write(MinerID)}, 
            {"currentHighestBlockHash", ss.str().substr(2)}, 
            {"currentHighestBlockHeight", CurrentHighestBlockHeight}, 
            {"fees", to_JSON(Fees)}} : JSON{};
    }
    
    MAPI::get_policy_quote_response::get_policy_quote_response(const JSON &j) : get_fee_quote_response{} {
        
        if (!j.contains("callbacks") || !j.contains("policies")) return;
        
        get_fee_quote_response parent{j};
        if (!parent.valid()) return;
        
        auto ips = read_ip_address_list(j["callbacks"]);
        if (!bool(ips)) return;
        
        static_cast<get_fee_quote_response>(*this) = parent;
        
        Policies = j["policies"];
        Callbacks = *ips;
    }
    
    MAPI::get_policy_quote_response::operator JSON() const {
        JSON j = get_fee_quote_response::operator JSON();
        
        if (j == nullptr) return nullptr;
        
        j["callbacks"] = ip_addresses_to_JSON(Callbacks);
        j["policies"] = JSON(Policies);
        
        return j;
    }
    
    MAPI::submit_transaction_response::submit_transaction_response(const JSON& j) : 
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
        
        APIVersion = j["apiVersion"];
        Timestamp = j["timestamp"];
        
        MinerID = secp256k1::pubkey{*pk_hex};
        CurrentHighestBlockHash = block_hash;
        CurrentHighestBlockHeight = j["currentHighestBlockHeight"];
        TxSecondMempoolExpiry = uint32(j["txSecondMempoolExpiry"]);
        static_cast<transaction_status>(*this) = sub;
        
    }
    
    MAPI::submit_transaction_response::operator JSON() const {
        if (!valid()) return nullptr;
        
        JSON j = to_JSON(static_cast<transaction_status>(*this));
        
        std::stringstream ss;
        ss << CurrentHighestBlockHash;
        
        j["apiVersion"] = APIVersion;
        j["timestamp"] = Timestamp;
        j["minerId"] = encoding::hex::write(MinerID);
        j["currentHighestBlockHash"] = ss.str().substr(2);
        j["currentHighestBlockHeight"] = CurrentHighestBlockHeight;
        j["txSecondMempoolExpiry"] = TxSecondMempoolExpiry;
        
        return j;
    }
    
    MAPI::transaction_status::operator JSON() const {
        JSON j {
            {"txid", to_JSON(TXID) }, 
            {"returnResult", to_JSON(ReturnResult) }, 
            {"resultDescription", ResultDescription }
        };
        
        if (ConflictedWith.size() > 0) j["conflictedWith"] = to_JSON(ConflictedWith);
        
        return j;
    }
    
    MAPI::transaction_status_response::transaction_status_response(const JSON& j) : 
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
        
        MinerID = secp256k1::pubkey{*pk_hex};
        BlockHash = block_hash;
        
        static_cast<transaction_status>(*this) = sub;
        
        APIVersion = j["apiVersion"];
        Timestamp = j["timestamp"];
        BlockHeight = j["blockHeight"];
        TxSecondMempoolExpiry = uint32(j["txSecondMempoolExpiry"]);
        
        if (j.contains("confirmations")) Confirmations = uint64(j["confirmations"]);
        
    }
    
    MAPI::transaction_status_response::operator JSON() const {
        if (!valid()) return nullptr;
        
        JSON j = to_JSON(static_cast<transaction_status>(*this));
        
        j["apiVersion"] = APIVersion; 
        j["timestamp"] = Timestamp; 
        j["minerId"] = encoding::hex::write(MinerID); 
        j["txSecondMempoolExpiry"] = TxSecondMempoolExpiry;
        
        if (Confirmations.has_value()) j["confirmations"] = *Confirmations; 
    
        return j;
    }
    
    MAPI::submit_transactions_response::submit_transactions_response(const JSON& j) : 
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
        for (const JSON& w : j["txs"]) {
            sr = sr << read_transaction_status(w);
            if (!sr.first().valid()) return;
        }
        
        auto pk_hex = encoding::hex::read(string(j["minerId"]));
        if (pk_hex == nullptr) return;
        
        digest256 block_hash{string{"0x"} + string(j["blockHash"])};
        if (!block_hash.valid()) return;
        
        MinerID = secp256k1::pubkey{*pk_hex};
        CurrentHighestBlockHash = block_hash;
        
        APIVersion = j["apiVersion"];
        Timestamp = j["timestamp"];
        CurrentHighestBlockHeight = j["currentHighestBlockHeight"];
        TxSecondMempoolExpiry = uint32(j["txSecondMempoolExpiry"]);
        Transactions = sr;
        FailureCount = uint32(j["failureCount"]);
        
    }
    
    MAPI::submit_transactions_response::operator JSON() const {
        std::stringstream ss;
        ss << CurrentHighestBlockHash;
        
        JSON::array_t txs;
        txs.resize(Transactions.size());
        
        int i = 0;
        for (const transaction_status &status : Transactions) txs[i++] = JSON(status);
        
        return valid() ? JSON{
            {"apiVersion", APIVersion }, 
            {"timestamp", Timestamp }, 
            {"minerId", encoding::hex::write(MinerID) }, 
            {"currentHighestBlockHash", ss.str().substr(2) }, 
            {"currentHighestBlockHeight", CurrentHighestBlockHeight }, 
            {"txSecondMempoolExpiry", TxSecondMempoolExpiry }, 
            {"txs", txs }, 
            {"failureCount", FailureCount}} : JSON{};
    }
    
}
