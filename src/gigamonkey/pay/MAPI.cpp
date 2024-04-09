// Copyright (c) 2021-2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/pay/MAPI.hpp>

namespace Gigamonkey::nChain::MAPI {
    using namespace Bitcoin;
    
    JSON client::call (const net::HTTP::request &q) {
        net::HTTP::response r = (*this) (q);
        
        if (static_cast<unsigned int> (r.Status) < 200 ||
            static_cast<unsigned int> (r.Status) >= 300)
            throw net::HTTP::exception {q, r, "response code"};
        
        if (r.Headers[net::HTTP::header::content_type] != "application/json")
            throw net::HTTP::exception {q, r, string {"content type is not JSON; it is "} +
                r.Headers[net::HTTP::header::content_type]};

        JSON res = JSON::parse (r.Body);
        
        auto envelope = JSON_JSON_envelope {JSON_envelope {res}};
        
        if (!envelope.verify ()) throw net::HTTP::exception {q, r, "MAPI signature verify fail"};
        
        return res;
    }
    
    net::HTTP::request client::transaction_status_HTTP_request (const Bitcoin::txid &request) const {
        if (!request.valid ()) throw std::invalid_argument {"invalid txid"};
        std::stringstream ss;
        ss << "/mapi/tx/" << request;
        return this->REST.GET (ss.str ());
    }
    
    net::HTTP::request client::submit_transaction_HTTP_request (const submit_transaction_request &request) const {
        if (!request.valid ()) throw std::invalid_argument {"invalid transaction submission request"};
        return this->REST (net::HTTP::REST::request (request));
    }
    
    net::HTTP::request client::submit_transactions_HTTP_request (const submit_transactions_request &request) const {
        if (!request.valid ()) throw std::invalid_argument {"invalid transactions submission request"};
        return this->REST (net::HTTP::REST::request (request));
    }
    
    namespace {
    
        satoshi_per_byte spb_from_JSON (const JSON& j) {
            if (!(j.is_object () &&
                j.contains ("satoshis") && j["satoshis"].is_number_unsigned () &&
                j.contains ("bytes") && j["bytes"].is_number_unsigned ())) return {};
            
            return satoshi_per_byte {satoshi {int64 (j["satoshis"])}, uint64 (j["bytes"])};
            
        }
        
        JSON to_JSON (const digest256 &v) {
            return write_backwards_hex (v);
        }
        
        JSON to_JSON (const satoshi_per_byte v) {
            return JSON {{"satoshis", int64 (v.Satoshis)}, {"bytes", v.Bytes}};
        }
    
        string to_JSON (return_result r) {
            return r == success ? "success" : "failure";
        }
        
        JSON to_JSON (list<transaction_submission> subs) {
            JSON j = JSON::array ();
            
            for (const transaction_submission& sub : subs) j.push_back (JSON (sub));
            
            return j;
        }
        
        JSON to_JSON (map<string, fee> fees) {
            JSON j = JSON::array ();
            
            for (const data::entry<string, fee> &f : fees)
                j.push_back (f.valid () ? JSON {
                    {"feeType", f.Key}, 
                    {"miningFee", to_JSON (f.Value.MiningFee)},
                    {"relayFee", to_JSON (f.Value.RelayFee)}} : JSON (nullptr));
            
            return j;
        }
        
        maybe<list<net::IP::address>> read_ip_address_list (const JSON &j) {
            if (!j.is_array ()) return {};
            
            list<net::IP::address> ips;
            
            for (const JSON &i : j) {
                if (!j.contains ("ipAddress")) return {};
                ips = ips << net::IP::address {string (j["ipAddress"])};
            }
            
            return ips;
        } 
        
        JSON ip_addresses_to_JSON (list<net::IP::address> ips) {
            JSON::array_t ii;
            ii.resize (ips.size ());
            
            int i = 0;
            for (const net::IP::address &ip : ips) ii[i++] = string (ip);
            
            return ii;
        }
    
        status read_status (const JSON& j) {
            status x;
            
            if (!(j.is_object () &&
                j.contains ("txid") && j["txid"].is_string () &&
                j.contains ("returnResult") && j["returnResult"].is_string () &&
                j.contains ("returnDescription") && j["returnDescription"].is_string () &&
                (!j.contains ("conflictedWith") || j["conflictedWith"].is_array ()))) return {};
            
            string rr = j["returnResult"];
            if (rr == "success") x.ReturnResult = success;
            else if (rr == "failure") x.ReturnResult = failure;
            else return {};
            
            if (j.contains ("conflictedWith")) {
                list<conflicted_with> cw;
                for (const JSON& w : j["conflictedWith"]) {
                    cw = cw << conflicted_with {w};
                    if (!cw.first ().valid ()) return {};
                }
                x.ConflictedWith = cw;
            }
            
            x.TXID = read_backwards_hex<32> (std::string (j["txid"]));
            if (!x.TXID.valid ()) return {};
            
            x.ResultDescription = j["resultDescription"];
            
            return x;
        }
    
        JSON to_JSON (const submit_transaction_parameters &x) {
            JSON j = JSON::object_t {};
            
            if (x.CallbackURL.has_value ()) j["callbackUrl"] = *x.CallbackURL;
            if (x.CallbackToken.has_value ()) j["callbackToken"] = *x.CallbackToken;
            if (x.MerkleProof.has_value ()) j["merkleProof"] = *x.MerkleProof;
            if (x.DSCheck.has_value ()) j["dsCheck"] = *x.DSCheck;
            if (x.CallbackEncryption.has_value ()) j["callbackEncryption"] = *x.CallbackEncryption;
            
            return j;
        }
        
        JSON to_JSON (const transaction_submission &x) {
            if (!x.valid ()) return {};
            
            JSON j = to_JSON (x.Parameters);
            
            j["rawtx"] = encoding::hex::write (x.Transaction);
            
            return j;
        }
        
        JSON to_JSON (list<conflicted_with> cx) {
            JSON::array_t cf;
            cf.resize (cx.size ());
            
            int i = 0;
            for (const conflicted_with &c : cx) cf[i++] = JSON (c);
            
            return cf;
        }
        
        JSON to_JSON (const status &tst) {
            if (!tst.valid ()) return {};
        
            JSON j {
                {"txid", write_backwards_hex (tst.TXID)},
                {"returnResult", to_JSON (tst.ReturnResult)},
                {"resultDescription", tst.ResultDescription}};
        
            if (tst.ConflictedWith.size () > 0) j["conflictedWith"] = to_JSON (tst.ConflictedWith);
            
            return j;
        }
        
        list<data::entry<UTF8, UTF8>> to_url_params (const submit_transaction_parameters &ts) {
            list<data::entry<UTF8, UTF8>> params;
            
            if (ts.CallbackURL) params = params << data::entry<UTF8, UTF8> {"callbackUrl", *ts.CallbackURL};
            if (ts.CallbackToken) params = params << data::entry<UTF8, UTF8> {"callbackToken", *ts.CallbackToken};
            if (ts.MerkleProof) params = params << data::entry<UTF8, UTF8> {"merkleProof", std::to_string (*ts.MerkleProof)};
            if (ts.MerkleFormat) params = params << data::entry<UTF8, UTF8> {"merkleFormat", *ts.MerkleFormat};
            if (ts.DSCheck) params = params << data::entry<UTF8, UTF8> {"dsCheck", std::to_string (*ts.DSCheck)};
            if (ts.CallbackEncryption) params = params << data::entry<UTF8, UTF8> {"callbackEncryption", *ts.CallbackEncryption};
            
            return params;
        }
        
    }
    
    transaction_submission::operator JSON () const {
        JSON j{{"rawtx", encoding::hex::write (Transaction)}};
        
        if (this->Parameters.CallbackURL) j["callbackUrl"] = *this->Parameters.CallbackURL;
        if (this->Parameters.CallbackToken) j["callbackToken"] = *this->Parameters.CallbackToken;
        if (this->Parameters.MerkleProof) j["merkleProof"] = std::to_string (*this->Parameters.MerkleProof);
        if (this->Parameters.MerkleFormat) j["merkleFormat"] = *this->Parameters.MerkleFormat;
        if (this->Parameters.DSCheck) j["dsCheck"] = std::to_string (*this->Parameters.DSCheck);
        if (this->Parameters.CallbackEncryption) j["callbackEncryption"] = *this->Parameters.CallbackEncryption;
        
        return j;
    }
    
    submit_transaction_request::operator net::HTTP::REST::request () const {
        if (ContentType == application_JSON) {
            return net::HTTP::REST::request {net::HTTP::method::post, "/mapi/tx", {},
                {{net::HTTP::header::content_type, "application/JSON"}},
                JSON (static_cast<const transaction_submission> (*this))};
        }
        
        std::string tx {};
        tx.resize (this->Transaction.size ());
        std::copy (this->Transaction.begin (), this->Transaction.end (), tx.begin ());
        
        return net::HTTP::REST::request {net::HTTP::method::post,
            "/mapi/tx", to_url_params (Parameters),
            {{net::HTTP::header::content_type, "application/octet-stream"}}, tx};
    }
    
    submit_transactions_request::operator net::HTTP::REST::request () const {
        return net::HTTP::REST::request{net::HTTP::method::post, "/mapi/tx",
            to_url_params (DefaultParameters),
            {{net::HTTP::header::content_type, "application/JSON"}},
            to_JSON (Submissions)};
    }
    
    conflicted_with::operator JSON () const {
        return JSON {
            {"txid", to_JSON (TXID)},
            {"size", Size}, 
            {"hex", encoding::hex::write (Transaction)}
        };
    }
    
    conflicted_with::conflicted_with (const JSON &j) : conflicted_with {} {
        
        if (!(j.is_object () &&
            j.contains ("txid") && j["txid"].is_string () &&
            j.contains ("size") && j["size"].is_number_unsigned () &&
            j.contains ("hex") && j["hex"].is_string ())) return;
        
        auto tx = encoding::hex::read (std::string (j["hex"]));
        if (!bool (tx)) return;
        
        TXID = read_backwards_hex<32> (std::string (j["txid"]));
        Size = uint64 (j["size"]);
        Transaction = *tx;
        
    }
    
    get_fee_quote::get_fee_quote (const JSON& j) : get_fee_quote {} {
        
        if (!(j.is_object () &&
            j.contains ("apiVersion") && j["apiVersion"].is_string () &&
            j.contains ("timestamp") && j["timestamp"].is_string () &&
            j.contains ("expiryTime") && j["expiryTime"].is_string () &&
            j.contains ("minerId") && j["minerId"].is_string () &&
            j.contains ("currentHighestBlockHash") && j["currentHighestBlockHash"].is_string () &&
            j.contains ("currentHighestBlockHeight") && j["currentHighestBlockHeight"].is_number_unsigned () &&
            j.contains ("fees") && j["fees"].is_array ())) return;
        
        map<string, fee> f;
        
        for (const JSON &jf : j["fees"]) {
            
            if (!(jf.is_object () &&
                jf.contains ("feeType") && jf["feeType"].is_string () &&
                jf.contains ("miningFee") && jf.contains ("relayFee"))) return;
            
            satoshi_per_byte mf = spb_from_JSON (jf["miningFee"]);
            
            if (!mf.valid ()) return;
            
            satoshi_per_byte rf = spb_from_JSON (jf["relayFee"]);
            
            if (!rf.valid ()) return;
            
            f = f.insert (jf["feeType"], fee {mf, rf});
            
        }
        
        auto pk_hex = encoding::hex::read (string (j["minerId"]));
        if (!bool (pk_hex)) return;
        
        digest256 last_block = read_backwards_hex<32> (std::string (j["currentHighestBlockHash"]));
        if (!last_block.valid ()) return;
        
        APIVersion = j["apiVersion"];
        Timestamp = j["timestamp"];
        ExpiryTime = j["expiryTime"];
        
        MinerID = secp256k1::pubkey {*pk_hex};
        CurrentHighestBlockHash = last_block;
        CurrentHighestBlockHeight = j["currentHighestBlockHeight"];
        Fees = f;
        
    }
    
    get_fee_quote::operator JSON () const {
        std::stringstream ss;
        ss << CurrentHighestBlockHash;
        return valid () ? JSON {
            {"apiVersion", APIVersion},
            {"timestamp", Timestamp}, 
            {"expiryTime", ExpiryTime}, 
            {"minerId", encoding::hex::write (MinerID)},
            {"currentHighestBlockHash", ss.str ().substr (2)},
            {"currentHighestBlockHeight", CurrentHighestBlockHeight}, 
            {"fees", to_JSON (Fees)}} : JSON {};
    }
    
    get_policy_quote::get_policy_quote (const JSON &j) : get_fee_quote {} {
        
        if (!j.contains ("callbacks") || !j.contains ("policies")) return;
        
        get_fee_quote parent {j};
        if (!parent.valid ()) return;
        
        auto ips = read_ip_address_list (j["callbacks"]);
        if (!bool (ips)) return;
        
        static_cast<get_fee_quote_response> (*this) = parent;
        
        Policies = j["policies"];
        Callbacks = *ips;
    }
    
    get_policy_quote::operator JSON () const {
        JSON j = get_fee_quote::operator JSON ();
        
        if (j == nullptr) return nullptr;
        
        j["callbacks"] = ip_addresses_to_JSON (Callbacks);
        j["policies"] = JSON (Policies);
        
        return j;
    }
    
    submit_transaction::submit_transaction (const JSON &j) :
        submit_transaction {} {
        
        if (!(j.is_object () &&
            j.contains ("apiVersion") && j["apiVersion"].is_string () &&
            j.contains ("timestamp") && j["timestamp"].is_string () &&
            j.contains ("minerId") && j["minerId"].is_string () &&
            j.contains ("currentHighestBlockHash") && j["currentHighestBlockHash"].is_string () &&
            j.contains ("currentHighestBlockHeight") && j["currentHighestBlockHeight"].is_number_unsigned () &&
            j.contains ("txSecondMempoolExpiry") && j["txSecondMempoolExpiry"].is_number_unsigned ())) return;
        
        status sub = read_status (j);
        
        if (!sub.valid ()) return;
        
        auto pk_hex = encoding::hex::read (string (j["minerId"]));
        if (! bool (pk_hex)) return;
        
        digest256 block_hash = read_backwards_hex<32> (std::string (j["currentHighestBlockHash"]));
        if (!block_hash.valid ()) return;
        
        APIVersion = j["apiVersion"];
        Timestamp = j["timestamp"];
        
        MinerID = secp256k1::pubkey {*pk_hex};
        CurrentHighestBlockHash = block_hash;
        CurrentHighestBlockHeight = j["currentHighestBlockHeight"];
        TxSecondMempoolExpiry = uint32 (j["txSecondMempoolExpiry"]);
        static_cast<status> (*this) = sub;
        
    }
    
    submit_transaction::operator JSON () const {
        if (!valid ()) return nullptr;
        
        JSON j = to_JSON (static_cast<status> (*this));
        
        j["apiVersion"] = APIVersion;
        j["timestamp"] = Timestamp;
        j["minerId"] = encoding::hex::write (MinerID);
        j["currentHighestBlockHash"] = write_backwards_hex (CurrentHighestBlockHash);
        j["currentHighestBlockHeight"] = CurrentHighestBlockHeight;
        j["txSecondMempoolExpiry"] = TxSecondMempoolExpiry;
        
        return j;
    }
    
    status::operator JSON () const {
        JSON j {
            {"txid", to_JSON (TXID) },
            {"returnResult", to_JSON (ReturnResult) },
            {"resultDescription", ResultDescription }
        };
        
        if (ConflictedWith.size () > 0) j["conflictedWith"] = to_JSON (ConflictedWith);
        
        return j;
    }
    
    transaction_status::transaction_status (const JSON &j) :
        transaction_status {} {
        
        if (!(j.is_object () &&
            j.contains ("apiVersion") && j["apiVersion"].is_string () &&
            j.contains ("timestamp") && j["timestamp"].is_string () &&
            j.contains("blockHash") && j["blockHash"].is_string () &&
            j.contains ("blockHeight") && j["blockHeight"].is_number_unsigned () &&
            j.contains("minerId") && j["minerId"].is_string () &&
            (!j.contains ("confirmations") || j["confirmations"].is_number_unsigned ()) &&
            j.contains ("txSecondMempoolExpiry") && j["txSecondMempoolExpiry"].is_number_unsigned ())) return;
        
        status sub = read_status (j);
        if (!sub.valid ()) return;
        
        auto pk_hex = encoding::hex::read (string (j["minerId"]));
        if (! bool (pk_hex)) return;
        
        digest256 block_hash = read_backwards_hex<32> (std::string (j["blockHash"]));
        if (!block_hash.valid ()) return;
        
        MinerID = secp256k1::pubkey {*pk_hex};
        BlockHash = block_hash;
        
        static_cast<status> (*this) = sub;
        
        APIVersion = j["apiVersion"];
        Timestamp = j["timestamp"];
        BlockHeight = j["blockHeight"];
        TxSecondMempoolExpiry = uint32 (j["txSecondMempoolExpiry"]);
        
        if (j.contains ("confirmations")) Confirmations = uint64 (j["confirmations"]);
        
    }
    
    transaction_status::operator JSON () const {
        if (!valid ()) return nullptr;
        
        JSON j = to_JSON (static_cast<status> (*this));
        
        j["apiVersion"] = APIVersion; 
        j["timestamp"] = Timestamp; 
        j["minerId"] = encoding::hex::write (MinerID);
        j["txSecondMempoolExpiry"] = TxSecondMempoolExpiry;
        
        if (Confirmations.has_value ()) j["confirmations"] = *Confirmations;
    
        return j;
    }
    
    submit_transactions::submit_transactions (const JSON &j) :
        submit_transactions {} {
        
        if (!(j.is_object () &&
            j.contains ("apiVersion") && j["apiVersion"].is_string () &&
            j.contains ("timestamp") && j["timestamp"].is_string () &&
            j.contains ("minerId") && j["minerId"].is_string () &&
            j.contains ("currentHighestBlockHash") && j["currentHighestBlockHash"].is_string () &&
            j.contains ("currentHighestBlockHeight") && j["currentHighestBlockHeight"].is_number_unsigned () &&
            j.contains ("txSecondMempoolExpiry") && j["txSecondMempoolExpiry"].is_number_unsigned () &&
            j.contains ("txs") && j["txs"].is_array () &&
            j.contains ("failureCount") && j["failureCount"].is_number_unsigned ())) return;
        
        list<status> sr;
        for (const JSON& w : j["txs"]) {
            sr = sr << read_status (w);
            if (!sr.first ().valid ()) return;
        }
        
        auto pk_hex = encoding::hex::read (string (j["minerId"]));
        if (!bool (pk_hex)) return;
        
        digest256 block_hash = read_backwards_hex<32> (std::string (j["blockHash"]));
        if (!block_hash.valid ()) return;
        
        MinerID = secp256k1::pubkey {*pk_hex};
        CurrentHighestBlockHash = block_hash;
        
        APIVersion = j["apiVersion"];
        Timestamp = j["timestamp"];
        CurrentHighestBlockHeight = j["currentHighestBlockHeight"];
        TxSecondMempoolExpiry = uint32 (j["txSecondMempoolExpiry"]);
        Transactions = sr;
        FailureCount = uint32 (j["failureCount"]);
        
    }
    
    submit_transactions::operator JSON () const {

        JSON::array_t txs;
        txs.resize (Transactions.size ());
        
        int i = 0;
        for (const status &status : Transactions) txs[i++] = JSON (status);
        
        return valid () ? JSON{
            {"apiVersion", APIVersion }, 
            {"timestamp", Timestamp }, 
            {"minerId", encoding::hex::write (MinerID) },
            {"currentHighestBlockHash", write_backwards_hex (CurrentHighestBlockHash) },
            {"currentHighestBlockHeight", CurrentHighestBlockHeight }, 
            {"txSecondMempoolExpiry", TxSecondMempoolExpiry }, 
            {"txs", txs }, 
            {"failureCount", FailureCount}} : JSON {};
    }
    
}
