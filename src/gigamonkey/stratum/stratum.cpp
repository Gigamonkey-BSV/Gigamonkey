// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/stratum.hpp>

namespace Gigamonkey::Stratum {
    
    std::string method_to_string(method m) {
        switch (m) {
            case mining_notify :
                return "mining.notify";
            case mining_submit :
                return "mining.submit";
            case mining_authorize :
                return "mining.authorize";
            case mining_subscribe :
                return "mining.subscribe";
            case mining_set_difficulty :
                return "mining.set_difficulty";
            default: 
                return "";
        }
    }
    
    method method_from_string(std::string st) {
        if (st == "mining.notify") return mining_notify;
        if (st == "mining.submit") return mining_submit;
        if (st == "mining.authorize") return mining_authorize;
        if (st == "mining.subscribe") return mining_subscribe;
        if (st == "mining.set_difficulty") return mining_set_difficulty;
        return unset;
    }
    
    request_id request::id(const json& j) {
        if (!j.contains("id")) return 0;
        auto q = j["id"];
        if (q.is_number_unsigned()) return request_id(q);
        return 0;
    }
    
    Stratum::method request::method(const json& j) {
        if (!j.contains("method")) return unset;
        auto q = j["method"];
        if (q.is_string()) return method_from_string(string(q));
        return unset;
    }
    
    parameters request::params(const json& j) {
        if(!j.contains("params")) return {};
        auto q = j["params"];
        if(q.is_array()) return q;
        return {};
    }
    
    Stratum::method notification::method(const json& j) {
        if (!j.contains("method")) return unset;
        auto q = j["method"];
        if (q.is_string()) return method_from_string(string(q));
        return unset;
    }
    
    parameters notification::params(const json& j) {
        if(!j.contains("params")) return {};
        auto q = j["params"];
        if(q.is_array()) return q;
        return {};
    }
        
    bool response::valid(const json& j) {
        if (!(j.contains("id") && j.contains("result") && j.contains("error"))) return false;
        auto id = j["id"];
        auto err = j["error"];
        return id.is_number_unsigned() && (err.is_null() || Stratum::error::valid(err));
    }
    
    request_id response::id(const json& j) {
        if (!j.contains("id")) return 0;
        auto q = j["id"];
        if (q.is_number_unsigned()) return request_id(q);
        return 0;
    }
    
    json response::result(const json& j) {
        if (!j.contains("result")) return nullptr;
        return j["result"];
    }
    
    std::optional<Stratum::error> response::error(const json& j) {
        if (!j.contains("error")) return {};
        return {error(j["error"])};
    }
    
}


