// Copyright (c) 2020-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/stratum.hpp>

namespace Gigamonkey::Stratum {
    
    message_id request::id(const json& j) {
        if (!j.contains("id")) return message_id{};
        auto q = j["id"];
        if (message_id::valid(q)) return message_id(q);
        return message_id{};
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
        auto err = j["error"];
        return message_id::valid(j["id"]) && (err.is_null() || Stratum::error::valid(err));
    }
    
    message_id response::id(const json& j) {
        if (!j.contains("id")) return message_id{};
        auto q = j["id"];
        if (message_id::valid(q)) return message_id(q);
        return message_id{};
    }
    
    json response::result(const json& j) {
        if (!j.contains("result")) return nullptr;
        return j["result"];
    }
    
    std::optional<Stratum::error> response::error(const json& j) {
        if (!valid(j)) return {};
        auto err = j["error"];
        if (err.is_null()) return {};
        return {Stratum::error(j["error"])};
    }
    
}
