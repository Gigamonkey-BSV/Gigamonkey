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
    
    void to_json(json& j, const request& p) {
        if (!p.valid()) {
            j = {};
            return;
        }
        
        j = {{"id", p.ID}, {"method", method_to_string(p.Method)}, {"params", p.Params}};
    }
    
    void from_json(const json& j, request& p) {
        if (!(j.contains("id") && j.contains("params") && j.contains("method") && 
                j["id"].is_number_unsigned() && j["method"].is_string() && j["params"].is_array())) {
            p = {};
            return;
        }
        
        p = request{j["id"], method_from_string(j["method"]), j["params"]};
    }
    
    void to_json(json& j, const response& p) {
        if (p.Error == error{none}) j = {{"id", p.ID}, {"result", p.Result}, {"error", nullptr}};
        else {
            json errj;
            to_json(errj, p.Error);
            j = {{"id", p.ID}, {"result", p.Result}, {"error", errj}};
        }
    }
    
    void from_json(const json& j, response& p) {
        if (!(j.contains("id") && j.contains("result") && j.contains("error")) && 
                j["id"].is_null() && (j["error"].is_null() || (j["error"].is_array() && j["error"].size() == 2))) {
            p = {};
            return;
        }
        
        if (j["error"].is_null()) p = response{j["id"], j["result"]};
        else {
            error e;
            from_json(j["error"], e);
            p = response{j["id"], j["result"], e};
        }
    }
    
    void to_json(json& j, const notification& p) {
        if (!p.valid()) {
            j = {};
            return;
        }
        
        j = {{"id", nullptr}, {"method", method_to_string(p.Method)}, {"params", p.Params}};
    }
    
    void from_json(const json& j, notification& p) {
        if (!(j.contains("id") && j.contains("params") && j.contains("method") && 
                j["id"].is_null() && j["method"].is_string() && j["params"].is_array())) {
            p = {};
            return;
        }
        
        p = notification{method_from_string(j["method"]), j["params"]};
    }
    
}


