#include <gigamonkey/stratum/stratum.hpp>

namespace Gigamonkey::Stratum {
    
    std::string method_to_string(method m) {
        switch (m) {
            case mining_notify :
                return "mining.notify";
            case mining_submit :
                return "mining.submit";
            default: 
                return "";
        }
    }
    
    method method_from_string(std::string st) {
        if (st == "mining.notify") return mining_notify;
        if (st == "mining.submit") return mining_submit;
        return unset;
    }
    
    std::string error_message_from_code(error_code) {
        return "";
    }
    
    void to_json(json& j, const request& p) {
        if (!p.valid()) {
            j = {};
            return;
        }
        
        j = {{"id", p.ID}, {"method", method_to_string(p.Method)}, {"params", json::array()}};
        for (auto i = p.Params.begin(); i != p.Params.end(); i++) {
            j["params"].push_back(*i);
        }
    }
    
    void from_json(const json& j, request& p) {
        if (!(j.contains("id") && j.contains("params") && j.contains("method") && 
                j["id"].is_number_unsigned() && j["method"].is_string() && j["params"].is_array())) {
            p = {};
            return;
        }
        
        std::vector<json> params{};
        for (auto i = j["params"].begin(); i != j["params"].end(); i++) params.push_back(*i);
        p = request{j["id"], method_from_string(j["method"]), params};
    }
    
    void to_json(json& j, const response& p) {
        if (p.ErrorCode == none) j = {{"id", p.ID}, {"result", p.Result}, {"error", nullptr}};
        else j = {{"id", p.ID}, {"result", p.Result}, {"error", {uint32(p.ErrorCode),
            error_message_from_code(p.ErrorCode)}}};
    }
    
    void from_json(const json& j, response& p) {
        if (!(j.contains("id") && j.contains("result") && j.contains("error")) && 
                j["id"].is_null() && (j["error"].is_null() || (j["error"].is_array() && j["error"].size() == 2))) {
            p = {};
            return;
        }
        
        if (j["error"].is_null()) p = response{j["id"], j["result"]};
        else p = response{j["id"], j["result"], j["error"][0], j["error"][1]};
    }
    
    void to_json(json& j, const notification& p) {
        if (!p.valid()) {
            j = {};
            return;
        }
        
        j = {{"id", nullptr}, {"method", method_to_string(p.Method)}, {"params", json::array()}};
        
        for (auto i = p.Params.begin(); i != p.Params.end(); i++) {
            j["params"].push_back(*i);
        }
    }
    
    void from_json(const json& j, notification& p) {
        if (!(j.contains("id") && j.contains("params") && j.contains("method") && 
                j["id"].is_null() && j["method"].is_string() && j["params"].is_array())) {
            p = {};
            return;
        }
        
        std::vector<json> params{};
        for (auto i = j["params"].begin(); i != j["params"].end(); i++) params.push_back(*i);
        p = notification{method_from_string(j["method"]), params};
    }
    
}


