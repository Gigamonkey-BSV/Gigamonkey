#include <gigamonkey/stratum/stratum.hpp>

namespace Gigamonkey::Stratum {
    /*
    std::string method_to_string(method m) {
        switch (m) {
            case mining_authorize : 
            case mining_configure :
            case mining_subscribe :
            case mining_notify :
            case mining_set_target :
            case mining_submit :
            case client_get_version : 
            case client_reconnect : 
            default: 
                return "";
        }
    }
    
    method method_from_string(std::string st) {
        if (st == )
    }*/
    
    std::string method_to_string(method m) {
        throw data::method::unimplemented{""};
    }
    
    method method_from_string(std::string st) {
        throw data::method::unimplemented{""};
    }
    
    std::string error_message_from_code(error_code) {
        throw data::method::unimplemented{""};
    }
    
    bool notify::valid(const json& j) {
        throw data::method::unimplemented{""};
    }
    
    notify::operator notification() const {
        throw data::method::unimplemented{""};
    }
    
    bool share::valid(const json& j) {
        throw data::method::unimplemented{""};
    }
    
    void to_json(json& j, const request& p) {
        if (!p.valid()) {
            j = {};
            return;
        }
        
        j = {{"id", p.ID}, {"method", method_to_string(p.Method)}, {"params", json::array()}};
        list<json> params = p.Params;
        while(!params.empty()) {
            j["params"].push_back(params.first());
            params = params.rest();
        }
    }
    
    void from_json(const json& j, request& p) {
        if (!(j.contains("id") && j.contains("params") && j.contains("method") && 
                j["id"].is_number_unsigned() && j["method"].is_string() && j["params"].is_array())) {
            p = {};
            return;
        }
        
        list<json> params{};
        for (auto i = j["params"].begin(); i != j["params"].end(); i++) params = params << *i;
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
        list<json> params = p.Params;
        while(!params.empty()) {
            j["params"].push_back(params.first());
            params = params.rest();
        }
    }
    
    void from_json(const json& j, notification& p) {
        if (!(j.contains("id") && j.contains("params") && j.contains("method") && 
                j["id"].is_null() && j["method"].is_string() && j["params"].is_array())) {
            p = {};
            return;
        }
        
        list<json> params{};
        for (auto i = j["params"].begin(); i != j["params"].end(); i++) params = params << *i;
        p = notification{method_from_string(j["method"]), params};
    }
    
    void to_json(json& j, const notify& p) {
        if (!p.valid()) {
            j = {};
            return; 
        }
        
        to_json(j, notification(p));
    }

    void from_json(const json& j, notify& p) {
        p = {};
        if (!notify::valid(j)) return;
    }
    
    void to_json(json& j, const share& p) {
        j = {};
    }
    
    void from_json(const json& j, share& p) {
        p = {};
        if (!share::valid(j)) return;
    }
    
}


