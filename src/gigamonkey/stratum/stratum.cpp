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
    
    notify::operator notification() const {
        throw data::method::unimplemented{""};
    }
    
    void to_json(json& j, const notify& p) {
        if (!p.valid()) {
            j = {};
            return; 
        }
        
        to_json(j, notification(p));
    }
    
    notify::notify(const notification& n) {/*
        if (!n.valid()) return;
        
        if (n.Method != mining_notify) return;
        
        if (n.Params.size() < 9) return;
        
        if (!(n.Params[0].is_number_unsigned())) return;
        
        if (!(n.Params[1].is_string())) return;
        encoding::hex::string previous{n.Params[1].get<string>()};
        if (!previous.valid()) return;
        bytes previous_bytes = bytes_view(previous);
        
        // the two parts of the coinbase. 
        if (!(n.Params[2].is_string())) return; 
        encoding::hex::string coinbase_1{n.Params[2].get<string>()};
        if (!coinbase_1.valid()) return;
        
        if (!(n.Params[3].is_string())) return;
        encoding::hex::string coinbase_2{n.Params[3].get<string>()};
        if (!coinbase_2.valid()) return;
        
        // merkle path
        if (!(n.Params[4].is_array())) return;
        cross<std::string> merkle(n.Params[4].size(), "");
        int i = 0;
        for (auto it = n.Params[4].begin(); it != n.Params[4].end(); it ++) {
            if (!it->is_string()) return;
            merkle[i] = it->get<string>();
            if (merkle[i].size() != 64) return;
        }
        
        if (!(n.Params[5].is_string())) return;
        
        
        if (!(n.Params[6].is_string())) return;
        
        
        if (!(n.Params[7].is_string())) return;  
        
        
        if (!(n.Params[8].is_boolean())) return; 
        
        ID = n.Params[0].get<uint32>();
        std::copy(previous_bytes.begin(), previous_bytes.end(), Digest.begin()); */
        
        throw data::method::unimplemented{""};
    }

    void from_json(const json& j, notify& p) {
        p = {};
        notification x;
        from_json(j, x);
        p = notify(x);
    }
    
    void to_json(json& j, const share& p) {
        j = {};
    }
    
    share::share(const request& n) {
        if (!n.valid()) return;
        
        if (n.Method != mining_submit) return;
        
        throw data::method::unimplemented{""};
    }
    
    void from_json(const json& j, share& p) {
        p = {};
        request x;
        from_json(j, x);
        p = share(x);
    }
    
}


