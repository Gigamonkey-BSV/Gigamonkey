// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/mining_subscribe.hpp>

namespace Gigamonkey::Stratum::mining {
    
    subscribe_request::subscribe_request(const request& r) : subscribe_request{} {
        if (!r.valid() || r.Method != mining_subscribe || r.Params.size() == 0 || r.Params.size() > 2 || !r.Params[0].is_string()) return;
        if (r.Params.size() == 1) *this = subscribe_request{r.ID, string(r.Params[0])};
        else if (r.Params[1].is_string()) {
            session_id id;
            from_json(r.Params[1], id);
            if (data::valid(id)) *this = subscribe_request{r.ID, string(r.Params[0]), id};
        }
    }
    
    subscribe_request::operator request() const {
        if (!valid()) return {};
        params p;
        p.push_back(UserAgent);
        if (ExtraNonce1) {
            json j;
            to_json(j, *ExtraNonce1);
            p.push_back(j);
        }
        return request{ID, mining_subscribe, p};
    }
    
    subscribe_response::subscribe_response(const response& r) : subscribe_response{} {
        if (r.is_error() || 
            !r.Result.is_array() || 
            r.Result.size() != 3 || 
            !r.Result[0].is_array() || 
            !r.Result[1].is_string() || 
            !r.Result[2].is_number_unsigned()) return;
        
        ExtraNonce2Size = uint32(r.Result[2]);
        from_json(r.Result[1], ExtraNonce1);
        
        for (const json& j : r.Result[0]) {
            subscription x; 
            from_json(j, x);
            Subscriptions = Subscriptions << x;
        }
        
        Valid = true;
    }
    
    subscribe_response::operator response() const {
        if (!Valid) return {};
        
        params subs;
        for (const subscription& x : Subscriptions) {
            json j;
            to_json(j, x);
            subs.push_back(j);
        }
        
        params p;
        p.push_back(subs);
        
        json id;
        to_json(id, ExtraNonce1);
        p.push_back(id);
        p.push_back(ExtraNonce2Size);
        
        return response(ID, p);
    }
    
    void to_json(json& j, const subscription& p) {
        if (!data::valid(p)) {
            j = {};
            return;
        }
        json id;
        to_json(id, p.ID);
        j = {method_to_string(p.Method), id};
    }
    
    void from_json(const json& j, subscription& p) {
        p = {};
        if (j.is_array() && j.size() == 2 && j[0].is_string() && j[1].is_string()) {
            from_json(j[1], p.ID);
            p.Method = method_from_string(string(j[0]));
        }
    }
    
    void to_json(json& j, const subscribe_request& p) {
        if (!data::valid(p)) {
            j = {};
            return;
        }
        
        to_json(j, request(p));
    }
    
    void from_json(const json& j, subscribe_request& p) {
        p = {};
        request x;
        from_json(j, x);
        p = subscribe_request(x);
    }
    
    void to_json(json& j, const subscribe_response& p) {
        if (!data::valid(p)) {
            j = {};
            return;
        }
        
        to_json(j, response(p));
    }
    
    void from_json(const json& j, subscribe_response& p) {
        p = {};
        response x;
        from_json(j, x);
        p = subscribe_response(x);
    }
    
}
