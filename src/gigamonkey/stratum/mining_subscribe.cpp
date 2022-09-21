// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/mining_subscribe.hpp>

namespace Gigamonkey::Stratum::mining {
    
    subscription::subscription(const json& j) : subscription{} {
        if (!(j.is_array() && j.size() == 2 && j[0].is_string())) return;
        ID = j[1];
        Method = method_from_string(j[0]);
    }
    
    subscription::operator json() const {
        parameters p;
        p.resize(2);
        p[0] = method_to_string(Method);
        p[1] = ID;
        return p;
    }
    
    parameters subscribe_request::serialize(const parameters& p) {
        Stratum::parameters x;
        if (p.ExtraNonce1) {
            x.resize(2);
            x[1] = encoding::hex::fixed<4>(*p.ExtraNonce1);
        }
        else x.resize(1);
        x[0] = p.UserAgent;
        return x;
    }
    
    subscribe_request::parameters subscribe_request::deserialize(const Stratum::parameters& p) {
        if (p.size() == 0 || p.size() > 2 || !p[0].is_string()) return {};
        
        parameters x;
        x.UserAgent = p[0];
        if (p.size() == 2) {
            auto n1 = session_id::deserialize(p[1]);
            if (!n1) return {};
            x.ExtraNonce1 = *n1;
        }
        return x;
    }
    
    Stratum::parameters subscribe_response::serialize(const parameters& p) {
        if (!p.valid()) return {};
        
        Stratum::parameters s;
        s.resize(p.Subscriptions.size());
        auto n = s.begin();
        for (const subscription& x : p.Subscriptions) {
            *n = json(x);
            n++;
        }
        
        Stratum::parameters x(3);
        x[0] = s;
        x[1] = session_id::serialize(p.ExtraNonce.ExtraNonce1);
        x[2] = p.ExtraNonce.ExtraNonce2Size;
        
        return x;
    }
    
    subscribe_response::parameters subscribe_response::deserialize(const Stratum::parameters& p) {
        parameters x;
        if (p.size() != 3 || !p[0].is_array() || !p[2].is_number_unsigned()) return {};
        auto id = session_id::deserialize(p[1]);
        if (!id) return {};
        x.ExtraNonce.ExtraNonce1 = *id; 
        
        for (const json& j : p[0]) {
            subscription z{j};
            if (!z.valid()) return {};
            x.Subscriptions = x.Subscriptions << z;
        }
        
        x.ExtraNonce.ExtraNonce2Size = uint32(p[2]);
        
        return x;
        
    }
    
}
