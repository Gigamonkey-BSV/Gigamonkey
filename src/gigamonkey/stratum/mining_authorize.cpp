// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/mining_authorize.hpp>

namespace Gigamonkey::Stratum::mining {
    
    authorize_request::authorize_request(const request& r) : authorize_request{} {
        if (!r.valid() || r.Method != mining_authorize || r.Params.size() == 0 || r.Params.size() > 2 || ! r.Params[0].is_string()) return;
        if (r.Params.size() == 1) *this = {r.ID, string(r.Params[0])};
        else if (r.Params[1].is_string()) *this = {r.ID, string(r.Params[0]), string(r.Params[1])};
    }
    
    authorize_request::operator request() const {
        params p;
        p.push_back(username);
        if (password) p.push_back(*password);
        return request(ID, mining_authorize, p);
    }
    
    void to_json(json& j, const authorize_request& p) {
        if (!data::valid(p)) {
            j = {};
            return;
        }
        
        to_json(j, request(p));
    }
    
    void from_json(const json& j, authorize_request& p) {
        p = {};
        request x;
        from_json(j, x);
        p = authorize_request(x);
    }
}
