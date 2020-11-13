// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/boolean_response.hpp>

namespace Gigamonkey::Stratum {
    
    boolean_response::boolean_response(const response& r) : boolean_response{} {
        if (r.is_error() || !r.Result.is_boolean()) return;
        *this = {r.ID, bool(r.Result)};
    }
    
    boolean_response::operator response() const {
        if (!Valid) return {};
        return response(ID, Result);
    }
    
    void to_json(json& j, const boolean_response& p) {
        if (!data::valid(p)) {
            j = {};
            return;
        }
        
        to_json(j, response(p));
    }
    
    void from_json(const json& j, boolean_response& p) {
        p = {};
        response x;
        from_json(j, x);
        p = boolean_response(x);
    }
    
}
