// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_BOOLEAN_RESPONSE
#define GIGAMONKEY_STRATUM_BOOLEAN_RESPONSE

#include <gigamonkey/stratum/stratum.hpp>

namespace Gigamonkey::Stratum {
    
    struct boolean_response;
    
    inline bool operator==(const boolean_response& a, const boolean_response& b);
    inline bool operator!=(const boolean_response& a, const boolean_response& b);
    
    void to_json(json& j, const boolean_response& p);
    void from_json(const json& j, boolean_response& p);
    
    std::ostream& operator<<(std::ostream&, const boolean_response&);
    
    // Some responses in Stratum are just booleans, so we have a type for that. 
    struct boolean_response {
        request_id ID;
        bool Result;
        bool Valid;
        boolean_response() : ID{}, Result{}, Valid{false} {}
        boolean_response(request_id id, bool r) : ID{id}, Result{r}, Valid{true} {}
        explicit boolean_response(const response&);
        explicit operator response() const;
    };
    
    inline bool operator==(const boolean_response& a, const boolean_response& b) {
        return a.ID == b.ID && a.Result == b.Result;
    }
    
    inline bool operator!=(const boolean_response& a, const boolean_response& b) {
        return a.ID == b.ID || a.Result != b.Result;
    }
    
    inline std::ostream& operator<<(std::ostream& o, const boolean_response& r) {
        json j;
        to_json(j, r);
        return o << j;
    }

}

#endif
