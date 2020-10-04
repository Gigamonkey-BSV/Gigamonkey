// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_BOOLEAN_RESPONSE
#define GIGAMONKEY_STRATUM_BOOLEAN_RESPONSE

#include <gigamonkey/stratum/stratum.hpp>

namespace Gigamonkey::Stratum {
    
    // Some responses in Stratum are just booleans, so we have a type for that. 
    struct boolean_response : response {
        bool valid(const json& j) {
            return response::valid(j) && response::result().is_boolean();
        }
        
        using response::response;
        boolean_response(request_id id, bool r) : response{id, json(r)} {}
    };

}

#endif
