// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_BOOLEAN_RESPONSE
#define GIGAMONKEY_STRATUM_BOOLEAN_RESPONSE

#include <gigamonkey/stratum/stratum.hpp>

namespace Gigamonkey::Stratum {
    
    // Some responses in Stratum are just booleans, so we have a type for that. 
    struct boolean_response : response {
        
        static bool valid (const response& j) {
            return j.valid () && (j.result ().is_boolean () || bool (j.error ()));
        }
        
        bool valid () const {
            return valid (*this);
        }
        
        bool result () const {
            return valid (*this) && !bool (response::error ()) && bool (response::result ());
        }
        
        using response::response;
        boolean_response (message_id id, bool r) : response {id, JSON (r)} {}
        boolean_response (message_id id, const Stratum::error &e) : response {id, false, e} {}
    };

}

#endif
