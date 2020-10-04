// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_MINING_SUBMIT
#define GIGAMONKEY_STRATUM_MINING_SUBMIT

#include <gigamonkey/stratum/boolean_response.hpp>
#include <gigamonkey/stratum/mining.hpp>

namespace Gigamonkey::Stratum::mining {
    
    // A Stratum share; also a representation of the 'submit' method.
    struct submit_request : request {
        
        static parameters serialize(const share&);
        static share deserialize(const parameters&);
        
        submit_request(request_id id, const share& x);
        
        bool valid() const;
        
        using request::request;
    };
    
    using submit_response = boolean_response;
    
    inline submit_request::submit_request(request_id id, const share& x) : request{id, mining_submit, serialize(x)} {}
    
    inline bool submit_request::valid() const {
        return deserialize(*this).valid();
    }
    
}

#endif
