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
        
        submit_request(message_id id, const share& x);
        
        static bool valid(const request&);
        bool valid() const;
        
        static share params(const request&);
        share params() const;
        
        using request::request;
    };
    
    using submit_response = boolean_response;
    
    inline submit_request::submit_request(message_id id, const share& x) : request{id, mining_submit, serialize(x)} {}
    
    bool inline submit_request::valid(const request& r) {
        return r.valid() && deserialize(r.params()).valid();
    }
    
    bool inline submit_request::valid() const {
        return valid(*this);
    }
    
    share inline submit_request::params(const request &r) {
        return deserialize(r.params());
    }
    
    share inline submit_request::params() const {
        return params(*this);
    }
    
}

#endif
