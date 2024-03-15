// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_CLIENT_GET_VERSION
#define GIGAMONKEY_STRATUM_CLIENT_GET_VERSION

#include <gigamonkey/stratum/stratum.hpp>
#include <gigamonkey/stratum/difficulty.hpp>

namespace Gigamonkey::Stratum::client {
    struct get_version_request : request {
        
        using request::request;
        get_version_request (message_id id) : request {id, client_get_version, {}} {} 
        
        static bool valid (const request &r) {
            return r.valid () && r.method () == client_get_version && r.params ().size () == 0;
        }
        
        bool valid () const {
            return valid (*this);
        }
    };
    
    struct get_version_response : response {
        
        using response::response;
        get_version_response (message_id id, string version) : response {id, JSON::string_t (version)} {} 
        
        static bool valid (const response &r) {
            return r.valid () && r.result ().is_string ();
        }
        
        bool valid () const {
            return valid (*this);
        }
    };
}

#endif


