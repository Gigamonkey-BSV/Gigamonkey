// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_MINING_CONFIGURE
#define GIGAMONKEY_STRATUM_MINING_CONFIGURE

#include <gigamonkey/stratum/extensions.hpp>
#include <gigamonkey/stratum/stratum.hpp>

namespace Gigamonkey::Stratum::mining {
    
    struct configure_request;
    struct configure_response;
    
    struct configure_request : request {
        using request::request;
        
        struct parameters {
            list<string> Supported;
            JSON::object_t Parameters;
        
            static bool valid(const Stratum::parameters&);
            
            parameters() {}
            
            parameters(extensions::requests r);
            explicit operator extensions::requests() const;
        };
        
        static Stratum::parameters serialize(const parameters&);
        static parameters deserialize(const Stratum::parameters&);
        
        static parameters params(const request &r) {
            return deserialize(r.params());
        } 
        
        parameters params() const {
            return params(*this);
        }
        
        bool valid() const;
        
        static bool valid(const JSON& j);
    };
    
    struct configure_response : response {
        using response::response;
        
        struct parameters : public JSON::object_t {
            using JSON::object_t::object_t;
            
            parameters() {}
            
            parameters(extensions::results r);
            explicit operator extensions::results() const;
            
            bool valid() const;
        };
        
        static parameters result(const response &r) {
            return r.result();
        }
        
        parameters result() const {
            return result(*this);
        }
        
        bool valid() const;
        
        static bool valid(const JSON& j);
        
        // this checks that the result contains a response to every extension that was queried. 
        static bool valid_result(const parameters& r, const configure_request::parameters& q) {
            JSON j{r};
            for (const string& extension : q.Supported) if (!(j.contains(extension) && j[extension].is_boolean())) return false;
            return true;
        }
    };
    
    bool inline configure_request::valid() const {
        return valid(*this);
    }
    
    bool inline configure_response::valid() const {
        return valid(*this);
    }
    
    bool inline configure_response::valid(const JSON& j) {
        return response::valid(j) && j["result"].is_object();
    }
    
}

#endif
