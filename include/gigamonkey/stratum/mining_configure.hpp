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
            json::object_t Parameters;
        
            static bool valid(const Stratum::parameters&);
            
            template <extensions::extension x> 
            parameters add(extensions::configuration_request<x>) const;
            
            template <extensions::extension x>
            optional<extensions::configuration_request<x>> get() const;
            
            parameters() {}
            
            template <extensions::extension x, typename... P>
            parameters(extensions::configuration_request<x> r, P... p) : parameters{p...} {
                *this = this->add(r);
            }
        };
        
        static Stratum::parameters serialize(const parameters&);
        static parameters deserialize(const Stratum::parameters&);
        
        parameters params() const {
            return deserialize(request::params());
        }
        
        template <typename... P>
        configure_request(request_id id, P... conf) : request{id, mining_configure, parameters{conf...}} {}
        
        bool valid() const;
        
        static bool valid(const json& j);
    };
    
    struct configure_response : response {
        using response::response;
        
        struct parameters : public json::object_t {
            using json::object_t::object_t;
            
            template <extensions::extension x> 
            parameters add(extensions::configuration_result<x>) const;
            
            template <extensions::extension x>
            optional<extensions::configuration_result<x>> get() const;
            
            parameters() {}
            
            template <extensions::extension x, typename... P>
            parameters(extensions::configuration_result<x> r, P... p) : parameters{p...} {
                *this = this->add(r);
            }
        };
        
        parameters result() const {
            return response::result();
        }
        
        template <typename... P>
        configure_response(request_id id, P... conf) : response{id, parameters(conf...)} {}
        
        bool valid() const;
        
        static bool valid(const json& j);
        
        // this checks that the result contains a response to every extension that was queried. 
        static bool valid_result(const parameters& r, const configure_request::parameters& q) {
            json j{r};
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
    
    bool inline configure_response::valid(const json& j) {
        return response::valid(j) && j["result"].is_object();
    }
    
    template <> configure_request::parameters 
    configure_request::parameters::add(extensions::configuration_request<extensions::version_rolling>) const;
    
    template <> optional<extensions::configuration_request<extensions::version_rolling>> 
    configure_request::parameters::get() const;
    
    template <> configure_request::parameters 
    configure_request::parameters::add(extensions::configuration_request<extensions::minimum_difficulty>) const;
    
    template <> optional<extensions::configuration_request<extensions::minimum_difficulty>> 
    configure_request::parameters::get() const;
    
    template <> configure_request::parameters 
    configure_request::parameters::add(extensions::configuration_request<extensions::subscribe_extranonce>) const;
    
    template <> optional<extensions::configuration_request<extensions::subscribe_extranonce>> 
    configure_request::parameters::get() const;
    
    template <> configure_request::parameters 
    configure_request::parameters::add(extensions::configuration_request<extensions::info>) const;
    
    template <> optional<extensions::configuration_request<extensions::info>> 
    configure_request::parameters::get() const;
    
    template <> configure_response::parameters 
    configure_response::parameters::add(extensions::configuration_result<extensions::version_rolling>) const;
    
    template <> optional<extensions::configuration_result<extensions::version_rolling>> 
    configure_response::parameters::get() const;
    
    template <> configure_response::parameters 
    configure_response::parameters::add(extensions::configuration_result<extensions::minimum_difficulty>) const;
    
    template <> optional<extensions::configuration_result<extensions::minimum_difficulty>> 
    configure_response::parameters::get() const;
    
    template <> configure_response::parameters 
    configure_response::parameters::add(extensions::configuration_result<extensions::subscribe_extranonce>) const;
    
    template <> optional<extensions::configuration_result<extensions::subscribe_extranonce>> 
    configure_response::parameters::get() const;
    
    template <> configure_response::parameters 
    configure_response::parameters::add(extensions::configuration_result<extensions::info>) const;
    
    template <> optional<extensions::configuration_result<extensions::info>> 
    configure_response::parameters::get() const;
    
}

#endif
