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
        };
        
        static Stratum::parameters serialize(const parameters&);
        static parameters deserialize(const Stratum::parameters&);
        
        parameters params() const {
            return deserialize(request::params());
        }
        
        template <typename... P>
        static parameters encode(P...);
        
        template <typename... P>
        configure_request(request_id id, P... conf) : request{id, mining_configure, encode(conf...)} {}
        
        bool valid() const;
        
        static bool valid(const json& j);
    };
    
    struct configure_response : response {
        using response::response;
        
        struct parameters : json::object_t {
            using json::object_t::object_t;
            
            template <extensions::extension x> 
            parameters add(extensions::configuration_result<x>) const;
            
            template <extensions::extension x>
            optional<extensions::configuration_result<x>> get() const;
        };
        
        template <typename... P>
        static parameters encode(P...);
        
        parameters result() const {
            return response::result();
        }
        
        template <typename... P>
        configure_response(request_id id, P... conf) : response{id, encode(conf...)} {}
        
        bool valid() const;
        
        static bool valid(const json& j);
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
    
}

namespace Gigamonkey::Stratum::extensions {
    
    mining::configure_request::parameters add(mining::configure_request::parameters& p, const configuration_request<version_rolling>&);
    
    mining::configure_request::parameters add(mining::configure_request::parameters& p, const configuration_request<minimum_difficulty>&);
    
    mining::configure_request::parameters add(mining::configure_request::parameters& p, const configuration_request<subscribe_extranonce>&);
    
    mining::configure_request::parameters add(mining::configure_request::parameters& p, const configuration_request<info>&);
    
    mining::configure_response::parameters add(mining::configure_response::parameters& p, const configuration_result<version_rolling>&);
    
    mining::configure_response::parameters add(mining::configure_response::parameters& p, const configuration_result<minimum_difficulty>&);
    
    mining::configure_response::parameters add(mining::configure_response::parameters& p, const configuration_result<subscribe_extranonce>&);
    
    mining::configure_response::parameters add(mining::configure_response::parameters& p, const configuration_result<info>&);
    
    template <extension e> struct get;
        
    template <> struct get<version_rolling> {
        optional<configuration_request<version_rolling>> request(const mining::configure_request::parameters&);
        
        optional<configuration_result<version_rolling>> result(const mining::configure_response::parameters&);
    }; 
    
    template <> struct get<minimum_difficulty> {
        optional<configuration_request<minimum_difficulty>> request(const mining::configure_request::parameters&);
        
        optional<configuration_result<minimum_difficulty>> result(const mining::configure_response::parameters&);
    }; 
    
    template <> struct get<subscribe_extranonce> {
        optional<configuration_request<subscribe_extranonce>> request(const mining::configure_request::parameters&);
        
        optional<configuration_result<subscribe_extranonce>> result(const mining::configure_response::parameters&);
    }; 
    
    template <> struct get<info> {
        optional<configuration_request<info>> request(const mining::configure_request::parameters&);
        
        optional<configuration_result<info>> result(const mining::configure_response::parameters&);
    };
    
    mining::configure_request::parameters inline add_request(mining::configure_request::parameters& p) {
        return p;
    }
    
    template <typename X>
    mining::configure_request::parameters inline add_request(mining::configure_request::parameters& p, const X&) {
        return mining::configure_request::parameters{};
    }
    
    template <typename X, typename... P>
    mining::configure_request::parameters add_request(mining::configure_request::parameters& p, const X& x, P... conf) {
        return add_request(add(p, x), conf...);
    }
    
    mining::configure_response::parameters inline add_result(mining::configure_response::parameters& p) {
        return p;
    }
    
    template <typename X>
    mining::configure_response::parameters inline add_result(mining::configure_response::parameters& p, const X&) {
        return {};
    }
    
    template <typename X, typename... P>
    mining::configure_response::parameters add_result(mining::configure_response::parameters& p, const X& x, P... conf) {
        return add_response(add(p, x), conf...);
    }
    
}

namespace Gigamonkey::Stratum::mining {
    
    template <typename... P>
    configure_request::parameters configure_request::encode(P... conf) {
        return extensions::add_request(parameters{}, conf...);
    }
    
    template <extensions::extension e>
    optional<extensions::configuration_request<e>> configure_request::parameters::get() const {
        return extensions::get<e>{}.request(*this);
    }
    
    template <extensions::extension x> 
    configure_request::parameters inline configure_request::parameters::add(extensions::configuration_request<x> r) const {
        configure_request::parameters p = *this;
        return extensions::add(p, r);
    }
    
    template <typename... P>
    configure_response::parameters configure_response::encode(P... conf) {
        return extensions::add_result(configure_response::parameters{}, conf...);
    }
    
    template <extensions::extension e>
    optional<extensions::configuration_result<e>> configure_response::parameters::get() const {
        return extensions::get<e>{}.result(*this);
    }
    
    template <extensions::extension x> 
    configure_response::parameters inline configure_response::parameters::add(extensions::configuration_result<x> r) const {
        configure_response::parameters p = *this;
        return extensions::add(p, r);
    }
    
}

#endif
