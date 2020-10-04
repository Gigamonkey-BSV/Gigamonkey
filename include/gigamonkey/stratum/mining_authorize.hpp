// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_MINING_AUTHORIZE
#define GIGAMONKEY_STRATUM_MINING_AUTHORIZE

#include <gigamonkey/stratum/boolean_response.hpp>

namespace Gigamonkey::Stratum::mining {
    
    struct authorize_request;
    using authorize_response = boolean_response;
    
    struct authorize_request : request {
        struct parameters {
            string Username;
            std::optional<string> Password;
        
            bool valid() const;
            bool operator==(const parameters& x) const;
            bool operator!=(const parameters& x) const;
            
            parameters();
            explicit parameters(string u);
            parameters(string u, string p);
        };
        
        static Stratum::parameters serialize(const parameters&);
        static parameters deserialize(const Stratum::parameters&);
        
        static bool valid(const json&);
        
        static string username(const json&);
        static std::optional<string> password(const json&);
        
        using request::request;
        authorize_request(request_id id, string u);
        authorize_request(request_id id, string u, string p);
        
        string username() const;
        
        std::optional<string> password() const;
        
        bool valid() const;
    };
    
    bool inline authorize_request::parameters::valid() const {
        return Username != "";
    }
    
    bool inline authorize_request::parameters::operator==(const parameters& x) const {
        return Username == x.Username && Password == x.Password;
    }
    
    bool inline authorize_request::parameters::operator!=(const parameters& x) const {
        return Username != x.Username || Password != x.Password;
    }
    
    inline authorize_request::parameters::parameters() : Username{}, Password() {}
    inline authorize_request::parameters::parameters(string u) : Username{u}, Password{} {}
    inline authorize_request::parameters::parameters(string u, string p) : Username{u}, Password{p} {}
    
    inline authorize_request::authorize_request(request_id id, string u) : 
        request{id, mining_authorize, {u}} {}
    
    inline authorize_request::authorize_request(request_id id, string u, string p) : 
        request{id, mining_authorize, {u, p}} {}
        
    string inline authorize_request::username() const {
        return username(*this);
    }
    
    std::optional<string> inline authorize_request::password() const {
        return password(*this);
    }
    
    bool inline authorize_request::valid() const {
        return valid(*this);
    }
    
}

#endif

