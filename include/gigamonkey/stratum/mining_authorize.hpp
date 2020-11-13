// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_MINING_AUTHORIZE
#define GIGAMONKEY_STRATUM_MINING_AUTHORIZE

#include <gigamonkey/stratum/boolean_response.hpp>

namespace Gigamonkey::Stratum::mining {
    
    struct authorize_request;
    
    using authorize_response = boolean_response;
    
    inline bool operator==(const authorize_request& a, const authorize_request& b);
    inline bool operator!=(const authorize_request& a, const authorize_request& b);
    
    void to_json(json& j, const authorize_request& p);
    void from_json(const json& j, authorize_request& p);
    
    std::ostream& operator<<(std::ostream&, const authorize_request&);
    
    struct authorize_request {
        request_id ID;
        string username;
        std::optional<string> password;
        
        authorize_request();
        authorize_request(request_id id, string u);
        authorize_request(request_id id, string u, string p);
        
        bool valid() const;
        
        explicit authorize_request(const request&);
        explicit operator request() const;
    };
    
    inline bool operator==(const authorize_request& a, const authorize_request& b) {
        return a.ID == b.ID && a.username == b.username && a.password == b.password;
    }
    
    inline bool operator!=(const authorize_request& a, const authorize_request& b) {
        return a.ID != b.ID || a.username != b.username || a.password != b.password;
    }
    
    inline std::ostream& operator<<(std::ostream& o, const authorize_request& r) {
        json j;
        to_json(j, r);
        return o << j;
    }
    
    inline authorize_request::authorize_request() : ID{}, username{}, password{} {}
    
    inline authorize_request::authorize_request(request_id id, string u) : ID{id}, username{u}, password{} {}
    
    inline authorize_request::authorize_request(request_id id, string u, string p) : ID{id}, username{u}, password{p} {}
    
    inline bool authorize_request::valid() const {
        return username != "";
    }
    
}

#endif

