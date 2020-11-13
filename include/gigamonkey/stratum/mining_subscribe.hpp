// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_MINING_SUBSCRIBE
#define GIGAMONKEY_STRATUM_MINING_SUBSCRIBE

#include <gigamonkey/stratum/stratum.hpp>
#include <gigamonkey/stratum/session_id.hpp>

namespace Gigamonkey::Stratum::mining {
    
    struct subscription;
    struct subscribe_request;
    struct subscribe_response;
    
    bool operator==(const subscription& a, const subscription& b);
    bool operator!=(const subscription& a, const subscription& b);
    
    bool operator==(const subscribe_request& a, const subscribe_request& b);
    bool operator!=(const subscribe_request& a, const subscribe_request& b);
    
    bool operator==(const subscribe_response& a, const subscribe_response& b);
    bool operator!=(const subscribe_response& a, const subscribe_response& b);
    
    void to_json(json& j, const subscription& p); 
    void from_json(const json& j, subscription& p); 
    
    void to_json(json& j, const subscribe_request& p); 
    void from_json(const json& j, subscribe_request& p); 
    
    void to_json(json& j, const subscribe_response& p); 
    void from_json(const json& j, subscribe_response& p); 
    
    std::ostream& operator<<(std::ostream&, const subscription&);
    std::ostream& operator<<(std::ostream&, const subscribe_request&);
    std::ostream& operator<<(std::ostream&, const subscribe_response&);
    
    struct subscription {
        method Method;
        session_id ID;
        
        subscription() : Method{}, ID{} {}
        subscription(method m, session_id id) : Method{m}, ID{id} {}
        
        bool valid() const {
            return Method != unset && data::valid(ID);
        }
    };
    
    struct subscribe_request {
        request_id ID; 
        string UserAgent;
        std::optional<session_id> ExtraNonce1;
        
        bool valid() const {
            return UserAgent != "" && (! bool(ExtraNonce1) || data::valid(*ExtraNonce1));
        }
        
        subscribe_request() : ID{}, UserAgent{}, ExtraNonce1{} {}
        explicit subscribe_request(const request&);
        subscribe_request(request_id id, const string& u) : ID{id}, UserAgent{u}, ExtraNonce1{} {}
        subscribe_request(request_id id, const string& u, session_id i) : ID{id}, UserAgent{u}, ExtraNonce1{i} {}
        
        explicit operator request() const;
    };
    
    struct subscribe_response {
        request_id ID; 
        list<subscription> Subscriptions;
        session_id ExtraNonce1;
        uint32 ExtraNonce2Size;
        bool Valid;
        
        subscribe_response() : ID{}, Subscriptions{}, ExtraNonce1{}, ExtraNonce2Size{}, Valid{false} {}
        subscribe_response(request_id id, list<subscription> sub, session_id i, uint32 x) : 
            ID{id}, Subscriptions{sub}, ExtraNonce1{i}, ExtraNonce2Size{x}, Valid{true} {}
        
        explicit subscribe_response(const response&);
        explicit operator response() const;
    };
    
    inline bool operator==(const subscription& a, const subscription& b) {
        return a.Method == b.Method && a.ID == b.ID;
    }
    
    inline bool operator!=(const subscription& a, const subscription& b) {
        return a.Method != b.Method || a.ID != b.ID;
    }
    
    inline bool operator==(const subscribe_request& a, const subscribe_request& b) {
        return a.UserAgent == b.UserAgent && a.ExtraNonce1 == b.ExtraNonce1;
    }
    
    inline bool operator!=(const subscribe_request& a, const subscribe_request& b) {
        return a.UserAgent != b.UserAgent || a.ExtraNonce1 != b.ExtraNonce1;
    }
    
    inline bool operator==(const subscribe_response& a, const subscribe_response& b) {
        return a.Subscriptions == b.Subscriptions && a.ExtraNonce1 == b.ExtraNonce1 && a.ExtraNonce2Size == b.ExtraNonce2Size && a.Valid == b.Valid;
    }
    
    inline bool operator!=(const subscribe_response& a, const subscribe_response& b) {
        return a.Subscriptions != b.Subscriptions || a.ExtraNonce1 != b.ExtraNonce1 || a.ExtraNonce2Size != b.ExtraNonce2Size || a.Valid != b.Valid;
    }
    
    inline std::ostream& operator<<(std::ostream& o, const subscription& r) {
        json j;
        to_json(j, r);
        return o << j;
    }
    
    inline std::ostream& operator<<(std::ostream& o, const subscribe_request& r) {
        json j;
        to_json(j, r);
        return o << j;
    }
    
    inline std::ostream& operator<<(std::ostream& o, const subscribe_response& r) {
        json j;
        to_json(j, r);
        return o << j;
    }
}

#endif
