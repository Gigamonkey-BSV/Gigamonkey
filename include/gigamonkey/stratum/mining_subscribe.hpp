// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_MINING_SUBSCRIBE
#define GIGAMONKEY_STRATUM_MINING_SUBSCRIBE

#include <gigamonkey/stratum/stratum.hpp>
#include <gigamonkey/stratum/mining.hpp>

namespace Gigamonkey::Stratum::mining {
    
    struct subscription {
        method Method;
        string ID;
        
        subscription() : Method{unset}, ID{} {}
        subscription(method m, string id) : Method{m}, ID{id} {}
        explicit subscription(const JSON&);
        explicit operator JSON() const;
        
        bool valid() const {
            return Method != unset;
        }
    };
    
    bool operator==(const subscription& a, const subscription& b);
    bool operator!=(const subscription& a, const subscription& b);
    
    std::ostream& operator<<(std::ostream&, const subscription&);
    
    struct subscribe_request : request {
        struct parameters {
            string UserAgent;
            std::optional<session_id> ExtraNonce1;
            
            parameters(const string& u) : UserAgent{u}, ExtraNonce1{} {}
            parameters(const string& u, session_id i) : UserAgent{u}, ExtraNonce1{i} {}
            
            bool valid() const;
            bool operator==(const parameters& p) const;
            bool operator!=(const parameters& p) const;
            
            operator Stratum::parameters() const;
            
        private:
            parameters() : UserAgent{}, ExtraNonce1{} {}
            
            friend struct subscribe_request;
        };
        
        static Stratum::parameters serialize(const parameters&);
        static parameters deserialize(const Stratum::parameters&);
        
        static bool valid(const JSON& j);
        static string user_agent(const JSON& j);
        static std::optional<session_id> extra_nonce_1(const JSON& j);
        
        bool valid() const;
        string user_agent() const;
        std::optional<session_id> extra_nonce_1() const;
        
        static parameters params(const request &r) {
            return deserialize(r.params());
        }
        
        parameters params() const {
            return params(*this);
        }
        
        using request::request;
        subscribe_request(message_id id, const string& u) : request{id, mining_subscribe, {u}} {}
        subscribe_request(message_id id, const string& u, session_id i) : request{id, mining_subscribe, serialize(parameters{u, i})} {}
        
    };
    
    struct subscribe_response : response {
        struct parameters {
            list<subscription> Subscriptions;
            extranonce ExtraNonce;
            
            bool valid() const;
            
            parameters(list<subscription> s, extranonce n1);
            
            bool operator==(const parameters& p) const;
            bool operator!=(const parameters& p) const;
            
            operator JSON() const;
            
        private:
            parameters() : Subscriptions{}, ExtraNonce{} {}
            friend struct subscribe_response;
        };
        
        static Stratum::parameters serialize(const parameters&);
        static parameters deserialize(const Stratum::parameters&);
        
        static parameters result(const response &r) {
            return deserialize(r.result());
        }
        
        parameters result() const {
            return result(*this);
        }
        
        static bool valid(const JSON& j);
        static list<subscription> subscriptions(const JSON& j);
        static session_id extra_nonce_1(const JSON& j);
        static uint32 extra_nonce_2_size(const JSON& j);
        
        bool valid() const;
        list<subscription> subscriptions() const;
        session_id extra_nonce_1() const;
        uint32 extra_nonce_2_size() const;
        
        using response::response;
        subscribe_response(message_id id, list<subscription> sub, extranonce en) : 
            subscribe_response{id, serialize(parameters{sub, en})} {}
        subscribe_response(message_id id, const parameters &p) : 
            response{id, serialize(p)} {}
        
    };
    
    bool inline operator==(const subscription& a, const subscription& b) {
        return a.Method && b.Method && a.ID == b.ID;
    }
    
    bool inline operator!=(const subscription& a, const subscription& b) {
        return !(a == b);
    }
    
    bool inline subscribe_request::parameters::valid() const {
        return UserAgent != "" && (!bool(ExtraNonce1) || data::valid(*ExtraNonce1));
    }
    
    bool inline subscribe_request::parameters::operator==(const parameters& p) const {
        return UserAgent == p.UserAgent && ExtraNonce1 == p.ExtraNonce1;
    }
    
    bool inline subscribe_request::parameters::operator!=(const parameters& p) const {
        return UserAgent != p.UserAgent || ExtraNonce1 != p.ExtraNonce1;
    }
    
    bool inline subscribe_response::parameters::valid() const {
        return ExtraNonce.valid();
    }
    
    inline std::ostream& operator<<(std::ostream& o, const subscription& s) {
        return o << JSON(s);
    }
    
    inline subscribe_response::parameters::parameters(list<subscription> s, extranonce n1) : 
        Subscriptions{s}, ExtraNonce{n1} {}
    
    bool inline subscribe_response::parameters::operator==(const parameters& p) const {
        return Subscriptions == p.Subscriptions && ExtraNonce == p.ExtraNonce;
    }
    
    bool inline subscribe_response::parameters::operator!=(const parameters& p) const {
        return !(*this == p);
    }
    
    bool inline subscribe_request::valid() const {
        return valid(*this);
    }
    
    string inline subscribe_request::user_agent() const {
        return user_agent(*this);
    }
    
    std::optional<session_id> inline subscribe_request::extra_nonce_1() const {
        return extra_nonce_1(*this);
    }
    
    bool inline subscribe_request::valid(const JSON& j) {
        return request::valid(j) && deserialize(j["params"]).valid();
    }
    
    string inline subscribe_request::user_agent(const JSON& j) {
        return deserialize(j["params"]).UserAgent;
    }
    
    std::optional<session_id> inline subscribe_request::extra_nonce_1(const JSON& j) {
        return deserialize(j["params"]).ExtraNonce1;
    }
        
    bool inline subscribe_response::valid(const JSON& j) {
        return response::valid(j) && deserialize(j["result"]).valid();
    }
    
    list<subscription> inline subscribe_response::subscriptions(const JSON& j) {
        return deserialize(j["result"]).Subscriptions;
    }
    
    session_id inline subscribe_response::extra_nonce_1(const JSON& j) {
        return deserialize(j["result"]).ExtraNonce.ExtraNonce1;
    }
    
    uint32 inline subscribe_response::extra_nonce_2_size(const JSON& j) {
        return deserialize(j["result"]).ExtraNonce.ExtraNonce2Size;
    }
    
    bool inline subscribe_response::valid() const {
        return valid(*this);
    }
    
    list<subscription> inline subscribe_response::subscriptions() const {
        return subscriptions(*this);
    }
    
    session_id inline subscribe_response::extra_nonce_1() const {
        return extra_nonce_1(*this);
    }
    
    uint32 inline subscribe_response::extra_nonce_2_size() const {
        return extra_nonce_2_size(*this);
    }
    
    inline subscribe_request::parameters::operator Stratum::parameters() const {
        return serialize(*this);
    }
    
    inline subscribe_response::parameters::operator JSON() const {
        return serialize(*this);
    }
    
}

#endif
