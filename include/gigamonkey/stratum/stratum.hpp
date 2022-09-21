// Copyright (c) 2020-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_STRATUM
#define GIGAMONKEY_STRATUM_STRATUM

#include <gigamonkey/stratum/error.hpp>
#include <gigamonkey/stratum/method.hpp>
#include <gigamonkey/stratum/message_id.hpp>

// Description of Stratum: 
// https://docs.google.com/document/d/1ocEC8OdFYrvglyXbag1yi8WoskaZoYuR5HGhwf0hWAY

namespace Gigamonkey::Stratum {
    
    using parameters = json::array_t;
    
    template <typename X> using optional = std::optional<X>;
    
    struct notification : json {
        
        static bool valid(const json&);
        
        static Stratum::method method(const json&);
        static parameters params(const json&);
        
        bool valid() const;
        
        Stratum::method method() const;
        parameters params() const;
        
        notification();
        notification(Stratum::method m, const parameters& p);
        explicit notification(const json& j) : json(j) {}
    };
    
    struct request : json {
        
        static bool valid(const json&);
        
        static message_id id(const json&);
        static Stratum::method method(const json&);
        static parameters params(const json&);
        
        bool valid() const;
        
        message_id id() const;
        Stratum::method method() const;
        parameters params() const;
        
        request();
        request(message_id id, Stratum::method m, const parameters& p);
        explicit request(const json& j) : json(j) {}
    };
    
    struct response : json {
        
        static bool valid(const json&);
        
        static message_id id(const json&);
        static json result(const json&);
        static optional<Stratum::error> error(const json&);
        
        bool valid() const {
            return valid(*this);
        }
        
        message_id id() const;
        json result() const;
        optional<Stratum::error> error() const;
        
        response();
        response(message_id id, const json& p);
        response(message_id id, const json& p, const Stratum::error& e);
        explicit response(const json& j) : json(j) {}
        
        bool is_error() const {
            return bool(error());
        }
        
    };
    
    inline request::request() : json{} {}
    
    inline request::request(message_id id, Stratum::method m, const parameters& p) : 
        json{{"id", id}, {"method", method_to_string(m)}, {"params", p}} {}
    
    bool inline request::valid(const json& j) {
        return request::method(j) != unset && j.contains("params") && j["params"].is_array() && j.contains("id") && message_id::valid(j["id"]);
    }
    
    bool inline request::valid() const {
        return valid(*this);
    }
        
    message_id inline request::id() const {
        return id(*this);
    }
    
    Stratum::method inline request::method() const {
        return method(*this);
    }
    
    parameters inline request::params() const {
        return params(*this);
    }
    
    inline notification::notification() : json{} {}
    
    inline notification::notification(Stratum::method m, const parameters& p) : 
        json{{"id", nullptr}, {"method"}, {"params", p}} {}
    
    bool inline notification::valid(const json& j) {
        return notification::method(j) != unset && j.contains("params") && j["params"].is_array() && j.contains("id") && j["id"].is_null();
    }
    
    bool inline notification::valid() const {
        return valid(*this);
    }
    
    Stratum::method inline notification::method() const {
        return method(*this);
    }
    
    parameters inline notification::params() const {
        return params(*this);
    }
    
    inline response::response() : json{} {}
    
    inline response::response(message_id id, const json& p) : json{{"id", id}, {"result", p}, {"error", nullptr}} {}
    
    inline response::response(message_id id, const json& p, const Stratum::error& e) : json{{"id", id}, {"result", p}, {"error", json(e)}} {}
    
    message_id inline response::id() const {
        return id(*this);
    }
    
    json inline response::result() const {
        return result(*this);
    }
    
    optional<Stratum::error> inline response::error() const {
        return error(*this);
    }
    
}

#endif 

