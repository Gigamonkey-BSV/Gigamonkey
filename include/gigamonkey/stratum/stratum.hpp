// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_STRATUM
#define GIGAMONKEY_STRATUM_STRATUM

#include <gigamonkey/stratum/error.hpp>

namespace Gigamonkey::Stratum {
    using request_id = uint64;
    
    // List of stratum methods (incomplete)
    enum method {
        unset,
        mining_authorize, 
        mining_configure, 
        mining_subscribe, 
        mining_notify, 
        mining_set_difficulty, 
        mining_submit, 
        client_get_version,
        client_reconnect
    };
    
    std::string method_to_string(method m);
    
    method method_from_string(std::string st);
    
    using parameters = json::array_t;
    
    struct request : json {
        
        static bool valid(const json&);
        
        static request_id id(const json&);
        static Stratum::method method(const json&);
        static parameters params(const json&);
        
        bool valid() const;
        
        request_id id() const;
        Stratum::method method() const;
        parameters params() const;
        
        request();
        request(request_id id, Stratum::method m, const parameters& p);
        explicit request(const json& j) : json{j} {}
    };
    
    struct notification : json {
        
        static bool valid(const json&);
        
        static Stratum::method method(const json&);
        static parameters params(const json&);
        
        bool valid() const;
        
        Stratum::method method() const;
        parameters params() const;
        
        notification();
        notification(Stratum::method m, const parameters& p);
        explicit notification(const json& j) : json{j} {}
    };
    
    struct response : json {
        
        static bool valid(const json&);
        
        static request_id id(const json&);
        static json result(const json&);
        static std::optional<Stratum::error> error(const json&);
        
        bool valid() const;
        
        request_id id() const;
        json result() const;
        std::optional<Stratum::error> error() const;
        
        response();
        response(request_id id, const json& p);
        response(request_id id, const json& p, const Stratum::error& e);
        explicit response(const json& j) : json{j} {}
        
        bool is_error() const {
            return bool(error());
        }
        
    };
    
    inline request::request() : json{} {}
    
    inline request::request(request_id id, Stratum::method m, const parameters& p) : 
        json{{"id", id}, {"method", method_to_string(m)}, {"params", p}} {}
    
    inline bool request::valid(const json& j) {
        return request::method(j) != unset && j.contains("params") && j["params"].is_array() && j.contains("id") && j["id"].is_number_unsigned();
    }
    
    inline bool request::valid() const {
        return valid(*this);
    }
        
    inline request_id request::id() const {
        return id(*this);
    }
    
    inline Stratum::method request::method() const {
        return method(*this);
    }
    
    inline parameters request::params() const {
        return params(*this);
    }
    
    inline notification::notification() : json{} {}
    
    inline notification::notification(Stratum::method m, const parameters& p) : 
        json{{"id", nullptr}, {"method"}, {"params", p}} {}
    
    inline bool notification::valid(const json& j) {
        return notification::method(j) != unset && j.contains("params") && j["params"].is_array() && j.contains("id") && j["id"].is_null();
    }
    
    inline bool notification::valid() const {
        return valid(*this);
    }
    
    inline Stratum::method notification::method() const {
        return method(*this);
    }
    
    inline parameters notification::params() const {
        return params(*this);
    }
    
    inline response::response() : json{} {}
    
    inline response::response(request_id id, const json& p) : json{{"id", id}, {"result", p}, {"error", nullptr}} {}
    
    inline response::response(request_id id, const json& p, const Stratum::error& e) : json{{"id", id}, {"result", p}, {"error", json(e)}} {}
    
    request_id inline response::id() const {
        return id(*this);
    }
    
    json inline response::result() const {
        return result(*this);
    }
    
    std::optional<Stratum::error> inline response::error() const {
        return error(*this);
    }
    
}

#endif 

