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
    
    struct request;
    struct response;
    struct notification;
    
    inline bool operator==(const request& a, const request& b);
    inline bool operator!=(const request& a, const request& b);
    
    inline bool operator==(const notification& a, const notification& b);
    inline bool operator!=(const notification& a, const notification& b);
    
    inline bool operator==(const response& a, const response& b);
    inline bool operator!=(const response& a, const response& b);
    
    void to_json(json& j, const request& p); 
    void from_json(const json& j, request& p); 
    
    void to_json(json& j, const response& p); 
    void from_json(const json& j, response& p); 
    
    void to_json(json& j, const notification& p); 
    void from_json(const json& j, notification& p); 
    
    std::ostream& operator<<(std::ostream&, const request&);
    std::ostream& operator<<(std::ostream&, const response&);
    std::ostream& operator<<(std::ostream&, const notification&);
    
    using params = json::array_t;
    
    struct request {
        
        request_id ID;
        
        method Method;
        
        params Params;
        
        request();
        request(request_id id, method m, const params& p);
        
        bool valid() const;
        
    };
    
    struct notification {
        
        method Method;
        
        params Params;
        
        notification();
        notification(method m, const params& p);
        
        bool valid() const;
    };
    
    struct response {
        
        request_id ID;
        
        json Result;
        
        error Error;
        
        response();
        response(request_id id, const json& p);
        response(request_id id, const json& p, const error& e);
            
        bool is_error() const;
        bool valid() const;
        
    };
    
    using job_id = uint32;
    
    using worker_name = std::string;
    
    inline bool operator==(const request& a, const request& b) {
        return a.ID == b.ID && a.Method == b.Method && a.Params == b.Params;
    }
    
    inline bool operator!=(const request& a, const request& b) {
        return !(a == b);
    }
    
    inline bool operator==(const notification& a, const notification& b) {
        return a.Method == b.Method && a.Params == b.Params;
    }
    
    inline bool operator!=(const notification& a, const notification& b) {
        return ! (a == b);
    }
    
    inline bool operator==(const response& a, const response& b) {
        return a.ID == b.ID && a.Result == b.Result && a.Error == b.Error;
    }
    
    inline bool operator!=(const response& a, const response& b) {
        return ! (a == b);
    }
    
    inline std::ostream& operator<<(std::ostream& o, const request& r) {
        json j;
        to_json(j, r);
        return o << j;
    }
    
    inline std::ostream& operator<<(std::ostream& o, const response& r) {
        json j;
        to_json(j, r);
        return o << j;
    }
    
    inline std::ostream& operator<<(std::ostream& o, const notification& r) {
        json j;
        to_json(j, r);
        return o << j;
    }
    
    inline request::request() : ID{0}, Method{unset}, Params{} {}
    
    inline request::request(request_id id, method m, const params& p) : ID{id}, Method{m}, Params(p) {}
    
    inline bool request::valid() const {
        return Method != unset;
    }
    
    inline notification::notification() : Method{unset}, Params{} {}
    
    inline notification::notification(method m, const params& p) : Method{m}, Params(p) {}
    
    inline bool notification::valid() const {
        return Method != unset;
    }
    
    inline response::response() : ID{0}, Result{}, Error{none} {}
    
    inline response::response(request_id id, const json& p) : ID{id}, Result(p), Error{none} {}
    
    inline response::response(request_id id, const json& p, const error& e) : ID{id}, Result(p), Error{e} {}
    
    inline bool response::is_error() const {
        return Error.Code == none;
    }
    
    inline bool response::valid() const {
        return data::valid(Error);
    }
    
}

#endif 

