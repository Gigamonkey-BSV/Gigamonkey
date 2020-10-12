// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_STRATUM
#define GIGAMONKEY_STRATUM_STRATUM

#include <gigamonkey/work/proof.hpp>
#include <gigamonkey/stratum/difficulty.hpp>

namespace Gigamonkey::Stratum {
    using request_id = uint64;
    
    // List of stratum methods (incomplete)
    enum method {
        unset,
        mining_authorize, 
        mining_configure, 
        mining_subscribe, 
        mining_notify, 
        mining_set_target, 
        mining_submit, 
        client_get_version,
        client_reconnect
    };
    
    std::string method_to_string(method m);
    
    method method_from_string(std::string st);
    
    // Stratum error codes (incomplete)
    enum error_code {
        none
    };
    
    std::string error_message_from_code(error_code);
    
    struct request;
    struct response;
    struct notification;
    
    void to_json(json& j, const request& p); 
    void from_json(const json& j, request& p); 
    
    void to_json(json& j, const response& p); 
    void from_json(const json& j, response& p); 
    
    void to_json(json& j, const notification& p); 
    void from_json(const json& j, notification& p); 
    
    struct request {
        
        request_id ID;
        
        method Method;
        
        std::vector<json> Params;
        
        request() : ID{0}, Method{unset}, Params{} {}
        request(request_id id, method m, const std::vector<json>& p) : ID{id}, Method{m}, Params{p} {}
        
        bool valid() const {
            return Method != unset;
        }
        
        bool operator==(const request& r) const {
            return ID == r.ID && Method == r.Method && Params == r.Params;
        }
        
        bool operator!=(const request& r) const {
            return !operator==(r);
        }
        
    };
    
    struct notification {
        
        method Method;
        
        std::vector<json> Params;
        
        notification() : Method{unset}, Params{} {}
        notification(method m, const std::vector<json>& p) : Method{m}, Params{p} {}
        
        bool valid() const {
            return Method != unset;
        }
        
        bool operator==(const notification& r) const {
            return Method == r.Method && Params == r.Params;
        }
        
        bool operator!=(const notification& r) const {
            return !operator==(r);
        }
    };
    
    struct response {
        
        request_id ID;
        
        json Result;
        
        error_code ErrorCode;
        
        std::string ErrorMessage;
        
        response() : ID{0}, Result{}, ErrorCode{none}{}
        response(request_id id, json p) : ID{id}, Result{p}, ErrorCode{none}, ErrorMessage{} {}
        response(request_id id, json p, error_code c) : 
            ID{id}, Result{p}, ErrorCode{c}, ErrorMessage{error_message_from_code(c)} {}
        
        bool operator==(const response& r) const {
            return ID == r.ID && Result == r.Result && ErrorCode == r.ErrorCode;
        }
        
        bool operator!=(const response& r) const {
            return !operator==(r);
        }
        
    private:
        response(request_id id, json p, error_code c, std::string error_message) : 
            ID{id}, Result{p}, ErrorCode{c}, ErrorMessage{error_message} {}
            
        friend void from_json(const json& j, response& p);
    };
    
}

#endif 

