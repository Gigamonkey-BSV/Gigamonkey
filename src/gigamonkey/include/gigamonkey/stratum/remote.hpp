// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_REMOTE
#define GIGAMONKEY_STRATUM_REMOTE

#include <gigamonkey/stratum/stratum.hpp>
#include <gigamonkey/stratum/mining_configure.hpp>
#include <gigamonkey/stratum/mining_authorize.hpp>
#include <gigamonkey/stratum/mining_subscribe.hpp>
#include <gigamonkey/stratum/mining_submit.hpp>
#include <gigamonkey/stratum/client_get_version.hpp>
#include <boost/system/error_code.hpp>
#include <data/net/TCP.hpp>
#include <data/net/JSON.hpp>

namespace Gigamonkey::Stratum {
    
    // can be used for a remote server or a remote client. 
    struct remote_receive_handler {
        ptr<net::session<JSON>> Send;
    
        virtual void receive_notification (const notification &) = 0;
        virtual void receive_request (const Stratum::request &) = 0;
        virtual void receive_response (method, const Stratum::response &) = 0;
        
        virtual void parse_error (const string &invalid);
        
        uint32 Requests {0};
        std::map<request_id, method> Request;
        
        void operator () (const JSON &next);
        
        // there are two ways to talk to a server: request and notify. 
        // request expects a response and notify does not. 
        request_id send_request (method m, parameters p);
        
        void send_notification (method m, parameters p);
        
        remote_receive_handler (ptr<net::session<JSON>> x): Send {x} {}
        
    };
    
    struct exception : data::exception {
        using data::exception::exception;
        exception (const error &e) : data::exception {} {
            this->write ("Stratum error returned: ", JSON (e).dump ());
        }
        
        template <typename X> exception &operator << (X x) {
            this->write (x);
            return *this;
        }
    };
    
    void inline remote_receive_handler::send_notification (method m, parameters p) {
        Send->send (notification {m, p});
    }
    
    void inline remote_receive_handler::parse_error (const string &invalid) {
        throw exception {} << "Invalid JSON string: \"" << invalid << "\"";
    }
    
}

#endif 

