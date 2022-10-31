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
#include <data/networking/TCP.hpp>
#include <data/networking/JSON.hpp>

namespace Gigamonkey::Stratum {
    using JSON_line_session = networking::JSON_line_session;
    
    // can be used for a remote server or a remote client. 
    struct remote : public JSON_line_session {
    
        virtual void receive_notification(const notification &) = 0;
        virtual void receive_request(const Stratum::request &) = 0;
        virtual void receive_response(method, const Stratum::response &) = 0;
        
        virtual void parse_error(const string &invalid) override;
        
        uint32 Requests{0};
        std::map<request_id, method> Request;
        
        using mutex = std::mutex;
        using guard = std::lock_guard<mutex>;
        
        mutex Mutex{};
        
        void receive(const JSON &next) final override;
        
        // there are two ways to talk to a server: request and notify. 
        // request expects a response and notify does not. 
        request_id send_request(method m, parameters p);
        
        void send_notification(method m, parameters p);
        
        remote() {}
        virtual ~remote() {}
        
    };
    
    struct exception : std::logic_error {
        using std::logic_error::logic_error;
        exception(const error &e) : std::logic_error {string{"Stratum error returned: "} + JSON(e).dump()} {}
    };
    
    void inline remote::send_notification(method m, parameters p) {
        JSON_line_session::send(notification{m, p});
    }
    
    void inline remote::parse_error(const string &invalid) {
        throw exception{std::string{"Invalid JSON string: \""} + invalid + string{"\""}};
    }
    
}

#endif 

