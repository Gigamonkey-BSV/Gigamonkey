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
    template <typename X> using promise = std::promise<X>;
    template <typename X> using future = std::future<X>;
    
    // can be used for a remote server or a remote client. 
    class remote : protected networking::tcp_session, public networking::json_line_session {
        
        virtual void handle_notification(const notification &) = 0;
        
        virtual void handle_request(const Stratum::request &) = 0;
        
        // Number of requests sent in this session. It is used as the 
        // message id. 
        request_id Requests;
        
        // we keep track of requests that were made of the remote peer and
        // promises to the requestor. 
        std::list<std::pair<Stratum::request, promise<response>*>> AwaitingResponse;

    public:
        using mutex = std::mutex;
        using guard = std::lock_guard<mutex>;

    private:
        mutex Mutex;
        
        void shutdown();
        
        void handle_response(const response &p);
        
        void receive(const json &next) final override;
        
    public:
        // there are two ways to talk to a server: request and notify. 
        // request expects a response and notify does not. 
        response request(method m, parameters p);
        
        void send_notification(method m, parameters p);
        
        remote(networking::tcp::socket &s);
        virtual ~remote();
        
    };
    
    void inline remote::send_notification(method m, parameters p) {
        networking::json_line_session::send(notification{m, p});
    }
    
    inline remote::remote(networking::tcp::socket &s) : 
        networking::tcp_session{s}, networking::json_line_session{} {}
    
    inline remote::~remote() {
        shutdown();
    }
    
}

#endif 

