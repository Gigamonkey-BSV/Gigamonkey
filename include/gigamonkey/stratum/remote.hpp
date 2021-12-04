// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_REMOTE
#define GIGAMONKEY_STRATUM_REMOTE

#include <gigamonkey/stratum/stratum.hpp>
#include <gigamonkey/stratum/json_bi_stream.hpp>
#include <gigamonkey/stratum/mining_configure.hpp>
#include <gigamonkey/stratum/mining_authorize.hpp>
#include <gigamonkey/stratum/mining_subscribe.hpp>
#include <gigamonkey/stratum/mining_submit.hpp>
#include <gigamonkey/stratum/client_get_version.hpp>
#include <boost/system/error_code.hpp>

namespace Gigamonkey::Stratum {
    using mutex = std::mutex;
    template <typename X> using promise = std::promise<X>;
    template <typename X> using future = std::future<X>;
    
    // can be used for a remote server or a remote client. 
    class remote : public json_bi_stream {
        using guard = std::lock_guard<mutex>;
        
        virtual void handle_notification(const notification &) = 0;
        
        virtual void handle_request(const Stratum::request &) = 0;
        
        // Number of requests sent in this session. It is used as the 
        // message id. 
        request_id Requests;
        
        // we keep track of requests that were made of the remote peer and
        // promises to the requestor. 
        std::list<std::pair<Stratum::request, promise<response>*>> AwaitingResponse;
        
        mutex Mutex;
        
        void shutdown() {
            guard lock(Mutex);
            for (const std::pair<Stratum::request, promise<response>*>& p : AwaitingResponse) delete p.second;
        }
        
        void handle_response(const response &p) {
            guard lock(Mutex);
            
            // find the message that is beind responded to. 
            auto it = std::find_if(AwaitingResponse.begin(), AwaitingResponse.end(), 
                [&p](const std::pair<Stratum::request, promise<response>*> r) -> bool {
                    return p.id() == r.first.id();
                });
            
            if (it == AwaitingResponse.end()) throw 0; // should not happen. 
            
            it->second->set_value(p);
            delete it->second;
            AwaitingResponse.erase(it); 
            
        }
        
        void receive(const json &next) final override {
            if (notification::valid(next)) handle_notification(notification{next});
            if (response::valid(next)) handle_response(response{next});
            if (Stratum::request::valid(next)) handle_request(Stratum::request{next});
            throw std::logic_error{string{"invalid Stratum message received: "} + string(next)};
        }
        
    public:
        // there are two ways to talk to a server: request and notify. 
        // request expects a response and notify does not. 
        response request(method m, parameters p) {
            guard lock(Mutex);
            AwaitingResponse.push_back(std::pair{Stratum::request{message_id(Requests), m, p}, new promise<response>()});
            this->send(AwaitingResponse.back().first);
            Requests++;
            return AwaitingResponse.back().second->get_future().get();
        }
        
        void notify(method m, parameters p) {
            this->send(notification{m, p});
        }
        
        bool submit(const share &x) {
            auto serialized = mining::submit_request::serialize(x);
            
            std::cout << "sending submit request " << serialized << std::endl;
            
            response r = request(mining_submit, serialized);
            
            if (!mining::submit_response::valid(r)) 
                throw std::logic_error{string{"invalid mining.submit response received: "} + string(r)};
            
            return mining::submit_response{r}.result();
            
        }
        
        mining::configure_response::parameters configure(const mining::configure_request::parameters &q) {
            auto serialized = mining::configure_request::serialize(q);
            
            std::cout << "sending configure request " << serialized << std::endl;
            
            response s = request(mining_configure, serialized);
            
            if (!mining::configure_response::valid(s)) 
                throw std::logic_error{string{"invalid configure response received: "} + string(s)};
            
            auto r = mining::configure_response{s}.result();
            
            if (!mining::configure_response::valid_result(r, q))
                throw std::logic_error{string{"invalid response to "} + string(json{serialized}) + " received: " + string(s)};
            
            if (auto configuration = q.get<extensions::version_rolling>(); bool(configuration)) 
                std::cout << *configuration << " requested; response = " << *r.get<extensions::version_rolling>() << std::endl; 
            
            if (auto configuration = q.get<extensions::minimum_difficulty>(); bool(configuration)) 
                std::cout << *configuration << " requested; response = " << *r.get<extensions::minimum_difficulty>() << std::endl; 
            
            if (auto configuration = q.get<extensions::subscribe_extranonce>(); bool(configuration)) 
                std::cout << *configuration << " requested; response = " << *r.get<extensions::subscribe_extranonce>() << std::endl; 
            
            if (auto configuration = q.get<extensions::info>(); bool(configuration)) 
                std::cout << *configuration << " requested; response = " << *r.get<extensions::info>() << std::endl; 
            
            return r;
        }
        
        bool authorize(const mining::authorize_request::parameters &x) {
            auto serialized = mining::authorize_request::serialize(x);
            
            std::cout << "sending authorize request " << serialized << std::endl;
            
            response r = request(mining_authorize, serialized);
            
            if (!mining::authorize_response::valid(r)) 
                throw std::logic_error{string{"invalid authorization response received: "} + string(r)};
            
            bool result = mining::authorize_response{r}.result();
            std::cout << (result ? "authorization successful!" : "authorization failed!") << std::endl;
            return result;
        }
        
        mining::subscribe_response::parameters subscribe(const mining::subscribe_request::parameters &x) {
            auto serialized = mining::subscribe_request::serialize(x);
            
            std::cout << "sending subscribe request " << serialized << std::endl;
            
            response r = request(mining_subscribe, serialized);
            
            if (!mining::subscribe_response::valid(r)) 
                throw std::logic_error{string{"invalid subscribe response received: "} + string(r)};
            
            std::cout << "subscribe response received " << r << std::endl;
            
            return mining::subscribe_response{r}.result();
        }
        
        string get_version() {
            response r = request(client_get_version, {});
            if (!client::get_version_response::valid(r)) 
                throw std::logic_error{string{"invalid get_version response received: "} + string(r)}; 
            return client::get_version_response{r}.result();
        }
        
        remote(tcp::socket &s) : json_bi_stream{s} {}
        
        virtual ~remote() {
            shutdown();
        }
        
    };
    
}

#endif 

