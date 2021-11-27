// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_REMOTE
#define GIGAMONKEY_STRATUM_REMOTE

#include <gigamonkey/stratum/stratum.hpp>
#include <gigamonkey/stratum/json_bi_stream.hpp>

namespace Gigamonkey::Stratum {
    
    // can be used for a remote server or a remote client. 
    class remote : public json_bi_stream {
        
        virtual void handle_notification(const notification &) = 0;
        
        virtual void handle_request(const Stratum::request &) = 0;
        
        // Number of requests sent in this session. It is used as the 
        // message id. 
        uint64 Requests;
        
        // we keep track of requests that were made of the remote peer and
        // promises to the requestor. 
        std::list<std::pair<Stratum::request, std::promise<response>*>> AwaitingResponse;
        
        std::mutex Mutex;
        
        void handle_response(const response &p) {
            std::lock_guard<std::mutex> lock(Mutex);
            
            // find the message that is beind responded to. 
            auto it = std::find_if(AwaitingResponse.begin(), AwaitingResponse.end(), 
                [&p](const std::pair<Stratum::request, std::promise<response>*> r) -> bool {
                    return p.id() == r.first.id();
                });
            
            if (it == AwaitingResponse.end()) throw std::logic_error {"invalid message id"};
            
            it->second->set_value(p);
            delete it->second;
            AwaitingResponse.erase(it); 
            
        }
        
        void error(const io_error&) final override;
        
        void receive(const json &next) final override {
            if (notification::valid(next)) handle_notification(notification{next});
            if (response::valid(next)) handle_response(response{next});
            if (Stratum::request::valid(next)) handle_request(Stratum::request{next});
            // TODO handle an error if the message is ill-formed. 
        }
        
    public:
        // there are two ways to talk to a server: request and notify. 
        // request expects a response and notify does not. 
        std::future<response> request(method m, parameters p) {
            std::lock_guard<std::mutex> lock(Mutex);
            AwaitingResponse.push_back(std::pair{Stratum::request{message_id(Requests), m, p}, new std::promise<response>()});
            this->send(AwaitingResponse.back().first);
            Requests++;
            return AwaitingResponse.back().second->get_future();
        }
        
        void notify(method m, parameters p) {
            this->send(notification{m, p});
        }
        
        remote(tcp::socket &&s) : json_bi_stream{std::move(s)} {}
        
        virtual ~remote();
        
    };
    
}

#endif 

