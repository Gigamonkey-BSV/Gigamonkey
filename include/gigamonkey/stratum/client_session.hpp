// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_CLIENT_SESSION
#define GIGAMONKEY_STRATUM_CLIENT_SESSION

#include <gigamonkey/stratum/remote.hpp>
#include <gigamonkey/stratum/mining_notify.hpp>
#include <gigamonkey/stratum/mining_set_difficulty.hpp>
#include <gigamonkey/stratum/mining_set_version_mask.hpp>
#include <gigamonkey/stratum/client_get_version.hpp>
#include <gigamonkey/stratum/client_show_message.hpp>

namespace Gigamonkey::Stratum {
    
    // this represents a client talking to a remote server. 
    class client_session : public remote {
        
        virtual void notify(const mining::notify::parameters&) = 0;
        virtual void set_difficulty(const difficulty&) = 0;
        virtual void set_extranonce(const mining::set_extranonce::parameters&) = 0;
        virtual void set_version_mask(const extensions::version_mask&) = 0;
        
        virtual void show_message(const string &m) {
            std::cout << "Server says: " << m << std::endl;
        }
        
        virtual string version() = 0;
        
        void handle_notification(const notification &n) final override {
            if (mining::notify::valid(n)) return notify(mining::notify{n}.params());
            if (mining::set_difficulty::valid(n)) return set_difficulty(mining::set_difficulty{n}.params());
            if (mining::set_extranonce::valid(n)) return set_extranonce(mining::set_extranonce{n}.params());
            if (mining::set_version_mask::valid(n)) return set_version_mask(mining::set_version_mask{n}.params());
            if (client::show_message::valid(n)) return show_message(client::show_message{n}.params());
            throw std::logic_error{string{"unknown notification received: "} + string(n)};
        }
        
        void handle_request(const Stratum::request &r) final override {
            if (client::get_version_request::valid(r)) return this->send(client::get_version_response{r.id(), version()});
            this->send(response{r.id(), nullptr, error{ILLEGAL_METHOD}});
            throw std::logic_error{string{"unknown request received: "} + string(r)};
        }
        
        void setup_extensions(const mining::configure_response::parameters &r) {
            // we don't actually need to do anything here. 
        }
        
    protected:
        bool initialize(
            const optional<mining::configure_request::parameters> c, 
            const mining::authorize_request::parameters& ap, 
            const mining::subscribe_request::parameters& sp) {
            
            if (c) setup_extensions(this->configure(*c));
            
            if (!this->authorize(ap)) {
                std::cout << "failed to authorize" << std::endl;
                return false;
            }
            
            auto subs = subscribe(sp);
            return true;
        }
        
        
    public:
        
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
        
        client_session(tcp::socket &s) : remote{s} {}
        
        virtual ~client_session() {}
        
    };
    
}

#endif 
