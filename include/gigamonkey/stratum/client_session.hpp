// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_CLIENT
#define GIGAMONKEY_STRATUM_CLIENT

#include <gigamonkey/stratum/remote.hpp>
#include <gigamonkey/stratum/mining_notify.hpp>
#include <gigamonkey/stratum/mining_set_difficulty.hpp>
#include <gigamonkey/stratum/mining_set_version_mask.hpp>
#include <gigamonkey/stratum/client_get_version.hpp>
#include <gigamonkey/stratum/client_show_message.hpp>

namespace Gigamonkey::Stratum {
    
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
            if (client::get_version_request::valid(r)) this->send(client::get_version_response{r.id(), version()});
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
        
        client_session(tcp::socket &s) : remote{s} {}
        
        virtual ~client_session() {}
        
    };
    
}

#endif 
