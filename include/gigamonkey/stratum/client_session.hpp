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
#include <gigamonkey/stratum/mining_set_extranonce.hpp>

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
        
        void handle_notification(const notification &n) final override;
        
        void handle_request(const Stratum::request &r) final override;
        
    protected:
        bool initialize(
            const optional<extensions::requests> c, 
            const mining::authorize_request::parameters& ap, 
            const mining::subscribe_request::parameters& sp);
        
        // last minimum difficulty accepted. 
        optional<difficulty> Minimum{};
        
        list<mining::subscription> Subscriptions{};
        
    public:
        
        extensions::results configure(const extensions::requests &);
        
        bool authorize(const mining::authorize_request::parameters &);
        
        mining::subscribe_response::parameters subscribe(const mining::subscribe_request::parameters &);
        
        bool set_minimum_difficulty(const extensions::configuration<extensions::minimum_difficulty> &);
        
    private:
        
        uint32 SharesSubmitted{0};
        uint32 SharesAccepted{0};
        
    public:
        
        bool submit(const share &x);
        
        client_session(tcp::socket &s) : remote{s} {}
        
        virtual ~client_session() {}
        
    };
    
}

#endif 
