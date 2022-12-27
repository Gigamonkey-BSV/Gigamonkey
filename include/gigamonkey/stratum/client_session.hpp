// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_CLIENT_SESSION
#define GIGAMONKEY_STRATUM_CLIENT_SESSION

#include <gigamonkey/work/solver.hpp>
#include <gigamonkey/stratum/remote.hpp>
#include <gigamonkey/stratum/mining_notify.hpp>
#include <gigamonkey/stratum/mining_set_difficulty.hpp>
#include <gigamonkey/stratum/mining_set_version_mask.hpp>
#include <gigamonkey/stratum/client_get_version.hpp>
#include <gigamonkey/stratum/client_show_message.hpp>
#include <gigamonkey/stratum/mining_set_extranonce.hpp>

namespace Gigamonkey::Stratum {
    
    // A client talking to a remote server. 
    struct client_session : public remote, public virtual work::solver {
        request_id send_configure(const extensions::requests &);
        request_id send_authorize(const mining::authorize_request::parameters &);
        request_id send_subscribe(const mining::subscribe_request::parameters &);
        request_id send_submit(const share &x);
        
        struct options {
            // how to respond to get_version requests. 
            string Version;
            
            optional<extensions::requests> ConfigureRequest;
            optional<mining::authorize_request::parameters> AuthorizeRequest;
            optional<mining::subscribe_request::parameters> SubscribeRequest;
        };
        
        client_session(const options &o) : Options{o} {}
        virtual ~client_session() {}
        
    private:
        
        void receive_submit(bool);
        virtual void receive_submit_error(const error &);
        
        void receive_authorize(bool);
        virtual void receive_authorize_error(const error &) = 0;
        void receive_configure(const extensions::results &);
        virtual void receive_configure_error(const error &) = 0;
        void receive_subscribe(const mining::subscribe_response::parameters &);
        virtual void receive_subscribe_error(const error &) = 0;
        
        virtual void receive_show_message(const string &m) {
            std::cout << "Server says: " << m << std::endl;
        }
        
        void receive_notification(const notification &n) final override;
        void receive_request(const Stratum::request &r) final override;
        void receive_response(method, const Stratum::response &r) final override;
        void solved(const work::solution &) final override;
        
        void receive_notify(const mining::notify::parameters&);
        void receive_set_difficulty(const difficulty&);
        void receive_set_extranonce(const mining::set_extranonce::parameters&);
        void receive_set_version_mask(const extensions::version_mask&);
        
        mutex Mutex{};
        
        options Options;
        
        optional<extensions::results> ExtensionResults;
        
        bool Authorized{false};
        list<mining::subscription> Subscriptions{};
        
        // last minimum difficulty accepted. 
        optional<difficulty> Minimum{};
        
        // the notifications we will receive from the server that
        // define the mining job we are to perform. 
        optional<difficulty> Difficulty{};
        optional<mining::set_extranonce::parameters> ExtraNonce{};
        optional<extensions::version_mask> VersionMask{};
        optional<mining::notify::parameters> Notify{};
        
        uint32 SharesSubmitted{0};
        uint32 SharesAccepted{0};
        
        void pose_current_puzzle();
        
    };
    
    request_id inline client_session::send_configure(const extensions::requests &q) {
        return send_request(mining_configure, mining::configure_request::serialize(mining::configure_request::parameters{q}));
    }
    
    request_id inline client_session::send_authorize(const mining::authorize_request::parameters &p) {
        return send_request(mining_authorize, mining::authorize_request::serialize(p));
    }
    
    request_id inline client_session::send_subscribe(const mining::subscribe_request::parameters &p) {
        return send_request(mining_subscribe, mining::subscribe_request::serialize(p));
    }
    
    request_id inline client_session::send_submit(const share &x) {
        remote::guard lock(Mutex);
        SharesSubmitted++;
        return send_request(mining_submit, mining::submit_request::serialize(x));
    }
    
    void inline client_session::receive_submit(bool b) {
        remote::guard lock(Mutex);
        if (b) SharesAccepted++;
    }
    
    void inline client_session::receive_submit_error(const error &e) {
        std::cout << "Share rejected with error " << JSON(e).dump() << std::endl;
    }
    
    void inline client_session::receive_notify(const mining::notify::parameters &x) {
        remote::guard lock(Mutex);
        Notify = x;
        pose_current_puzzle();
    }
    
    void inline client_session::receive_set_difficulty(const difficulty &x) {
        remote::guard lock(Mutex);
        Difficulty = x;
    }
    
    void inline client_session::receive_set_extranonce(const mining::set_extranonce::parameters &x) {
        remote::guard lock(Mutex);
        ExtraNonce = x;
    }
    
    void inline client_session::receive_set_version_mask(const extensions::version_mask &x) {
        remote::guard lock(Mutex);
        VersionMask = x;
        pose_current_puzzle();
    }
    
}

#endif 
