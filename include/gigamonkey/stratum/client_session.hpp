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
    class client_session : public remote, public virtual work::challenger {
        
        void notify(const mining::notify::parameters&);
        void set_difficulty(const difficulty&);
        void set_extranonce(const mining::set_extranonce::parameters&);
        void set_version_mask(const extensions::version_mask&);
        
        virtual void show_message(const string &m) {
            std::cout << "Server says: " << m << std::endl;
        }
        
        string version() const {
            return Version;
        };
        
        void handle_notification(const notification &n) final override;
        
        void handle_request(const Stratum::request &r) final override;
        
        void solved(const work::solution &) final override;
        
    protected:
        bool initialize(
            const optional<extensions::requests> c, 
            const mining::authorize_request::parameters& ap, 
            const mining::subscribe_request::parameters& sp);
        
        // last minimum difficulty accepted. 
        optional<difficulty> Minimum{};
        
        list<mining::subscription> Subscriptions{};
        
        // the notifications we will receive from the server that
        // define the mining job we are to perform. 
        optional<difficulty> Difficulty{};
        optional<mining::set_extranonce::parameters> ExtraNonce{};
        optional<extensions::version_mask> VersionMask{};
        optional<mining::notify::parameters> Notify{};
        
    public:
        
        extensions::results configure(const extensions::requests &);
        
        bool authorize(const mining::authorize_request::parameters &);
        
        mining::subscribe_response::parameters subscribe(const mining::subscribe_request::parameters &);
        
        bool set_minimum_difficulty(const extensions::configuration<extensions::minimum_difficulty> &);
        
        bool ready_to_mine() {
            return bool(ExtraNonce) && bool(Difficulty) && bool(Notify);
        }
        
    private:
        
        uint32 SharesSubmitted{0};
        uint32 SharesAccepted{0};
        
        string Version;
        
    public:
        bool submit(const share &x);
        
        client_session(networking::TCP::socket &&s, const string &version) : remote{std::move(s)}, Version{version} {}
        
        virtual ~client_session() {}
        
    };
    
}

#endif 
