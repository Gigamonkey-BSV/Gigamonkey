// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_SERVER_SESSION
#define GIGAMONKEY_STRATUM_SERVER_SESSION

#include <gigamonkey/work/solver.hpp>
#include <gigamonkey/stratum/remote.hpp>
#include <gigamonkey/stratum/mining_notify.hpp>
#include <gigamonkey/stratum/mining_configure.hpp>
#include <gigamonkey/stratum/mining_authorize.hpp>
#include <gigamonkey/stratum/mining_subscribe.hpp>
#include <gigamonkey/stratum/mining_submit.hpp>
#include <gigamonkey/stratum/mining_set_difficulty.hpp>
#include <gigamonkey/stratum/mining_set_version_mask.hpp>
#include <gigamonkey/stratum/mining_set_extranonce.hpp>
#include <shared_mutex>

namespace Gigamonkey::Stratum {
    
    // this represents a server talking to a remote client. 
    struct server_session : public remote_receive_handler, public work::selector {
        
        struct options {
            bool CanSubmitWithoutAuthorization {true};
            
            // maximum number of seconds a share can differ from our own 
            // clock to be accepted. 
            uint32 MaxTimeDifferenceSeconds {10};
            
            uint32 RememberOldJobsSeconds {60};
            
            optional<extensions::options> ExtensionsParameters {};
            
            // if minimum difficulty is supported, do we honor 
            // the client's requested minimum difficulty or 
            // do we ignore it? 
            bool HonorMinimumDifficulty {true};
            
            options () {};
        };
        
        server_session  (stream p, const options &x) : remote_receive_handler {p}, State {x} {}
        virtual ~server_session () {}
        
        Stratum::difficulty difficulty () const;
        
        // send a set_difficulty message to the client. 
        // this will not go into effect until the next 
        // notify message is sent. 
        awaitable<void> send_set_difficulty (const Stratum::difficulty &d);
        
        optional<string> username () const;
        
        // notify the client of a new job. 
        awaitable<void> send_notify (const mining::notify::parameters &p);
        
        optional<string> client_version () const;
        
        extensions::version_mask version_mask () const;
        
        // send a set_version_mask message to the client. 
        void send_set_version_mask (const extensions::version_mask &p);
        
        Stratum::extranonce extranonce () const;
        
        // send a set_extranonce message to the client. 
        // this will not go into effect until the next 
        // notify message is sent. 
        awaitable<void> send_set_extranonce (const Stratum::extranonce &n);
        
        // get_version is the only request that the server sends to the client.
        // It doesn't depend on state so can be sent at any time. 
        request_id send_get_version ();
        
    private:
        virtual void receive_get_version (const string &) {};
        
        // we need a database of users to check logins. 
        // empty return value means a successful authorization. 
        virtual optional<error> authorize (const mining::authorize_request::parameters&) = 0;
        
        // authorize the client to the server. 
        mining::authorize_response authorize (const mining::authorize_request &r);
        
        // We also need a way to assign session ids and subscriptions to users. 
        virtual mining::subscribe_response::parameters subscribe (const mining::subscribe_request::parameters&) = 0;
        
        // typically the client does not send notifications to the server.
        virtual void receive_notification (const notification &n) override {
            throw exception {} << "unknown notification received: " + n.dump ();
        }
        
        awaitable<void> receive_request (const Stratum::request &) final override;
        void receive_response (method, const Stratum::response &) final override;
        work::puzzle select () final override;
        
        // generate a configure response from a configure request message. 
        // this is the optional first method of the protocol. 
        mining::configure_response configure (const mining::configure_request &r);
        
        // empty return value for an accepted share. 
        optional<error> submit (const share &x);
        
        // the state data of the protocol. 
        class state {
            
            options Options;
            
            // whether we have received and responded to a mining.configure message. 
            bool Configured {false};
            
            // Extension version_rolling allows clients to use ASICBoost. Server and client agree
            // on a mask that says what bits of the version field the client is allowed to alter. 
            extensions::parameters<extensions::version_rolling> VersionRollingMaskParameters;
            
            // optionally a client can request a minimum difficulty. 
            optional<Stratum::difficulty> MinimumDifficulty;
            
            // we can ask the client for its version string and we 
            // store that here if we get it. 
            optional<string> ClientVersion;
            
            // The user name of the worker. 
            // Set during the authorize method. 
            optional<string> Name {};
            
            // subscriptions are assigned during the subscribe method. 
            list<mining::subscription> Subscriptions; 
            
            // set_extranonce and set_difficulty do go into effect until 
            // after the next mining.notify message is sent, so we have 
            // to remember two of each. 
            Stratum::extranonce Extranonce;
            Stratum::extranonce NextExtranonce;
            
            Stratum::difficulty Difficulty;
            Stratum::difficulty NextDifficulty;
            
        public:
            bool extensions_supported () const;
            
            // whether we have received and responded to a mining.configure message. 
            bool configured () const;
            
            // whether we have received and responded 'true' to a mining.authorize message.
            bool authorized () const;
            
            string name () const;
            void set_name (const string &x);
            
            optional<string> client_version () const;
            void set_client_version (const string &x);
            
            // whether we have received and responded true' to a mining.subscribe message. 
            bool subscribed () const;
        
            Stratum::difficulty difficulty () const;
            bool set_difficulty (const Stratum::difficulty& d);
            
            Stratum::extranonce extranonce () const;
            bool set_extranonce (const Stratum::extranonce &n);
            
            // version mask that the client is using. 
            optional<extensions::version_mask> version_mask () const;
            
            // return value is whether the version mask has changed. 
            bool set_version_mask (const extensions::version_mask &x);
            
            Stratum::difficulty minimum_difficulty () const;
            void set_minimum_difficulty (optional<Stratum::difficulty> d);
            
            extensions::result configure_result (
                const string &extension, 
                const extensions::request &request);
            
            // empty return value means extensions are not supported. 
            optional<extensions::results> configure (const extensions::requests& p);
            
            // we need to keep track of the last few notify notifications that have been sent. 
            struct history {
                struct entry {
                    optional<extensions::version_mask> Mask;
                    Stratum::extranonce ExtraNonce;
                    mining::notify::parameters Notification;
                    
                    entry ();
                    entry (
                        const optional<extensions::version_mask> &m,
                        const Stratum::extranonce &n,
                        const mining::notify::parameters &p) : 
                        Mask{m}, ExtraNonce {n}, Notification{p} {}
                    
                    Bitcoin::timestamp time () const {
                        return Notification.Now;
                    }
                };
                
                double RememberForThisMuchTime;
                std::list<entry> Notifications;
                
                void push(
                    optional<extensions::version_mask> mask,
                    Stratum::extranonce n,
                    const mining::notify::parameters &p) {
                    
                    while (Notifications.size () > 0 && (p.Now - Notifications.back().time()) > RememberForThisMuchTime)
                        Notifications.pop_back ();
                    
                    Notifications.push_front ({mask, n, p});
                }
            };
        
            history Notifies;
            set<byte_array<80>> Recent;
            
            struct found {
                proof Proof;
                bool Found;
                bool Stale;
                
                found () : Proof{}, Found{false}, Stale{true} {}
                found (const proof &p, bool x) : Proof{p}, Found{true}, Stale{x} {}
            };
            
            found find (const share &x) const;
        
            void notify (const mining::notify::parameters& p);
            
            state () {}
            state (const options &x) :
               Options {x}, Notifies {static_cast<double> (x.RememberOldJobsSeconds)}, Recent {} {}
            
        };
        
        state State {};
        
    };
    
    optional<string> inline server_session::username () const {
        return State.name ();
    }
    
    Stratum::extranonce inline server_session::extranonce () const {
        return State.extranonce ();
    }
    
    awaitable<void> inline server_session::send_set_extranonce (const Stratum::extranonce &n) {
        if (State.set_extranonce (n)) co_return co_await this->send_notification (
            mining_set_extranonce,
            mining::set_extranonce::serialize (n));
    }
    
    extensions::version_mask inline server_session::version_mask () const {
        auto mask = State.version_mask ();
        return bool (mask) ? *mask : extensions::version_mask {0};
    }
    
    void inline server_session::send_set_version_mask (const extensions::version_mask &n) {
        if (State.set_version_mask (n))
            this->send_notification (mining_set_extranonce, mining::set_version_mask::serialize (*State.version_mask ()));
    }
    
    Stratum::difficulty inline server_session::difficulty () const {
        return State.difficulty ();
    }
    
    awaitable<void> inline server_session::send_set_difficulty (const Stratum::difficulty &d) {
        if (State.set_difficulty (d)) this->send_notification (mining_set_difficulty, mining::set_difficulty::serialize (d));
    }
    
    awaitable<void> inline server_session::send_notify (const mining::notify::parameters &p) {
        State.notify (p);
        this->send_notification (mining_notify, mining::notify::serialize (p));
    }
    
    request_id inline server_session::send_get_version () {
        return this->send_request (client_get_version, {});
    }
    
    optional<string> inline server_session::client_version () const {
        return State.client_version ();
    }
    
    bool inline server_session::state::extensions_supported () const {
        return bool (Options.ExtensionsParameters);
    }
    
    // whether we have received and responded to a mining.configure message. 
    bool inline server_session::state::configured() const {
        return Configured;
    }
    
    // whether we have received and responded 'true' to a mining.authorize message.
    bool inline server_session::state::authorized() const {
        return bool (Name);
    }
    
    string inline server_session::state::name() const {
        return bool (Name) ? *Name : "";
    }
    
    void inline server_session::state::set_name(const string &x) {
        Name = x;
    }
    
    optional<string> inline server_session::state::client_version() const {
        return ClientVersion;
    }
    
    void inline server_session::state::set_client_version(const string &x) {
        ClientVersion = x;
    }
    
    // whether we have received and responded true' to a mining.subscribe message. 
    bool inline server_session::state::subscribed () const {
        return Subscriptions.size () > 0;
    }
    
    Stratum::difficulty inline server_session::state::difficulty () const {
        return Difficulty;
    }
    
    Stratum::extranonce inline server_session::state::extranonce () const {
        return Extranonce;
    }
    
    // version mask that the client is using. 
    optional<extensions::version_mask> inline server_session::state::version_mask () const {
        return VersionRollingMaskParameters.get ();
    }
    
    Stratum::difficulty inline server_session::state::minimum_difficulty () const {
        if (!MinimumDifficulty) return Stratum::difficulty {0};
        return *MinimumDifficulty;
    }
    
    void inline server_session::state::set_minimum_difficulty (optional<Stratum::difficulty> d) {
        MinimumDifficulty = d;
    }
}

#endif
