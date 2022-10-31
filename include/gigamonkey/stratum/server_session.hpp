// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_SERVER_SESSION
#define GIGAMONKEY_STRATUM_SERVER_SESSION

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
    class server_session : public remote, public virtual work::challenger {
        
        // we need a database of users to check logins. 
        // empty return value means a successful authorization. 
        virtual optional<error> authorize(const mining::authorize_request::parameters&) = 0;
        
        // We also need a way to assign session ids and subscriptions to users. 
        virtual mining::subscribe_response::parameters subscribe(const mining::subscribe_request::parameters&) = 0;
        
        // typically the client does not send notifications to the server.
        virtual void receive_notification(const notification &n) override {
            throw std::logic_error{string{"unknown notification received: "} + string(n)};
        }
        
        void receive_request(const Stratum::request &) final override;
        void receive_response(method, const Stratum::response &) final override;
        void pose(const work::puzzle &) final override;
        
    public:
        struct options {
            bool CanSubmitWithoutAuthorization{true};
            
            // maximum number of seconds a share can differ from our own 
            // clock to be accepted. 
            uint32 MaxTimeDifferenceSeconds{10};
            
            uint32 RememberOldJobsSeconds{60};
            
            optional<extensions::options> ExtensionsParameters{};
            
            options() {};
        };
        
        server_session(const options &x = {}) : State{x} {}
        virtual ~server_session() {}
        
        Stratum::difficulty difficulty() const;
        
        // send a set_difficulty message to the client. 
        // this will not go into effect until the next 
        // notify message is sent. 
        void send_set_difficulty(const Stratum::difficulty& d);
        
        optional<string> username() const;
        
        // notify the client of a new job. 
        void send_notify(const mining::notify::parameters& p);
        
        optional<string> version() const;
        
        // get_version is the only request that the server sends to the client.
        // It doesn't depend on state so can be sent at any time. 
        request_id send_get_version();
        
        extensions::version_mask version_mask() const;
        
        // send a set_version_mask message to the client. 
        void send_set_version_mask(const extensions::version_mask& p);
        
        Stratum::extranonce extranonce() const;
        
        // send a set_extranonce message to the client. 
        // this will not go into effect until the next 
        // notify message is sent. 
        void send_set_extranonce(const Stratum::extranonce &n);
        
    private:
        void receive_get_version();
        
        // generate a configure response from a configure request message. 
        // this is the optional first method of the protocol. 
        mining::configure_response configure(const mining::configure_request &r);
        
        // authorize the client to the server. 
        mining::authorize_response authorize(const mining::authorize_request &r);
        
        // empty return value for an accepted share. 
        optional<error> submit(const share &x);
        
        // the state data of the protocol. 
        struct state {
            
            options Options;
            
            bool extensions_supported() const {
                return bool(Options.ExtensionsParameters);
            }
            
            bool Configured{false};
            
            // whether we have received and responded to a mining.configure message. 
            bool configured() const {
                return Configured;
            }
            
            // Extension version_rolling allows clients to use ASICBoost. Server and client agree
            // on a mask that says what bits of the version field the client is allowed to alter. 
            extensions::parameters<extensions::version_rolling> VersionRollingMaskParameters;
            
            extensions::version_mask version_mask() const {
                auto mask = VersionRollingMaskParameters.get();
                if (!mask) return 0;
                return *mask;
            }
            
            optional<extensions::version_mask> set_version_mask(const extensions::version_mask &x) {
                return VersionRollingMaskParameters.set(x);
            }
            
            extensions::result configure_result(
                const string &extension, 
                const extensions::request &request);
            
            // empty return value means extensions are not supported. 
            optional<extensions::results> configure(const extensions::requests& p);
            
            // The user name of the worker. 
            // Set during the authorize method. 
            optional<string> Name{};
            
            // whether we have received and responded 'true' to a mining.authorize message.
            bool authorized() const {
                return bool(Name);
            };
            
            optional<Stratum::difficulty> MinimumDifficulty;
            
            Stratum::difficulty minimum_difficulty() const {
                if (!MinimumDifficulty) return Stratum::difficulty{0};
                return *MinimumDifficulty;
            }
            
            void set_minimum_difficulty(optional<Stratum::difficulty> d) {
                MinimumDifficulty = d;
            }
        
            // subscriptions are assigned during the subscribe method. 
            list<mining::subscription> Subscriptions; 
            
            // whether we have received and responded true' to a mining.subscribe message. 
            bool subscribed() {
                return Subscriptions.size() > 0;
            }
            
            Stratum::extranonce Extranonce;
            Stratum::extranonce NextExtranonce;
        
            void set_extranonce(const Stratum::extranonce &n) {
                if (!subscribed()) throw std::logic_error{"Cannot set extra nonce before client is subscribed"};
                NextExtranonce = n;
            }
        
            Stratum::difficulty Difficulty;
            Stratum::difficulty NextDifficulty;
        
            Stratum::difficulty difficulty() const {
                return Difficulty;
            }
            
            void set_difficulty(const Stratum::difficulty& d) {
                if (!subscribed()) throw std::logic_error{"Cannot set difficulty before client is subscribed"};
                if (bool(MinimumDifficulty) && d > *MinimumDifficulty) NextDifficulty = d; 
                NextDifficulty = d;
            }
            
            // we need to keep track of the last few notify notifications that have been sent. 
            struct history {
                struct entry {
                    optional<extensions::version_mask> Mask;
                    Stratum::extranonce ExtraNonce;
                    mining::notify::parameters Notification;
                    
                    entry();
                    entry(
                        const optional<extensions::version_mask> &m,
                        const Stratum::extranonce &n,
                        const mining::notify::parameters &p) : 
                        Mask{m}, ExtraNonce{n}, Notification{p} {}
                    
                    Bitcoin::timestamp time() const {
                        return Notification.Now;
                    }
                };
                
                double RememberForThisMuchTime;
                std::list<entry> Notifications;
                
                void push(
                    optional<extensions::version_mask> mask,
                    Stratum::extranonce n,
                    const mining::notify::parameters &p) {
                    
                    while (Notifications.size() > 0 && (p.Now - Notifications.back().time()) > RememberForThisMuchTime)
                        Notifications.pop_back();
                    
                    Notifications.push_front({mask, n, p});
                }
            };
        
            history Notifies;
            set<byte_array<80>> Recent;
            
            struct found {
                proof Proof;
                bool Found;
                bool Stale;
                
                found() : Proof{}, Found{false}, Stale{true} {}
                found(const proof &p, bool x) : Proof{p}, Found{true}, Stale{x} {} 
            };
            
            found find(const share &x) const;
        
            void notify(const mining::notify::parameters& p);
            
            state() {}
            state(const options &x) : 
               Options{x}, Notifies{static_cast<double>(x.RememberOldJobsSeconds)}, Recent{} {}
            
        };
        
        state State{};
        
        mutable std::shared_mutex Mutex{};
        
    };
    
    extensions::version_mask inline server_session::version_mask() const {
        std::shared_lock lock(Mutex);
        return State.version_mask();
    }
    
    optional<string> inline server_session::username() const {
        std::shared_lock lock(Mutex);
        return State.Name;
    }
    
    Stratum::extranonce inline server_session::extranonce() const {
        std::shared_lock lock(Mutex);
        return State.Extranonce;
    }
    
    void inline server_session::send_set_extranonce(const Stratum::extranonce &n) {
        std::unique_lock lock(Mutex);
        State.set_extranonce(n);
        this->send_notification(mining_set_extranonce, mining::set_extranonce::serialize(n));
    }
    
    Stratum::difficulty inline server_session::difficulty() const {
        std::shared_lock lock(Mutex);
        return State.difficulty();
    }
    
    void inline server_session::send_set_difficulty(const Stratum::difficulty& d) {
        std::unique_lock lock(Mutex);
        State.set_difficulty(d);
        this->send_notification(mining_set_difficulty, mining::set_difficulty::serialize(d));
    }
    
    void inline server_session::send_notify(const mining::notify::parameters& p) {
        std::shared_lock lock(Mutex);
        State.notify(p);
        this->send_notification(mining_notify, mining::notify::serialize(p));
    }
}

#endif
