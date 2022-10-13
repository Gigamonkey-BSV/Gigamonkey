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
    class server_session : public remote {
        
        // we need a database of users to check logins. 
        // empty return value means a successful authorization. 
        virtual optional<error> authorize(const mining::authorize_request::parameters&) = 0;
        
        // We also need a way to assign session ids and subscriptions to users. 
        virtual mining::subscribe_response::parameters subscribe(const mining::subscribe_request::parameters&) = 0;
        
        // typically the client does not send notifications to the server.
        virtual void handle_notification(const notification &n) override {
            throw std::logic_error{string{"unknown notification received: "} + string(n)};
        }
        
        // indicate that a user has earned a payment. 
        virtual void payment(const string &username, const difficulty &) = 0;
        
        // solution found. 
        virtual void solution(const proof &) = 0;
        
    public:
        
        struct options {
            bool CanSubmitWithoutAuthorization{true};
            
            // maximum number of seconds a share can differ from our own 
            // clock to be accepted. 
            uint32 MaxTimeDifferenceSeconds{10};
            
            optional<extensions::options> ExtensionsParameters{};
        };
        
        // get_version is the only request that the server sends to the client.
        // It doesn't depend on state so can be sent at any time. 
        string get_version();
        
    private:
        
        // the state data of the protocol. 
        struct state {
            
            options Options;
            
            // Extensions requested by the client. 
            optional<extensions::requests> ExtensionsRequested{};
            
            // Extension parameters returned by the server. 
            extensions::results ExtensionsParameters{};
            
            // whether we have received and responded to a mining.configure message. 
            bool configured() const {
                return bool(Options.ExtensionsParameters) && bool(ExtensionsRequested);
            }
        
            static optional<extensions::version_mask> make_version_mask(
                extensions::version_mask x, 
                const extensions::configuration<extensions::version_rolling> &r);
            
            // Extension version_rolling allows clients to use ASICBoost. Server and client agree
            // on a mask that says what bits of the version field the client is allowed to alter. 
            extensions::version_mask version_mask() const;
            
            optional<extensions::version_mask> set_version_mask(extensions::version_mask x);
            
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
        
            string username() const {
                if (Name.has_value()) return *Name;
                return "";
            }
            
            optional<Stratum::difficulty> MinimumDifficulty;
            
            Stratum::difficulty minimum_difficulty() const {
                if (!MinimumDifficulty) return Stratum::difficulty{0};
                return *MinimumDifficulty;
            }
            
            void set_minimum_difficulty(optional<Stratum::difficulty> d) {
                MinimumDifficulty = d;
            }
        
            // subscriptions are assigned during the subscribe method. 
            optional<mining::subscription> Subscriptions; 
            
            // whether we have received and responded true' to a mining.subscribe message. 
            bool subscribed() {
                return bool(Subscriptions);
            }
            
            Stratum::extranonce Extranonce;
            Stratum::extranonce NextExtranonce;
            
            Stratum::extranonce extranonce() const {
                return ExtraNonce;
            }
        
            void set_extranonce(const Stratum::extranonce &n) {
                if (!subscribed()) throw std::logic_error{"Cannot set extra nonce before client is subscribed"};
                NextExtranonce = n;
            }
        
            Stratum::difficulty Difficulty;
            Stratum::difficulty NextDifficulty;
        
            Stratum::difficulty difficulty() const {
                if (!Difficulty) return Stratum::difficulty{0};
                return *Difficulty;
            }
            
            void set_difficulty(const Stratum::difficulty& d) {
                if (!subscribed()) throw std::logic_error{"Cannot set difficulty before client is subscribed"};
                Difficulty = d;
            }
            
            // we need to keep track of the last few notify notifications that have been sent. 
            struct notifies {
                struct entry {
                    std::chrono::time_point<std::chrono::system_clock> Time;
                    extensions::version_mask Mask;
                    Stratum::extranonce ExtraNonce;
                    mining::notify::parameters Notification;
                    
                    entry();
                    entry(
                        const std::chrono::time_point<std::chrono::system_clock> &t,
                        const extensions::version_mask &m,
                        const Stratum::extranonce &n,
                        const mining::notify::parameters &p) : 
                        Time{t}, Mask{m}, ExtraNonce{n}, Notification{p} {}
                };
                
                std::list<entry> Notifications;
                std::chrono::duration<uint64> RememberForThisMuchTime;
                uint32 MaxSize;
                
                void push(
                    extensions::version_mask mask,
                    Stratum::extranonce n,
                    const mining::notify::parameters &p) {
                    const std::chrono::time_point<std::chrono::system_clock> now =
                        std::chrono::system_clock::now();
                        
                    while (Notifications.size() > MaxSize) Notifications.pop_back();
                    while (Notifications.size() > 0 && (now - Notifications.back().Time) > RememberForThisMuchTime) Notifications.pop_back();
                    
                    Notifications.push_front({now, mask, n, p});
                }
            };
        
            notifies Notifies{};
            set<byte_array<80>> Recent;
            
            struct found {
                proof Proof;
                bool Found;
                bool Stale;
                
                found() : Proof{}, Found{false}, Stale{true} {}
                found(const proof &p, bool x) : Proof{p}, Found{true}, Stale{x} {} 
            };
            
            found find(const share &x) const;
        
            void notify(const mining::notify::parameters& p) {
                if (p.Clean) Recent = set<byte_array<80>>{};
                Notifies.push(version_mask(), extranonce(), p);
                Extranonce = NextExtranonce;
                Difficulty = NextDifficulty;
            }
            
            state() {}
            state(const options &x) : Options{x} {}
            
        };
        
        state State{};
        
        mutable std::shared_mutex Mutex{};
        
    public:
        
        extensions::version_mask version_mask() const;
        
        // send a set_version_mask message to the client. 
        void set_version_mask(const extensions::version_mask& p);
        
        string username() const;
        
        Stratum::extranonce extranonce() const;
        
        // send a set_extranonce message to the client. 
        // this will not go into effect until the next 
        // notify message is sent. 
        void set_extranonce(const Stratum::extranonce &n);
        
        Stratum::difficulty difficulty() const;
        
        // send a set_difficulty message to the client. 
        // this will not go into effect until the next 
        // notify message is sent. 
        void set_difficulty(const Stratum::difficulty& d);
        
        // notify the client of a new job. 
        void notify(const mining::notify::parameters& p);
        
    private:
        
        // generate a configure response from a configure request message. 
        // this is the optional first method of the protocol. 
        mining::configure_response configure(const mining::configure_request &r);
        
        // authorize the client to the server. 
        mining::authorize_response authorize(const mining::authorize_request &r);
            
        // subscribe is when the client gets its
        // session id, which is also known as extra nonce 1. 
        mining::subscribe_response subscribe(const mining::subscribe_request &r);
        
        // empty return value for an accepted share. 
        optional<error> submit(const share &x);
        
        response respond(const Stratum::request &r);
        
        void handle_request(const Stratum::request &r) final override {
            this->send(respond(r));
        }
        
    public:
        server_session(tcp::socket &s, const options &x = {}) : remote{s}, State{x} {}
    };
    
    extensions::version_mask inline server_session::version_mask() const {
        std::shared_lock lock(Mutex);
        return State.version_mask();
    }
    
    string inline server_session::username() const {
        std::shared_lock lock(Mutex);
        return State.username();
    }
    
    Stratum::extranonce inline server_session::extranonce() const {
        std::shared_lock lock(Mutex);
        return State.extranonce();
    }
    
    void inline server_session::set_extranonce(const Stratum::extranonce &n) {
        std::unique_lock lock(Mutex);
        State.set_extranonce(n);
        this->send_notification(mining_set_extranonce, mining::set_extranonce::serialize(n));
    }
    
    Stratum::difficulty inline server_session::difficulty() const {
        std::shared_lock lock(Mutex);
        return State.difficulty();
    }
    
    void inline server_session::set_difficulty(const Stratum::difficulty& d) {
        std::unique_lock lock(Mutex);
        State.set_difficulty(d);
        this->send_notification(mining_set_difficulty, mining::set_difficulty::serialize(d));
    }
    
    void inline server_session::notify(const mining::notify::parameters& p) {
        std::shared_lock lock(Mutex);
        State.notify(p);
        this->send_notification(mining_notify, mining::notify::serialize(p));
    }
}

#endif
