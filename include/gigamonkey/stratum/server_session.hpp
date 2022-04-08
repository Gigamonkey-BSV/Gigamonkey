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
        
        // get_version is the only request that the server sends to the client.
        // It doesn't depend on state so can be sent at any time. 
        string get_version();
        
    private:
        
        // the state data of the protocol. 
        struct state {
        
            // Stratum clients sessions optionally first negotiate extensions and parameters, 
            // then authorize themselves with the server, and then get some ids from the server
            // with the subscribe method. Then they enter a mining loop until disconnection. 
            enum phase {
                initial, 
                configured, 
                authorized, 
                working 
            };
        
            phase Phase{initial};
        
            // Defines what extensions are supported by the server. 
            extensions::results ExtensionsSupported{};
            
            // Extensions requested by the client. 
            optional<extensions::requests> ExtensionsRequested{};
            
            // Extension parameters returned by the server. 
            extensions::results ExtensionsParameters{};
        
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
            optional<mining::subscribe_response::parameters> Subscriptions; 
            
            Stratum::extranonce extranonce() const {
                return (Subscriptions) ? Subscriptions->ExtraNonce : Stratum::extranonce{};
            }
        
            void set_extranonce(const Stratum::extranonce &n) {
                if (Phase != working) throw 0;
                Subscriptions->ExtraNonce = n;
            }
        
            optional<Stratum::difficulty> Difficulty;
        
            Stratum::difficulty difficulty() const {
                if (!Difficulty) return Stratum::difficulty{0};
                return *Difficulty;
            }
            
            void set_difficulty(const Stratum::difficulty& d) {
                if (Phase != working) throw 0;
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
            }
            
            state() {}
            state(const mining::configure_response::parameters &x) : ExtensionsSupported{x} {}
            
        };
        
        state State{};
        
        mutable std::shared_mutex Mutex{};
        
    public:
        
        state::phase phase() const;
        
        extensions::version_mask version_mask() const;
        
        void set_version_mask(const extensions::version_mask& p);
        
        string username() const;
        
        Stratum::extranonce extranonce() const;
        
        void set_extranonce(const Stratum::extranonce &n);
        
        Stratum::difficulty difficulty() const;
        
        void set_difficulty(const Stratum::difficulty& d);
        
        void notify(const mining::notify::parameters& p);
        
    private:
        
        // generate a configure response from a configure request message. 
        // this the optional first method of the protocol. 
        mining::configure_response configure(const mining::configure_request &r);
        
        // authorize the client to the server. 
        // this is the original first method of the protocol. 
        mining::authorize_response authorize(const mining::authorize_request &r);
            
        // subscribe is the 3rd or 2nd method and it is when the client gets its
        // session id, which is also known as extra nonce 1. 
        mining::subscribe_response subscribe(const mining::subscribe_request &r);
        
        uint32 min_time_difference;
        
        // empty return value for an accepted share. 
        optional<error> submit(const share &x);
        
        response respond(const Stratum::request &r);
        
        void handle_request(const Stratum::request &r) final override {
            this->send(respond(r));
        }
        
    public:
        server_session(tcp::socket &s) : remote{s}, State{} {}
        server_session(tcp::socket &s, const mining::configure_response::parameters &x) : remote{s}, State{x} {}
    };
    
    server_session::state::phase inline server_session::phase() const {
        std::shared_lock lock(Mutex);
        return State.Phase;
    }
    
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
