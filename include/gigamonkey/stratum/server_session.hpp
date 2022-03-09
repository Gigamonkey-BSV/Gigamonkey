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
        string get_version() {
            response r = request(client_get_version, {});
            if (!client::get_version_response::valid(r)) 
                throw std::logic_error{string{"invalid get_version response received: "} + string(r)}; 
            return client::get_version_response{r}.result();
        }
        
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
            mining::configure_response::parameters ExtensionsSupported;
            
            // Extensions requested by the client. 
            optional<mining::configure_request::parameters> ExtensionsRequested{};
            
            // Extension parameters returned by the server. 
            mining::configure_response::parameters ExtensionsParameters{};
        
            static extensions::configuration_result<extensions::version_rolling> make_version_mask(
                extensions::version_mask x, 
                const extensions::configuration_request<extensions::version_rolling> &r) {
                extensions::version_mask new_mask = x & r.Mask;
                int bit_count = 0;
                for (int i = 0; i < 32; i++) if (((new_mask >> i) & 1) == 1) bit_count++;
                
                return bit_count < r.MinBitCount ? 
                    extensions::configuration_result<extensions::version_rolling>{} : 
                    extensions::configuration_result<extensions::version_rolling>{new_mask};
            }
            
            // Extension version_rolling allows clients to use ASICBoost. Server and client agree
            // on a mask that says what bits of the version field the client is allowed to alter. 
            extensions::version_mask version_mask() const {
                auto mask = ExtensionsParameters.get<extensions::version_rolling>();
                if (!mask || !(*mask)) return 0;
                return **mask;
            }
            
            extensions::configuration_result<extensions::version_rolling> set_version_mask(extensions::version_mask x) {
                if (!ExtensionsRequested) return {};
                auto mask = ExtensionsParameters.get<extensions::version_rolling>();
                if (!mask) return {};
                
                auto requested = ExtensionsRequested->get<extensions::version_rolling>();
                if (!requested) return {};
                
                auto new_mask = make_version_mask(x, *requested);
                if (new_mask) ExtensionsParameters = ExtensionsParameters.add(new_mask);
                
                return new_mask;
            }
            
            mining::configure_response::parameters configure_result(
                const string &extension, 
                const mining::configure_response::parameters &parameters) {
                switch (extensions::extension_from_string(extension)) {
                    case extensions::version_rolling: {
                        auto mask = ExtensionsSupported.get<extensions::version_rolling>();
                        if (!mask || !(*mask)) return parameters.add(extensions::configuration_result<extensions::version_rolling>{});
                        
                        auto requested = ExtensionsRequested->get<extensions::version_rolling>();
                        return parameters.add(requested ? 
                            make_version_mask(**mask, *requested) : 
                            extensions::configuration_result<extensions::version_rolling>{});
                    } 
                    case extensions::minimum_difficulty: {
                        auto min_diff = ExtensionsSupported.get<extensions::minimum_difficulty>();
                        return parameters.add(min_diff ? *min_diff : extensions::configuration_result<extensions::minimum_difficulty>{});
                    } 
                    case extensions::subscribe_extranonce: {
                        auto sub_extn = ExtensionsSupported.get<extensions::subscribe_extranonce>();
                        return parameters.add(sub_extn ? *sub_extn : extensions::configuration_result<extensions::subscribe_extranonce>{});
                    } 
                    case extensions::info: {
                        auto info = ExtensionsSupported.get<extensions::info>();
                        return parameters.add(info ? *info : extensions::configuration_result<extensions::info>{}); 
                    } 
                    default: return parameters.add(extensions::configuration_result<extensions::unsupported>(extension));
                }
            }
            
            // empty return value means extensions are not supported. 
            optional<mining::configure_response::parameters> configure(const mining::configure_request::parameters& p) {
                if (!ExtensionsRequested) throw 0;
                
                ExtensionsRequested = p;
                
                if (!ExtensionsSupported.valid()) return {};
                
                for (const string &supported : p.Supported) ExtensionsParameters = configure_result(supported, ExtensionsParameters);
                
                return ExtensionsParameters;
            } 
            
            // The user name of the worker. 
            // Set during the authorize method. 
            optional<string> Name{};
        
            string username() const {
                if (Name.has_value()) return *Name;
                return "";
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
                if (!Difficulty) return 0;
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
            
            found find(const share &x) const {
                bool stale = false;
                for (auto n = Notifies.Notifications.begin(); n != Notifies.Notifications.end(); n++) {
                    if (n->Notification.ID == x.JobID) 
                        return {proof{worker(username(), n->ExtraNonce, n->Mask), n->Notification, x}, stale};
                    if (n->Notification.Clean) stale = true;
                }
                
                return {};
            }
        
            void notify(const mining::notify::parameters& p) {
                if (p.Clean) Recent = set<byte_array<80>>{};
                Notifies.push(version_mask(), extranonce(), p);
            }
            
            state() : ExtensionsSupported{} {}
            state(const mining::configure_response::parameters &x) : ExtensionsSupported{x} {}
            
        };
        
        state State{};
        
        mutable std::shared_mutex Mutex{};
        
    public:
        
        state::phase phase() const {
            std::shared_lock lock(Mutex);
            return State.Phase;
        }
        
        extensions::version_mask version_mask() const {
            std::shared_lock lock(Mutex);
            return State.version_mask();
        }
        
        void set_version_mask(const extensions::version_mask& p) {
            std::unique_lock lock(Mutex);
            if (State.Phase != state::working) throw 0;
            extensions::configuration_result<extensions::version_rolling> new_mask = State.set_version_mask(p);
            if (!new_mask) return;
            this->send_notification(mining_set_version_mask, mining::set_version_mask::serialize(*new_mask));
        }
        
        string username() const {
            std::shared_lock lock(Mutex);
            return State.username();
        }
        
        Stratum::extranonce extranonce() const {
            std::shared_lock lock(Mutex);
            return State.extranonce();
        }
        
        void set_extranonce(const Stratum::extranonce &n) {
            std::unique_lock lock(Mutex);
            State.set_extranonce(n);
            this->send_notification(mining_set_extranonce, mining::set_extranonce::serialize(n));
        }
        
        Stratum::difficulty difficulty() const {
            std::shared_lock lock(Mutex);
            return State.difficulty();
        }
        
        void set_difficulty(const Stratum::difficulty& d) {
            std::unique_lock lock(Mutex);
            State.set_difficulty(d);
            this->send_notification(mining_set_difficulty, mining::set_difficulty::serialize(d));
        }
        
        void notify(const mining::notify::parameters& p) {
            std::shared_lock lock(Mutex);
            State.notify(p);
            this->send_notification(mining_notify, mining::notify::serialize(p));
        }
        
    private:
        
        // generate a configure response from a configure request message. 
        // this the optional first method of the protocol. 
        mining::configure_response configure(const mining::configure_request &r) {
            std::unique_lock lock(Mutex);
            if (!r.valid()) response{r.id(), nullptr, error{ILLEGAL_PARARMS}};
            if (State.Phase != state::initial) return response{r.id(), nullptr, error{ILLEGAL_METHOD}};
            auto config = State.configure(r.params());
            if (!config.has_value()) return response{r.id(), nullptr, error{ILLEGAL_METHOD}};
            State.Phase = state::configured;
            return mining::configure_response{r.id(), *config};
        }
        
        // authorize the client to the server. 
        // this is the original first method of the protocol. 
        mining::authorize_response authorize(const mining::authorize_request &r) {
            std::unique_lock lock(Mutex);
            if (!r.valid()) return response{r.id(), nullptr, error{ILLEGAL_PARARMS}};
            if (State.Phase > state::configured) return response{r.id(), false, error{ILLEGAL_METHOD}};
            State.Name = r.params().Username;
            auto authorization = authorize(r.params());
            if (!authorization.has_value()) State.Phase = state::authorized;
            return mining::authorize_response{r.id(), authorization};
        }
            
        // subscribe is the 3rd or 2nd method and it is when the client gets its
        // session id, which is also known as extra nonce 1. 
        mining::subscribe_response subscribe(const mining::subscribe_request &r) {
            std::unique_lock lock(Mutex);
            if (!r.valid()) return response{r.id(), nullptr, error{ILLEGAL_PARARMS}};
            if (State.Phase != state::authorized) {
                error_code e = State.Phase < state::authorized || State.Phase == state::configured ? UNAUTHORIZED : ILLEGAL_METHOD;
                return response{r.id(), nullptr, error{UNAUTHORIZED}};
            }
            State.Subscriptions = subscribe(mining::subscribe_request::params(r));
            return mining::subscribe_response{r.id(), *State.Subscriptions};
        }
        
        uint32 min_time_difference;
        
        // empty return value for an accepted share. 
        optional<error> submit(const share &x) {
            auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
            
            if (now - uint32(x.Share.Timestamp) > min_time_difference) return error{TIME_TOO_OLD};
            if (uint32(x.Share.Timestamp) - now> min_time_difference) return error{TIME_TOO_NEW};
            
            state::found f = State.find(x);
            if (!f.Found) return error{JOB_NOT_FOUND};
            if (f.Stale) return error{STALE_SHARE};
            
            byte_array<80> string = work::proof(f.Proof).string().write();
            
            if (State.Recent.contains(string)) return error{DUPLICATE_SHARE};
            State.Recent = State.Recent.insert(string);
            
            if (!f.Proof.valid(State.difficulty())) return error{LOW_DIFFICULTY};
            payment(State.username(), State.difficulty());
            if (f.Proof.valid()) solution(f.Proof);
            
            return {};
        }
        
        response respond(const Stratum::request &r) {
            switch (r.method()) {
                case mining_submit: {
                    if (!mining::submit_request::valid(r)) return response{r.id(), nullptr, error{ILLEGAL_PARARMS}};
                    if (State.Phase != state::working) {
                        error_code e = State.Phase == state::initial || State.Phase == state::configured ? UNAUTHORIZED : NOT_SUBSCRIBED;
                        return response{r.id(), nullptr, error{UNAUTHORIZED}};
                    }
                    return mining::submit_response{r.id(), submit(mining::submit_request::params(r))};
                }
                case mining_configure: return configure(mining::configure_request{r});
                case mining_authorize: return authorize(mining::authorize_request{r});
                case mining_subscribe: return subscribe(mining::subscribe_request{r});
                default : return response{r.id(), nullptr, error{ILLEGAL_METHOD}};
            }
        }
        
        void handle_request(const Stratum::request &r) final override {
            this->send(respond(r));
        }
        
    public:
        server_session(tcp::socket &s) : remote{s}, State{} {}
        server_session(tcp::socket &s, const mining::configure_response::parameters &x) : remote{s}, State{x} {}
    };
}

#endif
