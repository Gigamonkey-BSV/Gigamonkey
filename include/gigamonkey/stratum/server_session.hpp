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

namespace Gigamonkey::Stratum {
    
    // this represents a server talking to a remote client. 
    class server_session : public remote {
        // empty return value means extensions are not supported. 
        virtual optional<mining::configure_response::parameters> configure(const mining::configure_request::parameters&) = 0;
        
        // empty return value for a successful authorization. 
        virtual optional<error> authorize(const mining::authorize_request::parameters&) = 0;
        
        virtual mining::subscribe_response::parameters subscribe(const mining::subscribe_request::parameters&) = 0;
        
        // empty return value for an accepted share. 
        virtual optional<error> submit(const share&) = 0;
        
        void handle_notification(const notification &n) final override {
            throw std::logic_error{string{"unknown notification received: "} + string(n)};
        }
        
        enum state {
            initial, 
            configured, 
            authorized, 
            working 
        };
        
        state State{initial};
        
        optional<mining::configure_response::parameters> SupportedExtensions;
        
        void handle_request(const Stratum::request &r) final override {
            switch (r.method()) {
                case mining_submit: {
                    if (!mining::submit_request::valid(r)) return this->send(response{r.id(), nullptr, error{ILLEGAL_PARARMS}});
                    if (State != working) {
                        error_code e = State == initial || State == configured ? UNAUTHORIZED : NOT_SUBSCRIBED;
                        return this->send(response{r.id(), nullptr, error{UNAUTHORIZED}});
                    }
                    return this->send(mining::submit_response{r.id(), submit(mining::submit_request::params(r))});
                }
                case mining_configure: {
                    if (!mining::configure_request::valid(r)) return this->send(response{r.id(), nullptr, error{ILLEGAL_PARARMS}});
                    if (State != initial) return this->send(response{r.id(), nullptr, error{ILLEGAL_METHOD}});
                    auto config = configure(mining::configure_request::params(r));
                    if (!config.has_value()) return this->send(response{r.id(), nullptr, error{ILLEGAL_METHOD}});
                    State = configured;
                    return this->send(mining::configure_response{r.id(), *config});
                }
                case mining_authorize: {
                    if (!mining::authorize_request::valid(r)) return this->send(response{r.id(), nullptr, error{ILLEGAL_PARARMS}});
                    if (State > configured) return this->send(response{r.id(), false, error{ILLEGAL_METHOD}});
                    auto authorization = authorize(mining::authorize_request::params(r));
                    if (!authorization.has_value()) State = authorized;
                    return this->send(mining::authorize_response{r.id(), authorization});
                }
                case mining_subscribe: {
                    if (!mining::subscribe_request::valid(r)) return this->send(response{r.id(), nullptr, error{ILLEGAL_PARARMS}});
                    if (State != authorized) {
                        error_code e = State < authorized || State == configured ? UNAUTHORIZED : ILLEGAL_METHOD;
                        return this->send(response{r.id(), nullptr, error{UNAUTHORIZED}});
                    }
                    return this->send(mining::subscribe_response{r.id(), subscribe(mining::subscribe_request::params(r))});
                }
                default : return this->send(response{r.id(), nullptr, error{ILLEGAL_METHOD}});
            }
            
        }
        
    public:
        string get_version() {
            response r = request(client_get_version, {});
            if (!client::get_version_response::valid(r)) 
                throw std::logic_error{string{"invalid get_version response received: "} + string(r)}; 
            return client::get_version_response{r}.result();
        }
        
    };
}

#endif
