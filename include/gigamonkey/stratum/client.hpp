// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_CLIENT
#define GIGAMONKEY_STRATUM_CLIENT

#include <gigamonkey/stratum/remote.hpp>

namespace Gigamonkey::Stratum {
    
    struct client : remote {
        
        // If extensions are supported, the first message sent to the server is a configure request. 
        // if not, the first message is an authorize request. 
        // it is possible to support extensions in general without supporting any extensions. In this 
        // case we will send an empty configure request to the server. Otherwise 
        bool ExtensionsSupported;
        
        // extensions that theoretically can be supported. 
        optional<extensions::configuration_request<extensions::version_rolling>> VersionRollingRequest;
        optional<extensions::configuration_request<extensions::minimum_difficulty>> MinimumDifficultyRequest;
        optional<extensions::configuration_request<extensions::subscribe_extranonce>> SubscribeExtranonceRequest;
        optional<extensions::configuration_request<extensions::info>> InfoRequest;
        
        mining::configure_request::parameters requested_configuration() const;
        
        // responses returned by the server to a configuration request. 
        // this tells us about what extensions are actually supported by this connection. 
        optional<extensions::configuration_result<extensions::version_rolling>> VersionRollingResult;
        optional<extensions::configuration_result<extensions::minimum_difficulty>> MinimumDifficultyResult;
        optional<extensions::configuration_result<extensions::subscribe_extranonce>> SubscribeExtranonceResult;
        optional<extensions::configuration_result<extensions::info>> InfoResult;
        
        // This are the parameters of the authorize request that is sent to the server. This message is first
        // if extensions are not supported, second if they are. 
        mining::authorize_request::parameters Authorization;
        
        // the subscriptions that we will request from the server. 
        mining::subscribe_request::parameters RequestedSubscriptions;
        
        // After the authorize request comes the subscribe request. This contains the result that is returned
        // by the server. 
        optional<mining::subscribe_response::parameters> Subscriptions;
        
        void notify(const notification &) final override;
        
        void request(const Stratum::request &) final override;
        
        // After a subscribe request, we expect the server to tell is what difficulty we should use.
        optional<difficulty> Difficulty;
        
        client(
            tcp::socket &&s, 
            const mining::authorize_request::parameters& ap, 
            const mining::subscribe_request::parameters& sp) : remote{std::move(s)}, 
            ExtensionsSupported{false}, 
            Authorization{ap}, RequestedSubscriptions{sp} {}
        
        void add_supported_extension(extensions::configuration_request<extensions::version_rolling> ex) {
            if (VersionRollingRequest) throw std::logic_error{"version rolling extension parameters already set"};
            VersionRollingRequest = ex;
        }
        
        void add_supported_extension(extensions::configuration_request<extensions::minimum_difficulty> ex) {
            if (MinimumDifficultyRequest) throw std::logic_error{"minimum difficulty extension parameters already set"};
            MinimumDifficultyRequest = ex;
        }
        
        void add_supported_extension(extensions::configuration_request<extensions::subscribe_extranonce> ex) {
            if (SubscribeExtranonceRequest) throw std::logic_error{"subscribe extranonce extension parameters already set"};
            SubscribeExtranonceRequest = ex;
        }
        
        void add_supported_extension(extensions::configuration_request<extensions::info> ex) {
            if (InfoRequest) throw std::logic_error{"info extension parameters already set"};
            InfoRequest = ex;
        }
        
        void add_supported_extensions() {}
        
        template <typename extension, typename... extensions>
        void add_supported_extensions(extension x, extensions... xx) {
            add_supported_extension(x);
            add_supported_extensions(xx...);
        }
        
        template <typename... extens>
        client(
            tcp::socket &&s, 
            const mining::authorize_request::parameters& ap, 
            const mining::subscribe_request::parameters& sp, 
            extens... xx) : client{s, ap, sp} {
            ExtensionsSupported = true;
            add_supported_extensions(xx...);
        }
        
        ~client();
        
    };
    
}

#endif 
