// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_CLIENT_SHOW_MESSAGE
#define GIGAMONKEY_STRATUM_CLIENT_SHOW_MESSAGE

#include <gigamonkey/stratum/stratum.hpp>
#include <gigamonkey/stratum/difficulty.hpp>

namespace Gigamonkey::Stratum::client {
    struct show_message : notification {
        
        static Stratum::parameters serialize(const string& message) {
            Stratum::parameters p;
            p.push_back(message);
            return p;
        }
        
        static string deserialize(const Stratum::parameters& p) {
            if (p.size() != 1 || !p[0].is_string()) return string{};
            return p[0];
        }
        
        using notification::notification;
        show_message(string message) : notification{client_show_message, serialize(message)} {} 
        
        static bool valid(const notification &n) {
            return n.valid() && n.method() == client_show_message && n.params().size() == 1 && n.params()[0].is_string();
        }
        
        bool valid() const;
        
        string params() const {
            return notification::params()[0];
        }
    };
}

#endif

