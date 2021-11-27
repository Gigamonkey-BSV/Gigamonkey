// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_MINING_SET_VERSION_MASK
#define GIGAMONKEY_STRATUM_MINING_SET_VERSION_MASK

#include <gigamonkey/stratum/extensions.hpp>

namespace Gigamonkey::Stratum::mining {
    struct set_version_mask : notification {
        
        static Stratum::parameters serialize(const extensions::version_mask& d);
        
        static optional<extensions::version_mask> deserialize(const Stratum::parameters& p);
        
        using notification::notification;
        set_version_mask(extensions::version_mask d) : notification{mining_set_version_mask, serialize(d)} {} 
        
        static bool valid(const notification &n) {
            return n.valid() && n.method() == mining_set_version_mask && deserialize(n.params());
        }
        
        bool valid() const {
            return notification::valid() && deserialize(notification::params());
        }
        
        extensions::version_mask params() const {
            return *deserialize(notification::params());
        }
    };
    
    Stratum::parameters set_version_mask::serialize(const extensions::version_mask& d) {
        Stratum::parameters p;
        p.push_back(extensions::write_version_mask(d));
        return p;
    }
        
    optional<extensions::version_mask> set_version_mask::deserialize(const Stratum::parameters& p) {
        if (p.size() != 1 || !p[0].is_string()) return {};
        return extensions::read_version_mask(string(p[0]));
    }
}

#endif

