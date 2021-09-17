// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_MINING_SET_DIFFICULTY
#define GIGAMONKEY_STRATUM_MINING_SET_DIFFICULTY

#include <gigamonkey/stratum/stratum.hpp>
#include <gigamonkey/stratum/difficulty.hpp>

namespace Gigamonkey::Stratum::mining {
    struct set_difficulty : notification {
        
        static Stratum::parameters serialize(const difficulty& d) {
            Stratum::parameters p;
            p.push_back(d);
            return p;
        }
        
        static difficulty deserialize(const Stratum::parameters& p) {
            if (p.size() != 1 || !p[0].is_number_unsigned()) return difficulty{};
            return difficulty{uint64(p[0])};
        }
        
        using notification::notification;
        set_difficulty(difficulty d) : notification{mining_set_difficulty, serialize(d)} {} 
        
        bool valid() const {
            return notification::valid() && deserialize(notification::params()).valid();
        }
        
        difficulty params() const {
            return deserialize(notification::params());
        }
    };
}

#endif
