// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_MINING_SET_EXTRANONCE
#define GIGAMONKEY_STRATUM_MINING_SET_EXTRANONCE

#include <gigamonkey/stratum/stratum.hpp>
#include <gigamonkey/stratum/mining.hpp>
#include <gigamonkey/stratum/session_id.hpp>

namespace Gigamonkey::Stratum::mining {
    struct set_extranonce : notification {
        using parameters = extranonce;
        
        static Stratum::parameters serialize(const parameters& p) {
            Stratum::parameters j;
            j.push_back(encoding::hex::fixed<4>(p.ExtraNonce1));
            j.push_back(p.ExtraNonce2Size);
            return j;
        } 
        
        static std::optional<parameters> deserialize(const Stratum::parameters& p) {
            if (p.size() != 2 || !p[0].is_string() || !p[1].is_number_unsigned()) return {};
            return parameters{session_id(encoding::hex::fixed<4>(p[0])), size_t(p[1])};
        }
        
        using notification::notification;
        set_extranonce(session_id extra_nonce_1, size_t extra_nonce_2_size); 
        
        static bool valid(const notification &n) {
            return n.valid() && n.method() == mining_set_extranonce && deserialize(n.params());
        }
        
        bool valid() const {
            return valid(*this);
        }
        
        parameters params() const {
            return *deserialize(notification::params());
        }
        
        friend std::ostream& operator<<(std::ostream&, const parameters &);
    };
}

#endif

