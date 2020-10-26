// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_SESSION_ID
#define GIGAMONKEY_STRATUM_SESSION_ID

#include <gigamonkey/types.hpp>

namespace Gigamonkey::Stratum {
    struct session_id {
        uint32_little Value;
        session_id() : Value{0} {}
        
        session_id(uint32 v) : Value{v} {}
        session_id(uint32_little v) : Value{v} {}
        
        explicit session_id(encoding::hex::fixed<4> v) : Value{0} {
            encoding::hex::view x{v};
            if (x.valid()) std::copy(bytes_view(x).begin(), bytes_view(x).end(), Value.begin());
        }
        
        explicit operator encoding::hex::fixed<4>() const {
            return encoding::hex::write(Value, encoding::hex::lower);
        }
        
        bool operator==(const session_id id) const {
            return Value == id.Value;
        }
        
        bool operator!=(const session_id id) const {
            return Value != id.Value;
        }
        
    };
    
    inline void to_json(json& j, const session_id& p) {
        j = encoding::hex::fixed<4>(p);
    } 
    
    inline void from_json(const json& j, session_id& p) {
        if (!j.is_string()) p = {};
        p = session_id{encoding::hex::fixed<4>(string(j))};
    }
    
    inline std::ostream& operator<<(std::ostream& o, const session_id id) {
        return o << data::encoding::hex::fixed<4>(id);
    }

}

#endif
