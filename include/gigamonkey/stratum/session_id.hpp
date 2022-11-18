// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_SESSION_ID
#define GIGAMONKEY_STRATUM_SESSION_ID

#include <gigamonkey/types.hpp>

namespace Gigamonkey::Stratum {
    struct session_id;
    
    struct session_id : uint32_big {
        session_id();
        
        session_id(uint32 v);
        explicit session_id(uint32_big v);
        
        explicit session_id(encoding::hex::fixed<4> v);
        
        explicit operator encoding::hex::fixed<4>() const;
        
        static JSON serialize(const session_id& p) {
            return JSON::string_t{encoding::hex::fixed<4>(p)};
        }
        
        static std::optional<session_id> deserialize(const JSON& j) {
            session_id p = {};
            if (!j.is_string()) return {};
            auto m = encoding::hex::fixed<4>(string(j));
            if (!m.valid()) return {};
            p = session_id{m};
            return p;
        }
        
    };
    
    inline std::ostream& operator<<(std::ostream& o, const session_id id) {
        return o << data::encoding::hex::fixed<4>(id);
    }
    
    inline session_id::session_id() : uint32_big{0} {}
    
    inline session_id::session_id(uint32 v) : uint32_big{v} {}
    
    inline session_id::session_id(uint32_big v) : uint32_big{v} {}
    
    inline session_id::session_id(encoding::hex::fixed<4> v) : uint32_big{0} {
        ptr<bytes> x = encoding::hex::read(v);
        if (x != nullptr) std::copy(x->begin(), x->end(), uint32_big::begin());
    }
    
    inline session_id::operator encoding::hex::fixed<4>() const {
        return encoding::hex::write(*this, encoding::hex::lower);
    }

}

#endif
