// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_SESSION_ID
#define GIGAMONKEY_STRATUM_SESSION_ID

#include <gigamonkey/types.hpp>

namespace Gigamonkey::Stratum {
    struct session_id;
    
    void to_json(json& j, const session_id& p);
    bool from_json(const json& j, session_id& p);
    
    struct session_id : uint32_big {
        session_id();
        
        session_id(uint32 v);
        explicit session_id(uint32_big v);
        
        explicit session_id(encoding::hex::fixed<4> v);
        
        explicit operator encoding::hex::fixed<4>() const;
        
    };
    
    inline void to_json(json& j, const session_id& p) {
        j = encoding::hex::fixed<4>(p);
    } 
    
    inline bool from_json(const json& j, session_id& p) {
        p = {};
        if (!j.is_string()) return false;
        auto m = encoding::hex::fixed<4>(string(j));
        if (!m.valid()) return false;
        p = session_id{m};
        return true;
    }
    
    inline std::ostream& operator<<(std::ostream& o, const session_id id) {
        return o << data::encoding::hex::fixed<4>(id);
    }
    
    inline session_id::session_id() : uint32_big{0} {}
    
    inline session_id::session_id(uint32 v) : uint32_big{v} {}
    
    inline session_id::session_id(uint32_big v) : uint32_big{v} {}
    
    inline session_id::session_id(encoding::hex::fixed<4> v) : uint32_big{0} {
        encoding::hex::view x{v};
        if (x.valid()) std::copy(bytes_view(x).begin(), bytes_view(x).end(), uint32_big::begin());
    }
    
    inline session_id::operator encoding::hex::fixed<4>() const {
        return encoding::hex::write(*this, encoding::hex::lower);
    }

}

#endif
