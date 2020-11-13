// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_SESSION_ID
#define GIGAMONKEY_STRATUM_SESSION_ID

#include <gigamonkey/types.hpp>

namespace Gigamonkey::Stratum {
    struct session_id;
    
    bool operator==(const session_id a, const session_id b);
    bool operator!=(const session_id a, const session_id b);
    
    void to_json(json& j, const session_id& p);
    void from_json(const json& j, session_id& p);
    
    std::ostream& operator<<(std::ostream& o, const session_id id);
    
    struct session_id {
        uint32_little Value;
        bool Valid;
        session_id();
        
        session_id(uint32 v);
        explicit session_id(uint32_little v);
        
        explicit session_id(encoding::hex::fixed<4> v);
        
        explicit operator encoding::hex::fixed<4>() const;
        
    };
    
    inline bool operator==(const session_id a, const session_id b) {
        return a.Value == b.Value && a.Valid == b.Valid;
    }
    
    inline bool operator!=(const session_id a, const session_id b) {
        return a.Value != b.Value || a.Valid != b.Valid;
    }
    
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
    
    inline session_id::session_id() : Value{0}, Valid{false} {}
    
    inline session_id::session_id(uint32 v) : Value{v}, Valid{true} {}
    
    inline session_id::session_id(uint32_little v) : Value{v}, Valid{true} {}
    
    inline session_id::session_id(encoding::hex::fixed<4> v) : Value{0}, Valid{true} {
        encoding::hex::view x{v};
        if (x.valid()) std::copy(bytes_view(x).begin(), bytes_view(x).end(), Value.begin());
    }
    
    inline session_id::operator encoding::hex::fixed<4>() const {
        return encoding::hex::write(Value, encoding::hex::lower);
    }

}

#endif
