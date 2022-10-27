// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_DIFFICULTY
#define GIGAMONKEY_STRATUM_DIFFICULTY

#include <gigamonkey/work/target.hpp>

namespace Gigamonkey::Stratum {
    
    // Stratum difficulty can be a JSON integer or a JSON floating point. 
    struct difficulty : JSON {
        
        difficulty() : JSON() {}
        explicit difficulty(const uint64& d) : JSON(JSON::number_unsigned_t{d}) {}
        explicit difficulty(const work::compact& t) : difficulty{t.difficulty()} {}
        explicit difficulty(const work::difficulty& d) : JSON(JSON::number_float_t{double(d)}) {}
        
        explicit operator work::difficulty() const;
        
        bool valid() const;

    };
    
    inline difficulty::operator work::difficulty() const {
        return work::difficulty{double(*this)};
    }
    
    bool inline difficulty::valid() const {
        return (JSON::is_number_float() && double(*this) > 0) || (JSON::is_number_unsigned() && uint64(*this) > 0);
    }
    
}

#endif
