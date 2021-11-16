// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_P2P_VAR_INT
#define GIGAMONKEY_P2P_VAR_INT

#include <gigamonkey/types.hpp>

namespace Gigamonkey::Bitcoin {
    
    size_t inline var_int_size(uint64 x) {
        return x <= 0xfc ? 1 : x <= 0xffff ? 3 : x <= 0xffffffff ? 5 : 9;
    }
    
    uint64 read_var_int(reader &r);
    
    writer &write_var_int(writer &w, uint64 x);
    
    template <typename X>
    reader &read_sequence(reader &r, list<X>& l) {
        l = {};
        uint64 size = read_var_int(r);
        for (int i = 0; i < size; i++) {
            X x;
            r >> x;
            l = l << x;
        }
        return r;
    }
    
    template <typename X>
    writer &write_sequence(writer &w, list<X> l) {
        write_var_int(w, data::size(l)); 
        for (const X& x: l) w << x;
        return w;
    }
    
    reader &read_bytes(reader &r, bytes& b);
    
    writer inline &write_bytes(writer &w, const bytes& b) {
        return write_var_int(w, b.size()) << b;
    }
    
}

#endif 
