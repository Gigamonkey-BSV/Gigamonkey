// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_P2P_VAR_INT
#define GIGAMONKEY_P2P_VAR_INT

#include <gigamonkey/types.hpp>

namespace Gigamonkey::Bitcoin {
    
    size_t inline var_int_size(uint64 x) {
        return x <= 0xfc ? 1 : x <= 0xffff ? 3 : x <= 0xffffffff ? 5 : 9;
    }
    
    template <typename reader>
    uint64 read_var_int(reader &r) {
        byte b;
        r >> b;
        if (b <= 0xfc) {
            return b;
        } 
        
        if (b == 0xfd) {
            uint16_little n;
            r >> n;
            return uint16(n);
        } 
        
        if (b == 0xfe) {
            uint32_little n;
            r >> n;
            return uint32(n);
        } 
        
        uint64_little n;
        r >> n;
        return uint64(n);
    }
    
    template <typename writer>
    writer &write_var_int(writer &w, uint64 x) {        
        if (x <= 0xfc) return w << static_cast<byte>(x);
        else if (x <= 0xffff) return w << byte(0xfd) << uint16_little{static_cast<uint16>(x)};
        else if (x <= 0xffffffff) return w << byte(0xfe) << uint32_little{static_cast<uint32>(x)};
        else return w << byte(0xff) << uint64_little{x};
    }
    
    template <typename reader, typename X>
    reader &read_sequence(reader &r, list<X>& l) {
        l = {};
        uint64 size = read_var_int(r);
        for (int i = 0; i < size; i++) {
            X x;
            X::read(r, x);
            l = l << x;
        }
        return r;
    }
    
    template <typename writer, typename X>
    writer &write_sequence(writer &w, list<X> l) {
        write_var_int(w, data::size(l)); 
        for (const X& x: l) X::write(w, x);
        return w;
    }
    
    template <typename reader>
    reader &read_bytes(reader &r, bytes& b) {
        b = {};
        uint64 size = read_var_int(r);
        b.resize(size);
        for (int i = 0; i < size; i++) r >> b[i];
        return r;
    }
    
    template <typename writer>
    writer inline &write_bytes(writer &w, const bytes& b) {
        return write_var_int(w, b.size()) << b;
    }
    
}

#endif 
