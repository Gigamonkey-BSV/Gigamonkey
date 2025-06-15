// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/counter.hpp>

namespace Gigamonkey::Bitcoin {
    
    slice<const byte> program_counter::read_instruction (slice<const byte> subscript) {

        if (subscript.size () == 0) return slice<const byte> {};
        
        op Op = op (subscript[0]);

        if (!is_push_data (Op)) return slice<const byte> {subscript.data (), 1};
        
        if (Op <= OP_PUSHSIZE75) return slice<const byte> {subscript.data (), std::min (size_t (Op + 1), subscript.size ())};
        
        if (Op == OP_PUSHDATA1) {
            if (2 > subscript.size ()) return slice<const byte> {subscript.data (), subscript.size ()};
            
            byte size = subscript[1];
            
            if (2 + size > subscript.size ()) return slice<const byte> {subscript.data (), subscript.size ()};
            
            return slice<const byte> {subscript.data (), size_t (2) + size};
        }
        
        if (Op == OP_PUSHDATA2) {
            if (3 > subscript.size ()) return slice<const byte> {subscript.data (), subscript.size ()};
            
            uint16_little size;
            std::copy (subscript.begin () + 1, subscript.begin () + 3, size.begin ());
            
            if (3 + size > subscript.size ()) return slice<const byte> {subscript.data (), subscript.size ()};
            
            return slice<const byte> {subscript.data (), size_t (3) + size};
        }
        
        if (Op == OP_PUSHDATA4) {
            if (5 > subscript.size ()) return slice<const byte> {subscript.data (), subscript.size ()};
            
            uint32_little size;
            std::copy (subscript.begin () + 1, subscript.begin () + 5, size.begin ());
            
            if (5 + size > subscript.size ()) return slice<const byte> {subscript.data (), subscript.size ()};
            
            return slice<const byte> {subscript.data (), size_t (5) + size};
        }
        
        // should never happen
        return slice<const byte> {};
    }
    
    
}
