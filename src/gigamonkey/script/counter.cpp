// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/counter.hpp>

namespace Gigamonkey::Bitcoin {
    
    bytes find_and_delete (bytes_view script_code, bytes_view instruction) {
        program_counter p {script_code};
        bytes r (script_code.size ());
        iterator_writer w {r.begin (), r.end ()};
        int bytes_written = 0;

        while (true) {
            bytes_view next = p.Next;
            if (next == bytes_view {}) break;
            p = p.next ();
            if (next == instruction) continue;
            w << next;
            bytes_written += next.size ();
        }

        r.resize (bytes_written);
        return r;
    }
    
    bytes_view program_counter::read_instruction (bytes_view subscript) {
        if (subscript.size () == 0) return bytes_view {};
        
        op Op = op (subscript[0]);
        
        if (!is_push_data (Op)) return bytes_view {subscript.data (), 1};
        
        if (Op <= OP_PUSHSIZE75) return bytes_view {subscript.data (), std::min (size_t (Op + 1), subscript.size ())};
        
        if (Op == OP_PUSHDATA1) {
            if (2 > subscript.size ()) return bytes_view {subscript.data (), subscript.size ()};
            
            byte size = subscript[1];
            
            if (2 + size > subscript.size ()) return bytes_view {subscript.data (), subscript.size ()};
            
            return bytes_view {subscript.data (), size_t (2) + size};
        }
        
        if (Op == OP_PUSHDATA2) {
            if (3 > subscript.size ()) return bytes_view {subscript.data (), subscript.size ()};
            
            uint16_little size;
            std::copy (subscript.begin () + 1, subscript.begin () + 3, size.begin ());
            
            if (3 + size > subscript.size ()) return bytes_view {subscript.data (), subscript.size ()};
            
            return bytes_view {subscript.data (), size_t (3) + size};
        }
        
        if (Op == OP_PUSHDATA4) {
            if (5 > subscript.size ()) return bytes_view {subscript.data (), subscript.size ()};
            
            uint32_little size;
            std::copy (subscript.begin () + 1, subscript.begin () + 5, size.begin ());
            
            if (5 + size > subscript.size ()) return bytes_view {subscript.data (), 5};
            
            return bytes_view {subscript.data (), size_t (5) + size};
        }
        
        // should never happen
        return bytes_view {};
    }
    
    
}
