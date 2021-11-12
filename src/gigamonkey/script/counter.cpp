// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/counter.hpp>

namespace Gigamonkey::Bitcoin::interpreter { 
    
    bytes find_and_delete(bytes_view script_code, bytes_view instruction) {
        program_counter p{script_code};
        bytes r(script_code.size());
        bytes_writer w{r.begin(), r.end()};
        int bytes_written = 0;
        while (true) {
            bytes_view next = p.next_instruction();
            if (next == bytes_view{}) break;
            if (next == instruction) continue;
            w << next;
            bytes_written += next.size();
        }
        r.resize(bytes_written);
        return r;
    }
    
    bytes_view program_counter::next_instruction() {
        if (Counter == Script.size()) return bytes_view{};
        
        auto last = Counter;
        
        op Op = op(Script[Counter]);
        
        if (!is_push_data(Op)) {
            Counter++;
            if (Op == OP_CODESEPARATOR) LastCodeSeparator = Counter;
            return bytes_view{Script.data() + last, 1};
        }
        
        if (Op <= OP_PUSHSIZE75) {
            size_t size = std::min(size_t(Op + 1), Script.size() - last);
            Counter += size;
            return bytes_view{Script.data() + last, size};
        }
        
        if (Op == OP_PUSHDATA1) {
            if (Counter + 2 > Script.size()) {
                Counter = Script.size();
                return bytes_view{Script.data() + Counter, 1};
            }
            
            byte size = Script[Counter + 1];
            
            if (Counter + 2 + size > Script.size()) {
                Counter = Script.size();
                return bytes_view{Script.data() + Counter, 2};
            }
            
            Counter += 2 + size;
            return bytes_view{Script.data() + last, size_t(2) + size};
        }
        
        if (Op == OP_PUSHDATA2) {
            if (Counter + 3 > Script.size()) {
                Counter = Script.size();
                return bytes_view{Script.data() + Counter, 1};
            }
            
            uint16_little size;
            std::copy(Script.begin() + Counter + 1, Script.begin() + Counter + 3, size.begin());
            
            if (Counter + 3 + size > Script.size()) {
                Counter = Script.size();
                return bytes_view{Script.data() + Counter, 3};
            }
            
            Counter += 3 + size;
            return bytes_view{Script.data() + last, size_t(3) + size};
        }
        
        if (Op == OP_PUSHDATA4) {
            if (Counter + 5 > Script.size()) {
                Counter = Script.size();
                return bytes_view{Script.data() + Counter, 1};
            }
            
            uint32_little size;
            std::copy(Script.begin() + Counter + 1, Script.begin() + Counter + 5, size.begin());
            
            if (Counter + 4 + size > Script.size()) {
                Counter = Script.size();
                return bytes_view{Script.data() + Counter, 5};
            }
            
            Counter += 5 + size;
            return bytes_view{Script.data() + last, size_t(5) + size};
        }
        
        // should never happen
        return bytes_view{};
    }
    
}
