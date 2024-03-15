// Copyright (c) 2019-2022 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_PATTERN_OP_RETURN
#define GIGAMONKEY_SCRIPT_PATTERN_OP_RETURN

#include <gigamonkey/script/pattern.hpp>

namespace Gigamonkey {
    
    // create and read an OP_RETURN script. 
    struct op_return {
        enum type {
            unsafe, 
            safe, 
            either
        };
        
        static Gigamonkey::pattern pattern (type t = either) {
            static Gigamonkey::pattern Either {optional {OP_FALSE}, op_return_data {}};
            static Gigamonkey::pattern Unsafe {op_return_data {}};
            static Gigamonkey::pattern Safe {OP_FALSE, op_return_data {}};
            switch (t) {
                case unsafe: return Unsafe;
                case safe: return Safe;
                case either: return Either;
            }
        }
        
        static Gigamonkey::script script (const bytes_view data, bool safe_script = true) {
            using namespace Bitcoin;
            return compile (safe_script ? 
                program {OP_FALSE, instruction::op_return_data (data)} : 
                program {instruction::op_return_data (data)});
        }
        
        static bool match (const bytes_view p) {
            return (p.size () > 1 && p[0] == 0x6a) || (p.size () > 2 && p[0] == 0x00 && p[1] == 0x6a);
        }
        
        bytes Data;
        bool Safe; // whether op_false is pushed before op_return
        
        bytes script () const {
            return script (Data, Safe);
        };
        
        Bitcoin::output output () const {
            return Bitcoin::output {0, script (Data, Safe)};
        }
        
        op_return (bytes_view b, bool safe_script = true) : Data {b}, Safe {safe} {}
    };
} 

#endif
