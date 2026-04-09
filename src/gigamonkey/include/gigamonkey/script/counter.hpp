// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_COUNTER
#define GIGAMONKEY_SCRIPT_COUNTER

#include <gigamonkey/script/instruction.hpp>
#include <gigamonkey/signature.hpp>

namespace Gigamonkey::Bitcoin {
    
    struct program_counter {

        slice<const byte> Next;
        slice<const byte> Script;
        size_t Index;
        
        static slice<const byte> read_instruction (slice<const byte> subscript);
        
        program_counter () {}
        program_counter (slice<const byte> s);
        program_counter next () const;

        // pre-increment;
        program_counter &operator ++ () {
            return *this = next ();
        }

        // post-increment
        program_counter operator ++ (int) {
            program_counter z = *this;
            *this = next ();
            return z;
        }
        
    private:
        program_counter (slice<const byte> n, slice<const byte> s, size_t c);
    };
    

    inline program_counter::program_counter (slice<const byte> s):
        Next {read_instruction (s)}, Script {s}, Index {0} {}

    program_counter inline program_counter::next () const {
        size_t next_counter = Index + Next.size ();
        return program_counter {read_instruction (
            Script.drop (static_cast<int32> (next_counter))), Script, next_counter};
    }

    inline program_counter::program_counter (slice<const byte> n, slice<const byte> s, size_t c) :
        Next {n}, Script {s}, Index {c} {}
}

#endif
