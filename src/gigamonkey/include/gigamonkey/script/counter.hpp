// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_COUNTER
#define GIGAMONKEY_SCRIPT_COUNTER

#include <gigamonkey/script/instruction.hpp>
#include <gigamonkey/signature.hpp>

namespace Gigamonkey::Bitcoin {
    
    struct program_counter {

        byte_slice Next;
        byte_slice Script;
        size_t Index;
        
        static byte_slice read_instruction (byte_slice subscript);
        
        program_counter () {}
        program_counter (byte_slice s);
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

        bool valid () const {
            return Next != byte_slice {};
        }
        
    private:
        program_counter (byte_slice n, byte_slice s, size_t c);
    };
    

    inline program_counter::program_counter (byte_slice s):
        Next {read_instruction (s)}, Script {s}, Index {0} {}

    program_counter inline program_counter::next () const {
        size_t next_counter = Index + Next.size ();
        return program_counter {read_instruction (
            Script.drop (static_cast<int32> (next_counter))), Script, next_counter};
    }

    inline program_counter::program_counter (byte_slice n, byte_slice s, size_t c) :
        Next {n}, Script {s}, Index {c} {}
}

#endif
