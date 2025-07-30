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
        size_t Counter;
        size_t LastCodeSeparator;
        
        static slice<const byte> read_instruction (slice<const byte> subscript);
        
        program_counter () {}
        program_counter (slice<const byte> s);
        program_counter next () const;

        // the script code is the part of the script that gets signed.
        // normally this will be the locking script.
        program to_last_code_separator () const;

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
        program_counter (slice<const byte> n, slice<const byte> s, size_t c, size_t l);
    };
    

    inline program_counter::program_counter (slice<const byte> s):
        Next {read_instruction (s)}, Script {s}, Counter {0}, LastCodeSeparator {0} {}

    program_counter inline program_counter::next () const {
        size_t next_counter = Counter + Next.size ();
        return program_counter {read_instruction (
            Script.drop (static_cast<int32> (next_counter))), Script, next_counter,
            Next.size () > 0 && Next[0] == OP_CODESEPARATOR ? next_counter : LastCodeSeparator};
    }

    program inline program_counter::to_last_code_separator () const {
        return decompile (slice<const byte> {Script.data () + LastCodeSeparator, Script.size () - LastCodeSeparator});
    }

    inline program_counter::program_counter (slice<const byte> n, slice<const byte> s, size_t c, size_t l) :
        Next {n}, Script {s}, Counter {c}, LastCodeSeparator {l} {}
}

#endif
