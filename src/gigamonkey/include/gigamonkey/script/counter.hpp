// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_COUNTER
#define GIGAMONKEY_SCRIPT_COUNTER

#include <gigamonkey/script/instruction.hpp>

namespace Gigamonkey::Bitcoin {
    
    struct program_counter {

        bytes Script;
        cross<size_t> Jump;

        slice<const byte> Next;

        size_t Index;
        
        static byte_slice read_next_instruction (byte_slice subscript);
        
        program_counter () {}

        program_counter (const bytes &script, const cross<size_t> &jump);

        program_counter (const program_counter &);
        program_counter &operator = (const program_counter &);

        program_counter (program_counter &&);
        program_counter &operator = (program_counter &&);

        // pre-increment;
        program_counter &operator ++ () {
            Index = Index + Next.size ();
            Next = read_next_instruction (byte_slice (Script).drop (static_cast<int32> (Index)));
            return *this;
        }

        // post-increment
        program_counter operator ++ (int) {
            program_counter z = *this;
            ++*this;
            return z;
        }

        bool valid () const {
            return Next != byte_slice {};
        }

        program_counter &jump () {
            for (size_t j : Jump) if (j > Index) {
                Next = read_next_instruction (byte_slice (Script).drop (j));
                Index = j;
                return *this;
            }

            Index = Script.size ();
            Next = {};
            return *this;
        }
        
    private:
        program_counter (byte_slice n, byte_slice s, size_t c);
    };
    
    inline program_counter::program_counter (const bytes &script, const cross<size_t> &jump):
        Script {script}, Jump {jump}, Next {}, Index {0} {
        Next = read_next_instruction (Script);
    }

    inline program_counter::program_counter (const program_counter &p):
        Script {p.Script}, Jump {p.Jump},
        Next {Script.data () + (p.Next.data () - p.Script.data ()), p.Next.size ()}, Index {p.Index} {}

    program_counter inline &program_counter::operator = (const program_counter &p) {
        Script = p.Script;
        Jump = p.Jump;
        Next = byte_slice {p.Script.data () + (p.Next.data () - p.Script.data ()), p.Next.size ()};
        Index = p.Index;
        return *this;
    }

    inline program_counter::program_counter (program_counter &&p) {
        *this = std::move (p);
    }

    program_counter inline &program_counter::operator = (program_counter &&p) {
        Script = std::move (p.Script);
        Jump = std::move (p.Jump);
        Next = p.Next;
        Index = p.Index;
        return *this;
    }
}

#endif
