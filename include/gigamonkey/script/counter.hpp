// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_COUNTER
#define GIGAMONKEY_SCRIPT_COUNTER

#include <gigamonkey/script/script.hpp>
#include <gigamonkey/signature.hpp>

namespace Gigamonkey::Bitcoin::interpreter { 
    
    bytes find_and_delete(bytes_view script_code, bytes_view sig);
    
    struct program_counter {
        bytes_view Next;
        bytes_view Script;
        size_t Counter;
        size_t LastCodeSeparator;
        
        static bytes_view read_instruction(bytes_view subscript);
        
        program_counter(bytes_view s): 
            Next{read_instruction(s)}, Script{s}, Counter{0}, LastCodeSeparator{0} {}
        
        program_counter next() const {
            size_t next_counter = Counter + Next.size();
            return program_counter{
                read_instruction(Script.substr(next_counter)), 
                Script, next_counter, 
                Next.size() > 0 && Next[0] == OP_CODESEPARATOR ? next_counter : LastCodeSeparator};
        }
        
        bytes_view script_code() const {
            return bytes_view{Script.data() + LastCodeSeparator, Script.size() - LastCodeSeparator};
        }
        
    private:
        program_counter(bytes_view n, bytes_view s, size_t c, size_t l) : 
            Next{n}, Script{s}, Counter{c}, LastCodeSeparator{l} {}
    };
    
}

#endif
