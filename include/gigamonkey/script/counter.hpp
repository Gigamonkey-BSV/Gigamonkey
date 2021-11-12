// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_COUNTER
#define GIGAMONKEY_SCRIPT_COUNTER

#include <gigamonkey/script/script.hpp>
#include <gigamonkey/signature.hpp>

namespace Gigamonkey::Bitcoin::interpreter { 
    
    bytes find_and_delete(bytes_view script_code, bytes_view sig);
    
    struct program_counter {
        script Script;
        size_t Counter;
        size_t LastCodeSeparator;
        
        program_counter(const script &s) : Script{s}, Counter{0}, LastCodeSeparator{0} {}
        
        bytes_view next_instruction();
        
        bytes_view script_code() const {
            return bytes_view{Script.data() + LastCodeSeparator, Script.size() - LastCodeSeparator};
        }
    };
    
}

#endif
