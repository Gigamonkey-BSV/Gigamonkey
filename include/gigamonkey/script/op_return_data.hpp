// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_OP_RETURN_DATA
#define GIGAMONKEY_SCRIPT_OP_RETURN_DATA

#include <gigamonkey/script.hpp>
#include "pattern.hpp"

namespace gigamonkey::bitcoin::script {
    
    struct op_return_data {
        static script::pattern pattern() {
            static script::pattern Pattern{optional{OP_FALSE}, OP_RETURN, repeated{push{}, 0}};
            return Pattern;
        }
        
        static bytes script(queue<bytes> push);
        
        queue<bytes> Push;
        bool Safe; // whether op_false is pushed before op_return
        bool Valid;
        
        bytes script() const {
            return script(Push);
        };
        
        op_return_data(bytes_view);
        op_return_data(queue<bytes> p) : Push{p}, Safe{true}, Valid{true} {}
    };
    
}

#endif


