// Copyright (c) 2019-2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script.hpp>
#include "script/interpreter.h"

namespace Gigamonkey::Bitcoin {
    
    evaluated evaluate_script(script in, script out) {
        throw data::method::unimplemented{"evaluate_script"}; // TODO
    }
    
    evaluated evaluate_script(script in, script out, bytes transaction) {
        throw data::method::unimplemented{"evaluate_script"}; // TODO
    }

}
