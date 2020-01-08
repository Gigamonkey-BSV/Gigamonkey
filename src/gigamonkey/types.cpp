// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/types.hpp>

namespace gigamonkey {
    
    bytes_writer write_var_int(bytes_writer, uint64) {
        throw data::method::unimplemented{"write_var_int"};
    }
    
    bytes_reader read_var_int(bytes_reader, uint64&) {
        throw data::method::unimplemented{"read_var_int"};
    }
    
    size_t var_int_size(uint64) {
        throw data::method::unimplemented{"var_int_size"};
    }
    
}
