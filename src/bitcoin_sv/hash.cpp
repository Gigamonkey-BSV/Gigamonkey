#include <gigamonkey/hash.hpp>
#include <hash.h>

#include "arith_uint256.h"

namespace Gigamonkey::Bitcoin {
    
    digest256 hash256(bytes_view b) {
        digest256 result;
        CHash256().Write(b.data(), b.size()).Finalize(result.Value.data());
        return result;
    } 
    
    digest160 hash160(bytes_view b) {
        digest160 result;
        CHash160().Write(b.data(), b.size()).Finalize(result.Value.data());
        return result;
    }

    digest256 hash256(string_view b) {
        return hash256(bytes_view((byte*)b.data(), b.size()));
    }
    
    digest160 hash160(string_view b) {
        return hash160(bytes_view((byte*)b.data(), b.size()));
    }
    
}


