// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef BITCOIN_TYPES
#define BITCOIN_TYPES

#include <string>
#include <string_view>
#include <array>

#include <data/stream.hpp>

#include <boost/endian/arithmetic.hpp>

#include <data/math/number/bounded/bounded.hpp>

#include <data/math/number/bytes/N.hpp>
#include <data/math/number/bytes/Z.hpp>

#include <data/math/number/gmp/N.hpp>
#include <data/math/number/gmp/Z.hpp>

inline bool implies(bool a, bool b) {
    return (!a) || b;
}

namespace gigamonkey {
    
    const boost::endian::order big_endian = boost::endian::order::big;
    const boost::endian::order little_endian = boost::endian::order::little;
    
    using byte = std::uint8_t;
    using uint32_little = boost::endian::little_uint32_t;
    using index = uint32_little;
    using uint24 = boost::endian::little_uint24_t;
    using satoshi = boost::endian::little_uint64_t;
    
    using checksum = boost::endian::big_uint32_t;
    
    using uint32 = std::uint32_t;
    using uint64 = std::uint64_t;
    
    using bytes = std::basic_string<byte>;
    using bytes_view = std::basic_string_view<byte>;
    
    using string = std::string;
    using string_view = std::string_view;
    
    template <size_t size, boost::endian::order o> 
    using uint = math::number::bounded<std::array<byte, size>, size, o, false>; 
    
    template <size_t size, boost::endian::order o> 
    using integer = math::number::bounded<std::array<byte, size>, size, o, true>;
    
    using N_bytes = data::math::number::N_bytes<little_endian>;
    using Z_bytes = data::math::number::Z_bytes<little_endian>;
    
    using N = data::math::number::gmp::N;
    using Z = data::math::number::gmp::Z;
    
    using signature = N_bytes;
    
    using writer = data::writer<byte*>;
    using reader = data::writer<byte*>;
    
    template <typename ... P>
    inline bytes write(uint32 size, P... p) {
        return data::stream::write_bytes(size, p...);
    }
    
    namespace bitcoin {
        
        template <typename size>
        using uint = gigamonkey::uint<size, little_endian>; 
        
        template <typename size>
        using integer = gigamonkey::integer<size, little_endian>;
        
    }
    
}

#endif
