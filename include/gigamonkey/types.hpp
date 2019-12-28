// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_TYPES
#define GIGAMONKEY_TYPES

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

#include <data/data.hpp>

inline bool implies(bool a, bool b) {
    return (!a) || b;
}

namespace gigamonkey {
    
    using namespace data::exported;
    
    using endian = boost::endian::order;
    
    const endian BigEndian = boost::endian::order::big;
    const endian LittleEndian = boost::endian::order::little;
    
    constexpr inline endian opposite_endian(endian e) {
        return e == BigEndian ? LittleEndian : BigEndian;
    }
    
    using byte = std::uint8_t;
    using uint16_little = boost::endian::little_uint16_t;
    using uint32_little = boost::endian::little_uint32_t;
    using int32_little = boost::endian::little_uint32_t;
    using index = uint32_little;
    using uint24 = boost::endian::little_uint24_t;
    using uint64_little = boost::endian::little_uint64_t;
    using satoshi = uint64_little;
    
    using checksum = boost::endian::big_uint32_t;
    
    using uint32 = std::uint32_t;
    using uint64 = std::uint64_t;
    using int64 = std::uint64_t;
    
    using bytes = std::basic_string<byte>;
    using bytes_view = std::basic_string_view<byte>;
    
    using string = std::string;
    using string_view = std::string_view;
    
    template <size_t size, boost::endian::order e> 
    using uint = data::math::number::bounded<std::array<byte, size>, size, e, false>; 
    
    template <size_t size, boost::endian::order e> 
    using integer = data::math::number::bounded<std::array<byte, size>, size, e, true>;
    
    using N_bytes = data::math::number::N_bytes<LittleEndian>;
    using Z_bytes = data::math::number::Z_bytes<LittleEndian>;
    
    using N = data::math::number::gmp::N;
    using Z = data::math::number::gmp::Z;
    
    template <typename X>
    using vector = std::vector<X>;
    
    template <typename X>
    using ptr = std::shared_ptr<X>;
    
    template <size_t size>
    using slice = data::slice<byte, size>;
    
    using writer = data::writer<byte*>;
    using reader = data::reader<byte*>;
    
    template <typename ... P>
    inline bytes write(uint32 size, P... p) {
        return data::stream::write_bytes(size, p...);
    }
    
    writer write_var_int(writer, uint64);
    
    template <typename X> 
    writer write_list(writer w, list<X> l) {
        return data::fold([](writer w, X x)->writer{return w << x;}, write_var_int(w, data::size(l)), l);
    }
    
    writer write_bytes(writer w, bytes_view b) {
        return write_var_int(w, b.size()) << b;
    }
    
    namespace bitcoin {
        
        template <size_t size>
        using uint = gigamonkey::uint<size, LittleEndian>; 
        
        template <size_t size>
        using integer = gigamonkey::integer<size, LittleEndian>;
        
    }
    
}

#endif
