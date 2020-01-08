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
    using uint24_little = boost::endian::little_uint24_t;
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
    
    using bytes_writer = data::writer<bytes::iterator>;
    using bytes_reader = data::reader<const byte*>;
    
    using string_writer = data::writer<string::iterator>;
    using string_reader = data::reader<const char*>;
    
    template <typename X>
    inline data::reader<typename X::iterator> reader(const X& x) {
        return {x.begin(), x.end()};
    }
    
    template <typename X>
    inline data::writer<typename X::iterator> writer(X& x) {
        return {x.begin(), x.end()};
    }
    
    template <typename ... P>
    inline bytes write(uint32 size, P... p) {
        return data::stream::write_bytes(size, p...);
    }
    
    struct timestamp {
        int32_little Timestamp;
        
        timestamp(uint32_little t) : Timestamp{t} {}
        timestamp(string_view s) : timestamp{read(s)} {}
        timestamp() : Timestamp{} {}
        
        bool operator==(const timestamp& t) const;
        bool operator!=(const timestamp& t) const;
        bool operator<(const timestamp&) const;
        bool operator>(const timestamp&) const;
        bool operator<=(const timestamp&) const;
        bool operator>=(const timestamp&) const;
        
        string_writer write(string_writer) const;
        string write() const;
        
        bytes_writer write(bytes_writer w) const {
            return w << Timestamp;
        }
        
        static timestamp read(string_view);
    };
    
    bytes_writer write_var_int(bytes_writer, uint64);
    
    bytes_reader read_var_int(bytes_reader, uint64&);
    
    size_t var_int_size(uint64);
    
    inline bytes_writer write_data(bytes_writer w, bytes_view b) {
        return write_var_int(w, b.size()) << b;
    }
    
    inline bytes_reader read_data(bytes_reader r, bytes& b) {
        uint64 size;
        r = read_var_int(r, size);
        b.resize(size);
        return r >> b;
    }
    
    template <typename X> 
    inline bytes_writer write_list(bytes_writer w, queue<X> l) {
        return data::fold([](bytes_writer w, X x)->bytes_writer{return w << x;}, write_var_int(w, data::size(l)), l);
    }
    
    template <typename X> 
    bytes_reader read_list(bytes_reader r, queue<X>& l);
    
    namespace bitcoin {
        
        template <size_t size>
        using uint = gigamonkey::uint<size, LittleEndian>; 
        
        template <size_t size>
        using integer = gigamonkey::integer<size, LittleEndian>;
        
    }
    
}

inline std::ostream& operator<<(std::ostream& o, const gigamonkey::timestamp& s) {
    return o << s.write();
}

inline gigamonkey::bytes_writer operator<<(gigamonkey::bytes_writer w, const gigamonkey::timestamp& s) {
    return w << s.Timestamp;
}

inline gigamonkey::bytes_reader operator>>(gigamonkey::bytes_reader r, gigamonkey::timestamp& s) {
    return r >> s.Timestamp;
}

namespace gigamonkey {
    inline bool timestamp::operator==(const timestamp& t) const {
        return Timestamp == t.Timestamp;
    }
    
    inline bool timestamp::operator!=(const timestamp& t) const {
        return Timestamp != t.Timestamp;
    }
    
    inline bool timestamp::operator<(const timestamp& t) const {
        return Timestamp < t.Timestamp;
    }
    
    inline bool timestamp::operator>(const timestamp& t) const {
        return Timestamp > t.Timestamp;
    }
    
    inline bool timestamp::operator<=(const timestamp& t) const {
        return Timestamp <= t.Timestamp;
    }
    
    inline bool timestamp::operator>=(const timestamp& t) const {
        return Timestamp >= t.Timestamp;
    }
}

#endif
