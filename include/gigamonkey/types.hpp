// Copyright (c) 2019-2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_TYPES
#define GIGAMONKEY_TYPES

#include <string>
#include <string_view>
#include <array>

#include <nlohmann/json.hpp>

#include <boost/endian/conversion.hpp>

#include <nlohmann/json.hpp>

#include <data/stream.hpp>
#include <data/tools.hpp>
#include <data/math/nonnegative.hpp>
#include <data/math/number/gmp/N.hpp>
#include <data/encoding/hex.hpp>

#include <data/encoding/hex.hpp>

inline bool implies(bool a, bool b) {
    return (!a) || b;
}

namespace Gigamonkey {
    
    using namespace data;
    
    using checksum = uint32_little;
    
    using index = uint32_little;
    
    using script = bytes;
    
    using nonce = uint32_little;
    
    enum chain : byte {test, main};
    
    using json = nlohmann::json;
    
    using N = data::math::number::gmp::N;
    
    template<typename x> using optional = std::optional<x>;
    
    using ostream = std::ostream;
    
    template <typename X> using nonzero = data::math::nonzero<X>;
    template <size_t size>
    using slice = data::slice<byte, size>;
    
    using bytes_writer = data::writer<bytes::iterator>;
    using bytes_reader = data::reader<const byte*>;
    
    using string_writer = data::writer<string::iterator>;
    using string_reader = data::reader<const char*>;
    
    template <typename X> bytes_writer 
    inline write(bytes_writer b, X x) {
        return b << x;
    }
    
    template <typename X, typename ... P> 
    inline bytes_writer write(bytes_writer b, X x, P... p) {
        return write(write(b, x), p...);
    }
    
    template <typename ... P> inline bytes write(size_t size, P... p) {
        bytes x(size);
        write(bytes_writer{x.begin(), x.end()}, p...);
        return x;
    }
    
    template <typename X>  
    inline bytes_writer write(bytes_writer b, list<X> ls) {
        while(!ls.empty()) {
            b = b << ls.first();
            ls = ls.rest();
        }
        return b;
    }
    
}

namespace Gigamonkey::Bitcoin {
    
    struct reader {
        static bytes_reader read_var_int(bytes_reader, uint64&);
        
        static bytes_reader read_data(bytes_reader r, bytes& b) {
            uint64 size;
            r = read_var_int(r, size);
            b = bytes(size);
            return r >> b;
        }
        
        bytes_reader Reader;
        reader(bytes_view b) : Reader{b.data(), b.data() + b.size()} {}
        reader(bytes_reader r) : Reader{r} {}
        
        reader operator>>(byte& b) const {
            return reader{Reader >> b};
        }

        reader operator>>(char& x) const {
            return reader{Reader >> x};
        }
        
        template <boost::endian::order Order, bool is_signed, std::size_t bytes>
        reader operator>>(endian::arithmetic<Order, is_signed, bytes>& x) const {
            return reader{Reader >> x};
        }

        reader operator>>(bytes& b) const {
            uint64 size;
            bytes_reader r = read_var_int(Reader, size);
            b.resize(size);
            return reader{r >> b};
        }
        
        reader operator>>(string& x) const {
            uint64 size;
            bytes_reader r = read_var_int(Reader, size);
            x.resize(size);
            
            auto is = r.Reader;
            for(uint64 i=0; i < size; i++) {
                byte b;
                is = is >> b; 
                x[i] = static_cast<char>(b);
            }
            
            return reader{bytes_reader{is}};
        }
        
        template <typename X> 
        reader operator>>(list<X>& l) {
            l = {};
            uint64 size;
            auto r = reader{read_var_int(Reader, size)};
            for (int i = 0; i < size; i++) {
                X x;
                r = r >> x;
                l = l << x;
            }
            return r;
        }
    };
    
    struct writer {
        static bytes_writer write_var_int(bytes_writer, uint64);
        static size_t var_int_size(uint64);
        static bytes_writer write_data(bytes_writer w, bytes_view b) {
            return write_var_int(w, b.size()) << b;
        }
        
        bytes_writer Writer; 
        writer(bytes_writer w) : Writer{w} {}
        writer(bytes& b) : Writer{b.begin(), b.end()} {}
        
        writer operator<<(const byte b) const {
            return writer{Writer << b};
        }

        writer operator<<(const char& c) const {
            return operator<<(static_cast<const byte&>(c));
        }
        
        writer operator<<(bytes_view b) const {
            return writer{write_data(Writer, b)};
        }
        
        writer operator<<(string_view b) const {
            return writer{write_data(Writer, bytes_view{(const byte*)b.data(), b.size()})};
        }
    
        template <boost::endian::order Order, bool is_signed, std::size_t bytes>
        writer operator<<(const endian::arithmetic<Order, is_signed, bytes> x) const {
            return writer{Writer << x};
        }
        
        template <typename X> 
        writer operator<<(const list<X>& l) {
            return data::fold([](writer w, const X& x) -> writer {
                    return w << x;
                }, writer{write_var_int(Writer, data::size(l))}, l);
        }
    };
    
}

#endif
