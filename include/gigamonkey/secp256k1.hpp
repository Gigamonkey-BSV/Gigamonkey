// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SECP256K1
#define GIGAMONKEY_SECP256K1

#include "number.hpp"
#include "hash.hpp"
#include <data/encoding/integer.hpp>
#include <data/crypto/encrypted.hpp>

namespace Gigamonkey::secp256k1 {
    
    using coordinate = integer<endian::big>;
    
    struct point {
        coordinate R;
        coordinate S;
        
        point(const coordinate &r, const coordinate &s) : R{r}, S{s} {}
    };
    
    bool operator==(const point &, const point &);
    bool operator!=(const point &, const point &);
    
    struct secret;
    struct pubkey;
    
    bool operator==(const secret &, const secret &);
    bool operator!=(const secret &, const secret &);
    
    bool operator==(const pubkey &, const pubkey &);
    bool operator!=(const pubkey &, const pubkey &);
    
    struct signature final : bytes {
        
        // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]
        constexpr static size_t MaxSize = 72; 
        
        static bool valid(bytes_view x);
        static bool minimal(bytes_view x);
        static bool normalized(bytes_view);
        
        static bytes_view R(bytes_view);
        static bytes_view S(bytes_view);
        
        explicit signature(bytes_view b) : bytes{b} {}
        
        explicit operator point() const;
        explicit signature(const point&);
        signature normalize() const;
        
        template <typename reader> static reader &read(reader& r, point& p);
        template <typename writer> static writer &write(writer& w, const point& p);
        
        static size_t serialized_size(const point& p) {
            return p.S.size() + p.R.size() + 6;
        }
        
        signature() : bytes{} {}
    };
    
    using digest = digest256;
    
    // Values written at the start of the standard
    // pubkey representation which tell how it is 
    // represented. 
    enum pubkey_type : byte {
        invalid = 0x00, 
        uncompressed = 0x04,
        compressed_positive = 0x03,
        compressed_negative = 0x02
    };
    
    struct pubkey : bytes {
        
        // There are two representations of public
        // keys that are allowed in Bitcoin. 
        // compressed is default. 
        constexpr static size_t CompressedSize{33};
        constexpr static size_t UncompressedSize{65};
        
        static bool valid(bytes_view);
        
        static bool compressed(bytes_view b) {
            return valid(b) && b.size() == CompressedSize;
        }
        
        static bool verify(bytes_view pubkey, const digest&, bytes_view sig);
        static bytes compress(bytes_view);
        static bytes decompress(bytes_view);
        static bytes negate(bytes_view);        
        static bytes plus_pubkey(bytes_view, bytes_view);
        static bytes plus_secret(bytes_view, const uint256&);
        static bytes times(bytes_view, bytes_view);
        
        static bool valid_size(size_t size) {
            return size == CompressedSize || size == UncompressedSize;
        }
        
        pubkey() : bytes() {}
        explicit pubkey(bytes_view v) : bytes{v} {}
        
        bool valid() const;
        
        bool verify(const digest& d, const signature& s) const;
        
        pubkey_type type() const;
        
        coordinate x() const;
        coordinate y() const;
        
        secp256k1::point point() const;
        
        pubkey compress() const;
        pubkey decompress() const;
        
        bool compressed() const {
            return compressed(*this);
        }
    
        pubkey operator-() const;
        pubkey operator+(const pubkey &) const;
        pubkey operator+(const secret &) const;
        pubkey operator*(const secret &) const;
        
    private:
        explicit pubkey(bytes&& b) : bytes{b} {}
        friend struct secret;
    };
    
    struct secret final : public nonzero<uint256> {
        
        static bool valid(bytes_view);
        static bytes to_public_compressed(bytes_view);
        static bytes to_public_uncompressed(bytes_view);
        static signature sign(bytes_view, const digest&);
        
        static uint256 negate(const uint256&);
        static uint256 plus(const uint256&, const uint256&);
        static uint256 times(const uint256&, const uint256&);
        
        constexpr static size_t Size = 32;
        
        static uint256 order() {
            static uint256 Order{"0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"};
            return Order;
        }

        using nonzero<uint256>::nonzero;
        
        bool valid() const;
        
        signature sign(const digest& d) const;
        
        pubkey to_public() const;
    
        secret operator-() const;
        secret operator+(const secret &) const;
        secret operator*(const secret &) const;
        
    };
    
    bool inline operator==(const point &a, const point &b) {
        return a.R == b.R && a.S == b.S;
    }
    
    bool inline operator!=(const point &a, const point &b) {
        return !(a == b);
    }
    
    template <typename reader> reader &signature::read(reader& r, point& p) {
        byte size;
        byte r_size;
        byte s_size;
        byte v;
        r >> v;
        if (v != 0x30) throw std::logic_error{"invalid signature format"};
        r >> size;
        if (size < 4) throw std::logic_error{"invalid signature format"};
        r >> v;
        if (v != 0x02) throw std::logic_error{"invalid signature format"};
        r >> r_size;
        if (size < r_size + 4) throw std::logic_error{"invalid signature format"};
        p.R.resize(r_size);
        r >> p.R;
        r >> v;
        if (v != 0x02) throw std::logic_error{"invalid signature format"};
        r >> s_size;
        if (size < r_size + s_size + 4) throw std::logic_error{"invalid signature format"};
        p.S.resize(s_size);
        r >> p.S;
        if (size > r_size + s_size + 4) r.skip(size - r_size - s_size - 4);
        return r;
    }
    
    template <typename writer> writer &signature::write(writer& w, const point& p) {
        size_t r_size = p.R.size();
        size_t s_size = p.S.size();
        return w << byte(0x30) << byte(r_size + s_size + 4) << byte(0x02) << 
            byte(r_size) << p.R << byte(0x02) << byte(s_size) << p.S;
    }
    
    std::ostream inline &operator<<(std::ostream &o, const secret &s) {
        return o << "secret{" << s.Value << "}";
    }

    std::ostream inline &operator<<(std::ostream &o, const pubkey &p) {
        return o << "pubkey{" << data::encoding::hex::write(p) << "}";
    }

    std::ostream inline &operator<<(std::ostream &o, const signature &x) {
        return o << "signature{" << data::encoding::hex::write(bytes(x)) << "}";
    }

    Gigamonkey::bytes_writer inline operator<<(bytes_writer w, const secret& x) {
        return w << x.Value;
    }

    Gigamonkey::bytes_reader inline operator>>(bytes_reader r, secret& x) {
        return r >> x.Value;
    }
    
    bool inline valid(const secret& s) {
        return s.valid();
    }
    
    signature inline sign(const secret& s, const digest& d) {
        return s.sign(d);
    }
    
    secret inline negate(const secret& s) {
        return -s;
    }
    
    secret inline plus(const secret& a, const secret& b) {
        return a + b;
    }
    
    pubkey inline to_public(const secret& s) {
        return s.to_public();
    }
    
    bool inline valid(const pubkey& p) {
        return p.valid();
    }
    
    bool inline verify(const pubkey& p, const digest& d, const signature& s) {
        return p.verify(d, s);
    }
    
    pubkey inline negate(const pubkey& p) {
        return -p;
    }
    
    pubkey inline plus(const pubkey& a, const pubkey& b) {
        return a + b;
    }
    
    pubkey inline plus(const pubkey& a, const secret& b) {
        return a + b;
    }
    
    secret inline times(const secret& a, const secret& b) {
        return a * b;
    }
    
    pubkey inline times(const pubkey& a, const secret& b) {
        return a * b;
    }
    
    bool inline secret::valid() const {
        return nonzero<uint256>::valid() && nonzero<uint256>::Value < order();
    }
    
    bool inline operator==(const secret &a, const secret &b) {
        return a.Value == b.Value;
    }
    
    bool inline operator!=(const secret &a, const secret &b) {
        return a.Value != b.Value;
    }
    
    signature inline secret::sign(const digest& d) const {
        return sign(Value, d);
    }
    
    pubkey inline secret::to_public() const {
        return pubkey{to_public_compressed(bytes_view(Value))};
    }
    
    secret inline secret::operator-() const {
        return secret{negate(this->Value)};
    }
    
    secret inline secret::operator+(const secret& s) const {
        return secret{secret::plus(this->Value, s.Value)};
    }
    
    secret inline secret::operator*(const secret& s) const {
        return secret{secret::times(this->Value, s.Value)};
    }
    
    bool inline pubkey::valid() const {
        return valid_size(bytes::size()) && valid(*this);
    }
    
    bool inline operator==(const pubkey &a, const pubkey &b) {
        return static_cast<bytes>(a) == static_cast<bytes>(b);
    }
    
    bool inline operator!=(const pubkey &a, const pubkey &b) {
        return static_cast<bytes>(a) != static_cast<bytes>(b);
    }
    
    bool inline pubkey::verify(const digest& d, const signature& s) const {
        return verify(*this, d, s);
    }
    
    pubkey_type inline pubkey::type() const {
        return size() == 0 ? invalid : pubkey_type{bytes::operator[](0)};
    }
    
    point inline pubkey::point() const {
        return {x(), y()};
    }
    
    pubkey inline pubkey::compress() const {
        return pubkey(compress(*this));
    }
    
    pubkey inline pubkey::decompress() const {
        return pubkey(decompress(*this));
    }
    
    pubkey inline pubkey::operator-() const {
        return pubkey(pubkey::negate(*this));
    }
    
    pubkey inline pubkey::operator+(const pubkey &b) const {
        return pubkey{pubkey::plus_pubkey(*this, b)};
    }
    
    pubkey inline pubkey::operator+(const secret &s) const {
        return pubkey{pubkey::plus_secret(*this, s.Value)};
    }
    
    pubkey inline pubkey::operator*(const secret &s) const {
        return pubkey{pubkey::times(*this, s.Value)};
    }
}

#endif

