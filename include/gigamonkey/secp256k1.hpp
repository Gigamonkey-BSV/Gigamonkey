// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SECP256K1
#define GIGAMONKEY_SECP256K1

#include "hash.hpp"
#include <data/encoding/integer.hpp>
#include <data/crypto/encrypted.hpp>

namespace Gigamonkey::secp256k1 {
    
    constexpr size_t SecretSize{32};
    
    // There are two representations of public
    // keys that are allowed in Bitcoin. 
    // compressed is default. 
    constexpr size_t CompressedPubkeySize{33};
    constexpr size_t UncompressedPubkeySize{65};
    
    // Values written at the start of the standard
    // pubkey representation which tell how it is 
    // represented. 
    enum pubkey_type : byte {
        invalid = 0x00, 
        uncompressed = 0x04,
        compressed_positive = 0x03,
        compressed_negative = 0x02
    };
    
    struct coordinate : uint<SecretSize> {
        using uint<SecretSize>::uint;
        
        static coordinate max() {
            static coordinate Max{"0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"};
            return Max;
        }
        
        bool valid() const {
            return *this < max(); 
        }
    };
    
    struct point {
        coordinate X;
        coordinate Y;
    };
    
    bool operator==(const point &, const point &);
    bool operator!=(const point &, const point &);
    
    struct secret;
    struct pubkey;
    
    bool operator==(const secret &, const secret &);
    bool operator!=(const secret &, const secret &);
    
    bool operator==(const pubkey &, const pubkey &);
    bool operator!=(const pubkey &, const pubkey &);
    
    secret operator-(const secret &);
    secret operator+(const secret &, const secret &);
    secret operator*(const secret &, const secret &);
    
    pubkey operator-(const pubkey &);
    pubkey operator+(const pubkey &, const pubkey &);
    pubkey operator+(const pubkey &, const secret &);
    pubkey operator*(const pubkey &, const secret &);
    
    struct signature : public bytes {
        signature() : bytes(MaxSignatureSize) {}
        explicit signature(const bytes& b) : bytes{} {
            if (b.size() <= MaxSignatureSize) {
                bytes::resize(b.size());
                std::copy(b.begin(), b.end(), bytes::begin());
            }
        }
        
        constexpr static size_t MaxSignatureSize = 72;
        
        secp256k1::point point() const;
    };
    
    using digest = digest256;
    
    struct secret final : public nonzero<coordinate> {
        
        static bool valid(bytes_view);
        static bytes to_public_compressed(bytes_view);
        static bytes to_public_uncompressed(bytes_view);
        static signature sign(bytes_view, const digest&);
        static coordinate negate(const coordinate&);
        static coordinate plus(const coordinate&, bytes_view);
        static coordinate times(const coordinate&, bytes_view);
        
        constexpr static size_t Size = 32;
        
        secret() : nonzero<coordinate>{} {}
        explicit secret(const coordinate& v) : nonzero<coordinate>{v} {}
        
        bool valid() const;
        
        signature sign(const digest& d) const;
        
        pubkey to_public() const;
        
    };
    
    struct pubkey : bytes {
        
        static bool valid(bytes_view);
        static bool verify(bytes_view pubkey, const digest&, const signature&);
        static bytes compress(bytes_view);
        static bytes decompress(bytes_view);
        static bytes negate(const bytes&);
        static bytes plus_pubkey(const bytes&, bytes_view);
        static bytes plus_secret(const bytes&, bytes_view);
        static bytes times(const bytes&, bytes_view);
        
        static bool valid_size(size_t size) {
            return size == CompressedPubkeySize || size == UncompressedPubkeySize;
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
    };
    
    bool inline operator==(const point &a, const point &b) {
        return a.X == b.X && a.Y == b.Y;
    }
    
    bool inline operator!=(const point &a, const point &b) {
        return !(a == b);
    }
    
    std::ostream inline &operator<<(std::ostream &o, const secret &s) {
        return o << "secret{" << s.Value << "}";
    }

    std::ostream inline &operator<<(std::ostream &o, const pubkey &p) {
        return o << "pubkey{" << data::encoding::hexidecimal::write(p, data::endian::little) << "}";
    }

    std::ostream inline &operator<<(std::ostream &o, const signature &p) {
        return o << "signature{" << data::encoding::hexidecimal::write(p, data::endian::little) << "}";
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
        return nonzero<coordinate>::valid();
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
    
    secret inline operator-(const secret &s) {
        return secret{secret::negate(s)};
    }
    
    secret inline operator+(const secret& a, const secret& b) {
        return secret{secret::plus(a.Value, b.Value)};
    }
    
    secret inline operator*(const secret& a, const secret& b) {
        return secret{secret::times(a.Value, b.Value)};
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
    
    pubkey inline operator-(const pubkey &p) {
        return pubkey(pubkey::negate(p));
    }
    
    pubkey inline operator+(const pubkey &a, const pubkey &b) {
        return pubkey{pubkey::plus_pubkey(a, b)};
    }
    
    pubkey inline operator+(const pubkey &a, const secret &b) {
        return pubkey{pubkey::plus_secret(a, b.Value)};
    }
    
    pubkey inline operator*(const pubkey &a, const secret &b) {
        return pubkey{pubkey::times(a, b.Value)};
    }
}

#endif

