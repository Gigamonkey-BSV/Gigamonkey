// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SECP256K1
#define GIGAMONKEY_SECP256K1

#include "types.hpp"
#include "hash.hpp"
#include <secp256k1.h>

namespace gigamonkey::secp256k1 {
    
    const size_t SecretSize = 32;
    
    // There are two representations of public
    // keys that are allowed in Bitcoin. 
    // compressed is default. 
    const size_t CompressedPubkeySize = 33;
    const size_t UncompressedPubkeySize = 65;
    
    // Values written at the start of the standard
    // pubkey representation which tell how it is 
    // represented. 
    enum pubkey_type : byte {
        invalid = 0x00, 
        uncompressed = 0x04,
        compressed_positive = 0x03,
        compressed_negative = 0x02
    };
    
    using coordinate = uint<SecretSize, LittleEndian>;
    
    class secret;
    class pubkey;
    
    class signature {
        friend class secret;
        secp256k1_ecdsa_signature* Data;
        
    public:
        constexpr static size_t Size = 64;
        
        signature() : Data{new secp256k1_ecdsa_signature()} {}
        ~signature() {
            delete Data;
        }
        
        operator bytes_view() {
            return bytes_view{Data->data, Size};
        }
        
        byte* begin() {
            return Data->data;
        }
        
        byte* end() {
            return Data->data + Size;
        }
        
        const byte* begin() const {
            return Data->data;
        }
        
        const byte* end() const {
            return Data->data + Size;
        }
        
        signature(const signature& s) : signature{} {
            std::copy_n(s.begin(), Size, begin());
        }
        
        signature(signature&& s) {
            Data = s.Data;
            s.Data = nullptr;
        }
    };
    
    using digest = gigamonkey::digest<SecretSize, BigEndian>;
    
    class secret {
        static bool valid(bytes_view);
        static N_bytes to_public_compressed(bytes_view);
        static N_bytes to_public_uncompressed(bytes_view);
        static signature sign(bytes_view, const digest&);
        static coordinate negate(const coordinate&);
        static coordinate plus(const coordinate&, bytes_view);
        static coordinate times(const coordinate&, bytes_view);
        
    public:
        constexpr static size_t Size = 32;
        
        coordinate Value;
        
        secret() : Value{0} {}
        secret(const coordinate& v) : Value{v} {}
        secret(string_view s); // hexidecimal and wif accepted. 
        
        bool valid() const {
            return valid(Value);
        }
        
        signature sign(const digest& d) const {
            return sign(Value, d);
        }
        
        pubkey to_public() const;
        
        secret operator-() const {
            return negate(Value);
        }
        
        secret operator+(const secret& s) const {
            return plus(Value, s.Value);
        }
        
        secret operator*(const secret& s) const {
            return times(Value, s.Value);
        }
    };
    
    class pubkey {
        static bool valid(bytes_view);
        static bool verify(bytes_view pubkey, digest&, const signature&);
        static N_bytes compress(bytes_view);
        static N_bytes decompress(bytes_view);
        static N_bytes negate(const N_bytes&);
        static N_bytes plus_pubkey(const N_bytes&, bytes_view);
        static N_bytes plus_secret(const N_bytes&, bytes_view);
        static N_bytes times(const N_bytes&, bytes_view);
        
    public:
        N_bytes Value;
        
        pubkey() : Value{} {}
        pubkey(const N_bytes& v) : Value{v} {}
        explicit pubkey(string_view s);
        
        bool valid() const {
            return valid(Value);
        }
        
        bool verify(digest& d, const signature& s) const {
            return verify(Value, d, s);
        }
        
        size_t size() const {
            return Value.size();
        }
        
        pubkey_type type() const {
            return size() == 0 ? invalid : pubkey_type{Value[0]};
        }
        
        operator bytes_view() const {
            return Value;
        }
        
        coordinate x() const;
        
        coordinate y() const;
        
        pubkey compress() const {
            return compress(Value);
        }
        
        pubkey decompress() const {
            return decompress(Value);
        }
        
        pubkey operator-() const {
            return negate(Value);
        }
        
        pubkey operator+(const pubkey& p) const {
            return plus_pubkey(Value, p.Value);
        }
        
        pubkey operator+(const secret& s) const {
            return plus_secret(Value, s.Value);
        }
        
        pubkey operator*(const secret& s) const {
            return times(Value, s.Value);
        }
    };
    
    inline bool valid(const secret& s) {
        return s.valid();
    }
    
    inline signature sign(const secret& s, const digest& d) {
        return s.sign(d);
    }
    
    inline pubkey secret::to_public() const {
        return to_public_compressed(bytes_view(Value));
    }
    
    inline secret negate(const secret& s) {
        return -s;
    }
    
    inline secret plus(const secret& a, const secret& b) {
        return a + b;
    }
    
    inline pubkey to_public(const secret& s) {
        return s.to_public();
    }
    
    inline bool valid(const pubkey& p) {
        return p.valid();
    }
    
    inline bool verify(const pubkey& p, digest& d, const signature& s) {
        return p.verify(d, s);
    }
    
    inline pubkey negate(const pubkey& p) {
        return -p;
    }
    
    inline pubkey plus(const pubkey& a, const pubkey& b) {
        return a + b;
    }
    
    inline pubkey plus(const pubkey& a, const secret& b) {
        return a + b;
    }
    
    inline secret times(const secret& a, const secret& b) {
        return a * b;
    }
    
    inline pubkey times(const pubkey& a, const secret& b) {
        return a * b;
    }
    
}

namespace gigamonkey::bitcoin {
    using secret = secp256k1::secret;
    using pubkey = secp256k1::pubkey;
}

inline std::ostream& operator<<(std::ostream& o, const gigamonkey::secp256k1::secret& s) {
    return o << "secret{" << s.Value << "}";
}

inline std::ostream& operator<<(std::ostream& o, const gigamonkey::secp256k1::pubkey& p) {
    return o << "pubkey{" << p.Value << "}";
}

#endif
