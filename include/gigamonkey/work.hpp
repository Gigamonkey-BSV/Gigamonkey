// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_WORK
#define GIGAMONKEY_WORK

#include "hash.hpp"

namespace gigamonkey::work {
    
    using nonce = boost::endian::little_int64_t;
    
    using digest = gigamonkey::digest<sha256::Size>;
    
    inline integer<32, LittleEndian> difficulty_1_target() {
        static integer<32, LittleEndian> Difficulty1Target = integer<32, LittleEndian>{"0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"};
        return Difficulty1Target;
    }
    
    using difficulty = data::math::number::fraction<integer<sha256::Size, LittleEndian>, uint<sha256::Size, LittleEndian>>;

    struct target {
        uint32_little Encoded;
        
        static target encode(byte e, uint24_little v) {
            target t;
            data::writer<byte*>(t.Encoded.data(), t.Encoded.data() + 4) << e << v;
            return t;
        }
        
        target() : Encoded{} {}
        target(uint32_little x) : Encoded{x} {}
        target(byte e, uint24_little v) : Encoded{encode(e, v)} {}
        
        byte exponent() const {
            return static_cast<byte>(Encoded & 0x000000ff);
        }
        
        uint24_little digits() const {
            return uint24_little{Encoded >> 8};
        }
        
        bool valid() const {
            byte e = exponent();
            return e >= 3 && e <= 32 && digits() != 0;
        }
        
        digest expand() const{
            return digest{uint<32, LittleEndian>{digits()} >> (exponent() - 3)};
        }
        
        explicit operator uint32_little() const {
            return Encoded;
        }
        
        explicit operator digest() const {
            return expand();
        }
        
        bool operator==(target t) const {
            return Encoded == t.Encoded;
        } 
        
        bool operator!=(target t) const {
            return Encoded != t.Encoded;
        } 
        
        bool operator<(target t) const {
            return expand() < t.expand();
        } 
        
        bool operator<=(target t) const {
            return expand() <= t.expand();
        } 
        
        bool operator>(target t) const {
            return expand() > t.expand();
        } 
        
        bool operator>=(target t) const {
            return expand() >= t.expand();
        } 
        
        work::difficulty difficulty() const {
            return work::difficulty{difficulty_1_target(), expand().Digest};
        }
    };
    
    const target Easy{32, 0xffffff}; 
    const target Hard{3, 0x000001};
    
    const target SuccessHalf{32, 0x800000};
    const target SuccessQuarter{32, 0x400000};
    const target SuccessEighth{32, 0x200000};
    const target SuccessSixteenth{32, 0x100000};
    
    const uint32 ContentSize = 68;
    
    using content = uint<ContentSize, LittleEndian>;
    
    struct order {
        content Message;
        target Target;
        
        bool valid() const {
            return Target.valid();
        }
        
        order(content m, target t) : Message{m}, Target{t} {}
        order() : Message{}, Target{} {}
    };
    
    bool satisfied(order, nonce);
    
    struct candidate {
        uint<80, LittleEndian> Data;
    
        static uint<80, LittleEndian> encode(order o, nonce n) {
            uint<80, LittleEndian> x;
            throw data::method::unimplemented{"encode"};
            /*writer(x) << data::greater_half(n) << o.Message << o.Target << data::lesser_half(n);
            return x;*/
        }
        
        candidate() : Data{} {}
        candidate(uint<80, LittleEndian> d) : Data{d} {}
        candidate(order o, nonce n) : Data{encode(o, n)} {}
        
        bool operator==(const candidate& c) {
            return Data == c.Data;
        }
        
        static digest hash(slice<80> data) {
            return bitcoin::hash256(data);
        }
        
        digest hash() const {
            return hash(Data);
        }
        
        work::nonce nonce() const;
        
        work::content content() const;
        
        static work::target target(slice<80> data) {
            throw data::method::unimplemented{"work::candidate::target"};
        }
    
        static bool valid(slice<80> data) {
            return hash(data) < target(data).expand();
        }
        
        work::target target() const {
            throw target(Data);
        }
    
        bool valid() const {
            return valid(Data);
        }
    };
    
    inline byte exponent(target t) {
        return t.exponent();
    }
    
    inline uint24_little digits(target t) {
        return t.digits();
    }
    
    inline bool valid(target t) {
        return t.valid();
    }
    
    inline digest expand(target t) {
        return t.expand();
    }
    
    nonce work(order);
    
}

inline gigamonkey::bytes_writer operator<<(gigamonkey::bytes_writer w, const gigamonkey::work::target& t) {
    return w << t.Encoded;
}

inline gigamonkey::bytes_reader operator>>(gigamonkey::bytes_reader r, gigamonkey::work::target& t) {
    return r >> t.Encoded;
}

#endif

