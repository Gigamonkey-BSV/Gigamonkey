// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_WORK_ASIC_BOOST
#define GIGAMONKEY_WORK_ASIC_BOOST

#include <data/arithmetic/halves.hpp>
#include <gigamonkey/types.hpp>

namespace Gigamonkey::work::ASICBoost {
    
    // This page implements general purpose nVersion bits, 
    // as described by https://en.bitcoin.it/wiki/BIP_0320. 
    
    // confusingly, the masks are given in a byte-reversed
    // order from what they should actually be. This is
    // because the version field is handled in the original
    // bitcoin core code as a big-endian number and is
    // converted to little endian when written to p2p messages.
    
    // the nature of the general purpose bits is also
    // discussed in terms of a big-endian number even though
    // version is actually written in little-endian. Thus the 
    // 13th through 28th bits are not as the number is written, 
    // but as the number is represented in big-endian. 
    
    static const int32_little Mask = 0xE0001FFFUL;
    static const int32_little Bits = ~Mask;
    
    inline int32_little version (int32_little version_field) {
        return Mask & version_field;
    }
    
    inline uint16_little bits (int32_little version_field) {
        return int32 (Bits & version_field) >> 13;
    }
    
    inline uint16_little magic_number (int32_little version_field) {
        static const uint32_little MaskLeft {0xe0000000};
        static const uint32_little MaskRight {0x00001fff};
        return ((MaskLeft & version_field) >> 16) | (MaskRight & version_field);
    }
    
    inline int32_little category (uint16_little magic_number, uint16_little bits) {
        static const int32_little MaskLeft {0xe000};
        static const int32_little MaskRight {0x1fff};
        return int32_little {0} + (int32_little {bits} << 13) + 
            (int32_little {magic_number & MaskRight}) + (int32_little {magic_number & MaskLeft} << 16);
    }
    
}

#endif

