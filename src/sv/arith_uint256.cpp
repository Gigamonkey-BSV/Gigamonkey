// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sv/arith_uint256.h>

#include <sv/crypto/common.h>
#include <sv/uint256.h>
#include <sv/utilstrencodings.h>

#include <cstdio>
#include <cstring>

namespace bsv {

// This implementation directly uses shifts instead of going through an
// intermediate MPI representation.
arith_uint256 &arith_uint256::SetCompact(uint32_t nCompact, bool *pfNegative,
                                         bool *pfOverflow) {
    int nSize = nCompact >> 24;
    uint32_t nWord = nCompact & 0x007fffff;
    if (nSize <= 3) {
        nWord >>= 8 * (3 - nSize);
        *this = nWord;
    } else {
        *this = nWord;
        *this <<= 8 * (nSize - 3);
    }
    if (pfNegative) *pfNegative = nWord != 0 && (nCompact & 0x00800000) != 0;
    if (pfOverflow)
        *pfOverflow =
            nWord != 0 && ((nSize > 34) || (nWord > 0xff && nSize > 33) ||
                           (nWord > 0xffff && nSize > 32));
    return *this;
}

uint32_t arith_uint256::GetCompact(bool fNegative) const {
    int nSize = (bits() + 7) / 8;
    uint32_t nCompact = 0;
    if (nSize <= 3) {
        nCompact = GetLow64() << 8 * (3 - nSize);
    } else {
        arith_uint256 bn = *this >> 8 * (nSize - 3);
        nCompact = bn.GetLow64();
    }
    // The 0x00800000 bit denotes the sign.
    // Thus, if it is already set, divide the mantissa by 256 and increase the
    // exponent.
    if (nCompact & 0x00800000) {
        nCompact >>= 8;
        nSize++;
    }
    assert((nCompact & ~0x007fffff) == 0);
    assert(nSize < 256);
    nCompact |= nSize << 24;
    nCompact |= (fNegative && (nCompact & 0x007fffff) ? 0x00800000 : 0);
    return nCompact;
}

uint256 ArithToUint256(const arith_uint256 &a) {
    uint256 b;
    for (int x = 0; x < a.WIDTH; ++x)
        WriteLE32(b.begin() + x * 4, a.pn[x]);
    return b;
}
arith_uint256 UintToArith256(const uint256 &a) {
    arith_uint256 b;
    for (int x = 0; x < b.WIDTH; ++x)
        b.pn[x] = ReadLE32(a.begin() + x * 4);
    return b;
}

}
