// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2021 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_TRANSACTION_H
#define BITCOIN_PRIMITIVES_TRANSACTION_H

struct CTxIn {

    /**
     * Setting nSequence to this value for every input in a transaction disables
     * nLockTime.
     */
    static const uint32_t SEQUENCE_FINAL = 0xffffffff;

    /* Below flags apply in the context of BIP 68*/
    /**
     * If this flag set, CTxIn::nSequence is NOT interpreted as a relative
     * lock-time.
     */
    static const uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 << 31);

    /**
     * If CTxIn::nSequence encodes a relative lock-time and this flag is set,
     * the relative lock-time has units of 512 seconds, otherwise it specifies
     * blocks with a granularity of 1.
     */
    static const uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22);

    /**
     * If CTxIn::nSequence encodes a relative lock-time, this mask is applied to
     * extract that lock-time from the sequence field.
     */
    static const uint32_t SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

    /**
     * In order to use the same number of bits to encode roughly the same
     * wall-clock duration, and because blocks are naturally limited to occur
     * every 600s on average, the minimum granularity for time-based relative
     * lock-time is fixed at 512 seconds. Converting from CTxIn::nSequence to
     * seconds is performed by multiplying by 512 = 2^9, or equivalently
     * shifting up by 9 bits.
     */
    static const int SEQUENCE_LOCKTIME_GRANULARITY = 9;

};

#endif
