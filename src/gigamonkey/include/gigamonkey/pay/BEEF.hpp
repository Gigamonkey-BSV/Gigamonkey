// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_PAY_BEEF
#define GIGAMONKEY_PAY_BEEF

#include <gigamonkey/SPV.hpp>
#include <gigamonkey/p2p/var_int.hpp>

// https://bsv.brc.dev/transactions/0062

// BEEF is a format for making payments that includes
// payment transactions and their merkle proofs.
namespace Gigamonkey {
    struct BEEF;

    writer &operator << (writer &w, const BEEF &h);
    reader &operator >> (reader &r, BEEF &h);

    struct BEEF {
        explicit BEEF () = default;
        explicit BEEF (slice<const byte>);
        explicit operator bytes () const;

        explicit BEEF (const SPV::proof &);

        // It's valid if it follows the right format. Use
        // validate to check all the merkle proofs.
        bool valid () const;

        // if this BEEF is valid, then this list should
        // be nonempty and full of merkle roots of valid
        // blocks.
        stack<digest256> roots () const;

        // validate means that we actually check all the merkle
        // against the block headers.
        bool validate (SPV::database &) const;

        uint64 serialized_size () const;

        // NOTE: it is possible for BUMP to contain several unconfirmed
        // transactions.
        SPV::proof read_SPV_proof (SPV::database &) const;

        // written out in byte order this is 0100BEEF.
        uint32_little Version {0xEFBE0001};

        uint32_little version () const {
            return Version - 0xEFBE0000;
        }

        stack<Merkle::BUMP> BUMPs {};

        struct transaction : Bitcoin::transaction {
            maybe<uint64> BUMPIndex;

            transaction (): Bitcoin::transaction {}, BUMPIndex {} {}
            transaction (const Bitcoin::transaction &tx) : Bitcoin::transaction {tx}, BUMPIndex {} {}
            transaction (const Bitcoin::transaction &tx, uint64 index) : Bitcoin::transaction {tx}, BUMPIndex {index} {}

            uint64 serialized_size () const;

            friend writer &operator << (writer &w, const transaction &h);
            friend reader &operator >> (reader &r, transaction &h);

            bool Merkle_proof_included () const {
                return bool (BUMPIndex);
            }

            bool operator == (const transaction &tx) const {
                return static_cast<Bitcoin::transaction> (*this) == static_cast<Bitcoin::transaction> (tx) && BUMPIndex == tx.BUMPIndex;
            }
        };

        stack<transaction> Transactions {};

        bool operator == (const BEEF &beef) const {
            return BUMPs == beef.BUMPs && Transactions == beef.Transactions;
        }

        // note: the official specs do not define a JSON representation of
        // a BEEF. Thus, the version we provide is an unofficial extension.
        explicit operator JSON () const;
    };

    writer inline &operator << (writer &w, const BEEF &h) {
        return w << h.Version << Bitcoin::var_sequence<Merkle::BUMP> {h.BUMPs} << Bitcoin::var_sequence<BEEF::transaction> {h.Transactions};
    }

    reader inline &operator >> (reader &r, BEEF &h) {
        return Bitcoin::var_sequence<BEEF::transaction>::read
            (Bitcoin::var_sequence<Merkle::BUMP>::read (r >> h.Version, h.BUMPs), h.Transactions);
    }

    bool inline BEEF::validate (SPV::database &d) const {
        if (!valid ()) return false;
        for (const auto &mr : roots ()) if (!d.header (mr)) return false;
        return true;
    }

    uint64 inline BEEF::serialized_size () const {
        return 4 + Bitcoin::var_sequence<Merkle::BUMP>::size (BUMPs) + Bitcoin::var_sequence<transaction>::size (Transactions);
    }

    inline BEEF::BEEF (slice<const byte> b) {
        it_rdr r {b.data (), b.data () + b.size ()};
        r >> *this;
    }

    uint64 inline BEEF::transaction::serialized_size () const {
        return static_cast<Bitcoin::transaction> (*this).serialized_size () + 1 + (bool (BUMPIndex) ? Bitcoin::var_int::size (*BUMPIndex) : 0);
    }

    writer inline &operator << (writer &w, const BEEF::transaction &h) {
        w << static_cast<Bitcoin::transaction> (h);
        if (bool (h.BUMPIndex))
        return w << byte (1) << Bitcoin::var_int {*h.BUMPIndex};
        return w << byte (0);
    }

}

#endif
