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
        explicit BEEF (bytes_view);
        explicit operator bytes () const;

        explicit BEEF (const SPV::proof &);

        // It's valid if it follows the right format. Use
        // validate to check all the merkle proofs.
        bool valid () const;

        // if this BEEF is valid, then this list should
        // be nonempty and full of merkle roots of valid
        // blocks.
        list<digest256> roots () const;

        // validate means that we actually check all the merkle
        // against the block headers.
        bool validate (const SPV::database &) const;

        uint64 serialized_size () const;

        // NOTE: it is possible for BUMP to contain several unconfirmeed
        // transactions.
        SPV::proof read_SPV_proof (const SPV::database &) const;

        // written out in byte order this is 0100BEEF.
        uint32_little Version {0xEFBE0001};

        uint32_little version () const {
            return Version - 0xEFBE0000;
        }

        list<Merkle::BUMP> BUMPs {};

        struct transaction {
            Bitcoin::transaction Transaction;
            maybe<uint64> BUMPIndex;

            transaction (): Transaction {}, BUMPIndex {} {}
            transaction (const Bitcoin::transaction &tx) : Transaction {tx}, BUMPIndex {} {}
            transaction (const Bitcoin::transaction &tx, uint64 index) : Transaction {tx}, BUMPIndex {index} {}

            friend writer &operator << (writer &w, const transaction &h);
            friend reader &operator >> (reader &r, transaction &h);
            uint64 serialized_size () const;

            bool Merkle_proof_included () const {
                return bool (BUMPIndex);
            }
        };

        list<transaction> Transactions {};
    };

    writer inline &operator << (writer &w, const BEEF &h) {
        return w << h.Version << Bitcoin::var_sequence<Merkle::BUMP> {h.BUMPs} << Bitcoin::var_sequence<BEEF::transaction> {h.Transactions};
    }

    reader inline &operator >> (reader &r, BEEF &h) {
        return r >> h.Version >> Bitcoin::var_sequence<Merkle::BUMP> {h.BUMPs} >> Bitcoin::var_sequence<BEEF::transaction> {h.Transactions};
    }

    bool inline BEEF::validate (const SPV::database &d) const {
        if (!valid ()) return false;
        for (const auto &mr : roots ()) if (!d.header (mr)) return false;
        return true;
    }

    uint64 inline BEEF::serialized_size () const {
        return 4 + Bitcoin::var_sequence<Merkle::BUMP>::size (BUMPs) + Bitcoin::var_sequence<transaction>::size (Transactions);
    }

    inline BEEF::BEEF (bytes_view b) {
        bytes_reader r {b.data (), b.data () + b.size ()};
        r >> *this;
    }

    uint64 inline BEEF::transaction::serialized_size () const {
        return Transaction.serialized_size () + 1 + (bool (BUMPIndex) ? Bitcoin::var_int::size (*BUMPIndex) : 0);
    }

    writer inline &operator << (writer &w, const BEEF::transaction &h) {
        w << h.Transaction;
        if (bool (h.BUMPIndex))
        return w << byte (1) << Bitcoin::var_int {*h.BUMPIndex};
        return w << byte (0);
    }

}

#endif
