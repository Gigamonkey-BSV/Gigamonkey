// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_MERKLE_BUMP
#define GIGAMONKEY_MERKLE_BUMP

#include <gigamonkey/merkle/serialize.hpp>
#include <gigamonkey/merkle/dual.hpp>

// https://bsv.brc.dev/transactions/0074

namespace Gigamonkey::Merkle {

    struct BUMP {
        friend BUMP operator + (const BUMP &, const BUMP &);

        friend writer &operator << (writer &w, const BUMP &h);
        friend reader &operator >> (reader &r, BUMP &h);

        BUMP (uint32 block_height, const map &d);

        // recover the dual tree.
        map tree () const;

        // encode
        operator bytes () const;
        operator JSON () const;

        // decode
        BUMP (const JSON &);
        BUMP (bytes_view);

        // check whether the data structure was read.
        bool valid () const;

        Bitcoin::TXID root () const;

        // check the proofs.
        bool validate (const Bitcoin::TXID &expected_root) const;

        // how big will this be in the binary representation?
        uint64 serialized_size () const;

        enum class flag : byte {
            not_client = 0,
            duplicate = 1,
            client = 2
        };

        struct node {
            uint32 Offset;
            flag Flag;
            maybe<Bitcoin::TXID> TXID;

            node (uint32 offset, flag f, const Bitcoin::TXID &id): Offset {offset}, Flag {f}, TXID {id} {}
            node (uint32 offset) : Offset {offset}, Flag {flag::duplicate}, TXID {} {}

            bool valid () const {
                return bool (TXID) && Flag != flag::duplicate || !bool (TXID) && Flag == flag::duplicate;
            }

            std::strong_ordering operator <=> (const node &n) const {
                return Offset <=> n.Offset;
            }

            bool operator == (const node &n) const;

            // encode JSON
            operator JSON () const;

            // decode JSON
            node (const JSON &);

            // encode and decode bytes.
            friend writer &operator << (writer &w, const node &h);
            friend reader &operator >> (reader &r, node &h);
        };

        uint32 BlockHeight;

        using nodes = list<ordered_list<node>>;
        nodes Path;

        BUMP (): BlockHeight {0}, Path {} {}

        static nodes to (const map &);
        static map from (const nodes);

        // calculate the next layer of merkle nodes as part of the validation process.
        static ordered_list<node> step (ordered_list<node>);

        // sort and remove duplicates.
        static ordered_list<node> combine (ordered_list<node>, ordered_list<node>);
    };

    bool BUMP::valid () const {
        return data::size (Path) != 0 && data::valid (Path);
    }

    bool BUMP::validate (const Bitcoin::TXID &expected_root) const {
        return expected_root == root ();
    }

    map inline BUMP::tree () const {
        return from (Path);
    }

    inline BUMP::BUMP (uint32 block_height, const map &d): BlockHeight {block_height}, Path {to (d)} {}

    Bitcoin::TXID inline BUMP::root () const {
        auto root_node = fold ([] (ordered_list<node> current, ordered_list<node> next) -> ordered_list<node> {
            return step (combine (current, next));
        }, ordered_list<node> {}, Path);
        return data::size (root_node) == 1 && bool (data::first (root_node).TXID) ? *data::first (root_node).TXID : Bitcoin::TXID {};
    }

}

#endif
