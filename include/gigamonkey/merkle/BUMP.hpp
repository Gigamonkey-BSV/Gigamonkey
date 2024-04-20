// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_MERKLE_BUMP
#define GIGAMONKEY_MERKLE_BUMP

#include <gigamonkey/merkle/dual.hpp>
#include <gigamonkey/timechain.hpp>

// https://bsv.brc.dev/transactions/0074

namespace Gigamonkey::Merkle {

    struct BUMP {
        friend BUMP operator + (const BUMP &, const BUMP &);
        BUMP operator + (const branch &);

        friend writer &operator << (writer &w, const BUMP &h);
        friend reader &operator >> (reader &r, BUMP &h);

        BUMP (uint64 block_height, const branch &);

        // encode
        operator bytes () const;
        operator JSON () const;

        // decode
        BUMP (const JSON &);
        BUMP (const bytes &);

        map paths () const;
        BUMP (uint64 block_height, map);

        // check whether the data structure was read.
        bool valid () const;

        // check the proofs.
        bool validate (const digest256 &expected_root) const;

        digest256 root () const;

        // how big will this be in the binary representation?
        uint64 serialized_size () const;

        enum class flag : byte {
            intermediate = 0,
            duplicate = 1,
            client = 2
        };

        struct node {
            uint64 Offset;
            flag Flag;
            maybe<digest> Digest;

            node (): Offset {0}, Flag {flag::intermediate}, Digest {} {}
            node (uint64 offset, flag f, const digest &id): Offset {offset}, Flag {f}, Digest {id} {}
            node (uint64 offset) : Offset {offset}, Flag {flag::duplicate}, Digest {} {}

            bool valid () const {
                return bool (Digest) && Flag != flag::duplicate || !bool (Digest) && Flag == flag::duplicate;
            }

            std::weak_ordering operator <=> (const node &n) const {
                return Offset <=> n.Offset;
            }

            bool operator == (const node &n) const {
                return Offset == n.Offset && Flag == n.Flag;
            }

            // encode JSON
            operator JSON () const;

            // decode JSON
            node (const JSON &);

            // encode and decode bytes.
            friend writer &operator << (writer &w, const node &h);
            friend reader &operator >> (reader &r, node &h);

            uint64 serialized_size () const {
                return Flag == flag::duplicate ? 1 : 33;
            }
        };

        uint64 BlockHeight;

        using nodes = list<ordered_list<node>>;
        nodes Path;

        BUMP (): BlockHeight {0}, Path {} {}
        BUMP (uint64 block_height, nodes path): BlockHeight {block_height}, Path {path} {}

        // calculate the next layer of merkle nodes as part of the validation process.
        static ordered_list<node> step (ordered_list<node>);

        // sort and remove duplicates.
        static ordered_list<node> combine (ordered_list<node>, ordered_list<node>, uint32 tree_height);

        // thrown when an error is found during validation.
        struct validation_error {};
    };

    bool inline BUMP::valid () const {
        return data::size (Path) != 0 && data::valid (Path);
    }

    BUMP inline BUMP::operator + (const branch &p) {
        return *this + BUMP {BlockHeight, p};
    }

    inline BUMP::BUMP (uint64 block_height, map m): BlockHeight {block_height}, Path {} {
        for (const auto &e : m) *this = *this + branch {e.Key, e.Value};
    }

    bool inline BUMP::validate (const Bitcoin::TXID &expected_root) const {
        try {
            return expected_root == root ();
        } catch (const validation_error &) {
            return false;
        }
    }

}

#endif
