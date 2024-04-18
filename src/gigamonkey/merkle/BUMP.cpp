// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/merkle/BUMP.hpp>

namespace Gigamonkey::Merkle {

    namespace {
        JSON JSON_write_path (ordered_list<BUMP::node> nodes) {
            JSON::array_t paths;
            for (const auto &n : nodes) paths.push_back (JSON (n));
            return paths;
        }

        JSON JSON_write_paths (const BUMP::nodes &paths) {
            JSON::array_t zaps;
            for (const auto &p : paths) zaps.push_back (JSON_write_path (p));
            return zaps;
        }

        BUMP::nodes read_paths (const JSON &j);

        BUMP::nodes to_path (const branch &p);
    }

    BUMP::operator bytes () const {
        bytes b (serialized_size ());
        bytes_writer w {b.begin (), b.end ()};
        w << *this;
        return b;
    }

    BUMP::BUMP (const bytes &b) {
        try {
            bytes_reader r {b.data (), b.data () + b.size ()};
            r >> *this;
        } catch (data::end_of_stream n) {
            *this = BUMP {};
        }

    }

    writer &operator << (writer &w, const BUMP &h) {
        w << Bitcoin::var_int {h.BlockHeight};

        w << static_cast<byte> (data::size (h.Path));

        for (const auto &level : h.Path) {
            w << Bitcoin::var_int {data::size (level)};
            for (const auto &n : level) w << n;
        }

        return w;
    }

    BUMP::operator JSON () const {

        JSON::object_t jx;

        jx["blockHeight"] = BlockHeight;
        jx["path"] = JSON_write_paths (Path);

        return jx;

    }

    BUMP::BUMP (const JSON &j): BlockHeight {j["blockHeight"]}, Path {read_paths (j["path"])} {}

    ordered_list<BUMP::node> BUMP::combine (ordered_list<node> A, ordered_list<node> B, uint32 tree_height) {
        stack<node> a = reverse (static_cast<stack<node>> (A));
        stack<node> b = reverse (static_cast<stack<node>> (B));

        stack<node> remainder;
        ordered_list<node> result;

        while (true) {
            if (data::empty (a)) {
                remainder = b;
                break;
            }

            if (data::empty (b)) {
                remainder = a;
                break;
            }

            stack<node> &next = a.first () > b.first () ? a : b;

            if (data::size (result) == 0) goto round_done;

            if (next.first ().Offset == result.first ().Offset) {
                if (next.first ().Flag == result.first ().Flag ||
                    result.first ().Flag == flag::client && next.first ().Flag == flag::intermediate) goto round_done;

                if (result.first ().Flag == flag::intermediate && next.first ().Flag == flag::client)
                    result = result.rest ().insert (next.first ());
                else if (result.first ().Flag == flag::duplicate && result.first ().Flag != flag::duplicate)
                    result = result.rest ().insert (next.first ()).insert (result.first ());
                else if (result.first ().Flag != flag::duplicate && result.first ().Flag == flag::duplicate)
                    result = result.insert (next.first ());
            // if the two offsets complement one another, then we don't
            // need them, unless the height is zero, in which case we need both.
            } else if (tree_height != 0 && next.first ().Offset & ~1 == result.first ().Offset & ~1) result = result.rest ();
            else result = result.insert (next.first ());

            round_done:
            next = next.rest ();
        }

        while (data::size (remainder) > 0) {
            result = result.insert (remainder.first ());
            remainder = remainder.rest ();
        }

        return result;
    }

    BUMP operator + (const BUMP &a, const BUMP &b) {
        if (a.BlockHeight != b.BlockHeight) return {};
        BUMP::nodes left = a.Path;
        BUMP::nodes right = b.Path;
        BUMP::nodes result;
        uint32 height = 0;
        while (data::size (left) > 0) {
            result <<= BUMP::combine (left.first (), right.first (), height);
            left = left.rest ();
            right = right.rest ();
            height++;
        }
        return BUMP {a.BlockHeight, result};
    }

    // calculate the next layer of merkle nodes as part of the validation process.
    ordered_list<BUMP::node> BUMP::step (ordered_list<node> x) {

        // the elements of the node should be organized in pairs, either
        // adjacent nodes of the full tree or a digest and a note saying
        // to duplicate it.
        if (data::size (x) % 2 == 1) throw validation_error {};

        stack<node> nodes = reverse (static_cast<stack<node>> (x));

        ordered_list<node> result;
        while (data::size (nodes) > 0) {
            if ((nodes[0].Offset >> 1) != (nodes[1].Offset >> 1)) throw validation_error {};

            if (nodes[0].Offset == nodes[1].Offset) {
                if (nodes[0].Flag != flag::duplicate) throw validation_error {};
                result = result.insert (node {nodes[0].Offset >> 1, flag::intermediate, hash_concatinated (*nodes[1].Digest, *nodes[1].Digest)});
            } else result = result.insert (node {nodes[0].Offset >> 1, flag::intermediate, hash_concatinated (*nodes[1].Digest, *nodes[0].Digest)});
        }

        return result;
    }

    inline BUMP::BUMP (uint32 block_height, const branch &d): BlockHeight {block_height}, Path {to_path (d)} {}

    digest256 inline BUMP::root () const {
        uint32 height = 0;
        ordered_list<node> current {};
        for (const ordered_list<node> &next : Path) {
            current = step (combine (current, next, height));
            height++;
        }

        return data::size (current) == 1 && bool (data::first (current).Digest) ? *data::first (current).Digest : digest256 {};
    }

}
