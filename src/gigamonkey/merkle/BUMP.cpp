// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/merkle/BUMP.hpp>

namespace Gigamonkey::Merkle {

    uint64 BUMP::serialized_size () const {
        uint64 size = Bitcoin::var_int::size (BlockHeight) + 1;

        for (const ordered_list<node> &nnn : Path) {
            size += Bitcoin::var_int::size (data::size (nnn));

            for (const node &n : nnn) size += n.serialized_size ();
        }

        return size;
    }

    writer &operator << (writer &w, const BUMP::node &h) {
        w << byte (h.Flag);
        if (bool (h.Digest)) w << *h.Digest;
        return w;
    }

    reader &operator >> (reader &r, BUMP::node &h) {
        Bitcoin::var_int offset;
        r >> offset;

        byte flag;
        r >> flag;

        if (BUMP::flag (flag) == BUMP::flag::duplicate)
            h = BUMP::node {offset.Value};
        else {
            digest d;
            r >> d;
            h = BUMP::node {offset.Value, BUMP::flag (flag), d};
        }

        return r;

    }

    BUMP::node::operator JSON () const {
        JSON::object_t j;
        j["offset"] = Offset;

        if (Flag == flag::duplicate) {
            j["duplicate"] = true;
            return j;
        }

        j["hash"] = Gigamonkey::write_reverse_hex (*Digest);

        if (Flag == flag::client) j["txid"] = true;

        return j;
    }

    BUMP::node::node (const JSON &j): Offset {j["offset"]}, Flag {}, Digest {} {
        if (j.contains ("duplicate") && bool (j["duplicate"])) {
            Flag = flag::duplicate;
            return;
        }

        Digest = Gigamonkey::read_reverse_hex<32> (std::string (j["hash"]));

        Flag = j.contains ("txid") && bool (j["txid"]) ? flag::client : flag::intermediate;
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

    reader &operator >> (reader &r, BUMP &h) {
        Bitcoin::var_int block_height;
        r >> block_height;
        byte depth;
        r >> depth;

        list<ordered_list<BUMP::node>> tree;
        for (int i = 0; i < depth; i++) {
            stack<BUMP::node> nodes;
            Bitcoin::var_int number_of_nodes;
            for (int j = 0; j < number_of_nodes; j++) {
                BUMP::node n {};
                r >> n;
                nodes <<= n;
            }

            ordered_list<BUMP::node> nnnn;
            for (const BUMP::node &n : data::reverse (nodes)) nnnn <<= n;
            tree <<= nnnn;
        }

        return r;
    }

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

        BUMP::nodes read_paths (const JSON &j) {
            list<ordered_list<BUMP::node>> nodes;
            for (const JSON &k : j) {
                ordered_list<BUMP::node> level;
                for (auto a = k.rbegin (); a != k.rend (); a++) level <<= BUMP::node {*a};
                nodes <<= level;
            }
            return nodes;
        }

        BUMP::nodes to_path (const branch &b) {
            uint32 path_index = b.Leaf.Index & 1 == 1 ? b.Leaf.Index - 1 : b.Leaf.Index + 1;

            digest last = b.Leaf.Digest;
            list<ordered_list<BUMP::node>> nodes;
            ordered_list<BUMP::node> level {BUMP::node {b.Leaf.Index, BUMP::flag::client, b.Leaf.Digest}};
            for (const digest &next : b.Digests) {
                level <<= last == next ? BUMP::node {path_index} : BUMP::node {path_index, BUMP::flag::intermediate, next};
                nodes <<= level;
                path_index >>= 1;
                last = hash_concatinated (last, next);
                level = ordered_list<BUMP::node> {};
            }

            return nodes;
        }
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

    BUMP::BUMP (uint64 block_height, const branch &d): BlockHeight {block_height}, Path {to_path (d)} {}

    digest256 BUMP::root () const {
        uint32 height = 0;
        ordered_list<node> current {};
        for (const ordered_list<node> &next : Path) {
            current = step (combine (current, next, height));
            height++;
        }

        return data::size (current) == 1 && bool (data::first (current).Digest) ? *data::first (current).Digest : digest256 {};
    }

    namespace {

        struct smash : BUMP::node {
            using BUMP::node::node;

            smash (const BUMP::node &n) : BUMP::node {n} {}

            ptr<smash> Left {nullptr};
            ptr<smash> Right {nullptr};
        };

        bool inline operator == (ptr<smash> a, ptr<smash> b) {
            return a->Offset == b->Offset && a->Digest == b->Digest;
        }

        std::weak_ordering inline operator <=> (ptr<smash> a, ptr<smash> b) {
            return a->Offset <=> b->Offset;
        }

        ordered_list<ptr<smash>> path_next_layer (ordered_list<ptr<smash>>, ordered_list<BUMP::node>);

        void read_down (map &, ptr<smash>, digests = {});
    }

    map BUMP::paths () const {
        ordered_list<ptr<smash>> smashes;
        for (const ordered_list<node> &n : Path) smashes = path_next_layer (smashes, n);
        map m;
        if (smashes[0]->Right != nullptr) read_down (m, smashes[0]->Right);
        if (smashes[0]->Left != nullptr) read_down (m, smashes[0]->Left);
        return m;
    }

    namespace {
        ptr<smash> smash_together (const ptr<smash> &a, const ptr<smash> &b) {
            ptr<smash> z {b->Flag == BUMP::flag::duplicate ?
                new smash {a->Offset >> 1, BUMP::flag::intermediate, hash_concatinated (*a->Digest, *a->Digest)}:
                new smash {a->Offset >> 1, BUMP::flag::intermediate, hash_concatinated (*a->Digest, *b->Digest)}};
            z->Left = a;
            z->Right = b;
            return z;
        }

        ordered_list<ptr<smash>> path_next_layer (ordered_list<ptr<smash>> zntz, ordered_list<BUMP::node> qbt) {
            auto qnf = zntz;
            auto lfo = qbt;

            while (!data::empty (lfo)) {
                qnf = qnf.insert (std::make_shared<smash> (lfo.first ()));
                lfo = lfo.rest ();
            }

            ordered_list<ptr<smash>> mzol;

            while (!data::empty (qnf)) {
                mzol = mzol.insert (smash_together (qnf[0], qnf[1]));
                qnf = qnf.rest ().rest ();
            }

            return mzol;
        }

        void read_down (map &m, ptr<smash> z, digests d) {
            // this will only happen for a block with just one tx in it.
            if (z->Right == nullptr && z->Left == nullptr) {
                m.insert (*z->Digest, path {z->Offset, d});

                return;
            }

            if (z->Right != nullptr && z->Left != nullptr && (z->Right->Flag == BUMP::flag::client || z->Left->Flag == BUMP::flag::client)) {

                if (z->Right->Flag == BUMP::flag::client) m.insert (*z->Right->Digest, path {z->Offset, d << *z->Left->Digest});

                if (z->Left->Flag == BUMP::flag::client) m.insert (*z->Left->Digest, path {z->Offset, d << *z->Right->Digest});

                return;
            }

            if (z->Left != nullptr) read_down (m, z->Left, d << *z->Digest);

            if (z->Right != nullptr) read_down (m, z->Right, d << *z->Digest);
        }
    }
}
