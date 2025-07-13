// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/merkle/BUMP.hpp>

namespace Gigamonkey::Merkle {

    writer &operator << (writer &w, const BUMP::node &h) {
        w << Bitcoin::var_int {h.Offset};
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

    writer &operator << (writer &w, const BUMP &h) {
        w << Bitcoin::var_int {h.BlockHeight};

        w << h.depth ();

        for (const auto &level : h.Path)
            Bitcoin::var_sequence<BUMP::node>::write (w, level);

        return w;
    }

    reader &operator >> (reader &r, BUMP &h) {
        Bitcoin::var_int block_height;
        r >> block_height;
        byte depth;
        r >> depth;

        list<ordst<BUMP::node>> tree;
        for (int i = 0; i < depth; i++) {
            stack<BUMP::node> nodes;

            Bitcoin::var_sequence<BUMP::node>::read (r, nodes);

            ordst<BUMP::node> nnnn;
            for (const BUMP::node &n : nodes) nnnn >>= n;
            tree <<= nnnn;
        }

        h = BUMP {block_height.Value, tree};

        return r;
    }

    uint32 inline next_offset (uint32 offset) {
        return ((offset & ~2) | (~offset & 2)) >> 1;
    }

    uint64 BUMP::serialized_size () const {
        uint64 z = Bitcoin::var_int::size (BlockHeight) + 1;

        for (const ordst<node> &nnn : Path) {
            z += Bitcoin::var_int::size (size (nnn));

            for (const node &n : nnn) z += n.serialized_size ();
        }

        return z;
    }

    BUMP::node::operator JSON () const {
        if (!valid ()) throw exception {} << "invalid BUMP";
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

    BUMP::node::node (const JSON &j): Offset {}, Flag {}, Digest {} {
        if (!j.is_object () || !j.contains ("offset")) throw exception {} << "invalid BUMP node JSON format!";

        Offset = j["offset"];

        if (j.contains ("duplicate") && bool (j["duplicate"])) {
            Flag = flag::duplicate;
            return;
        }

        Digest = Gigamonkey::read_reverse_hex<32> (std::string (j["hash"]));

        Flag = j.contains ("txid") && bool (j["txid"]) ? flag::client : flag::intermediate;
    }

    namespace {
        JSON JSON_write_path (ordst<BUMP::node> nodes) {
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
            if (!j.is_array () || j.size () == 0) throw exception {} << "invalid BUMP JSON format!";

            list<ordst<BUMP::node>> nodes;
            for (const JSON &k : j) {
                ordst<BUMP::node> level;
                for (auto a = k.rbegin (); a != k.rend (); a++) level >>= BUMP::node {*a};
                nodes <<= level;
            }

            return nodes;
        }

        BUMP::nodes to_path (const branch &b) {

            digest last = b.Leaf.Digest;
            list<ordst<BUMP::node>> nodes;
            ordst<BUMP::node> level {BUMP::node {b.Leaf.Index, BUMP::flag::client, b.Leaf.Digest}};

            uint32 path_index = (b.Leaf.Index & ~1) | (~b.Leaf.Index & 1);

            for (const maybe<digest> &next : b.Digests) {
                if (bool (next)) {
                    level >>= BUMP::node {path_index, BUMP::flag::intermediate, *next};
                    last = hash_concatinated (last, *next);
                } else {
                    level >>= BUMP::node {path_index};
                    last = hash_concatinated (last, last);
                }

                nodes <<= level;
                path_index = next_offset (path_index);
                level = ordst<BUMP::node> {};
            }

            return nodes;
        }
    }

    BUMP::operator bytes () const {
        if (!valid ()) throw exception {} << "invalid BUMP";
        bytes b (serialized_size ());
        it_wtr w {b.begin (), b.end ()};
        w << *this;
        return b;
    }

    BUMP::BUMP (const bytes &b) {
        try {
            it_rdr r {b.data (), b.data () + b.size ()};
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

    BUMP::BUMP (uint64 block_height, const branch &d): BlockHeight {block_height}, Path {to_path (d)} {}

    BUMP::BUMP (const JSON &j): BlockHeight {}, Path {} {
        if (!j.is_object () || !j.contains ("path") || !j.contains ("blockHeight") || !j["blockHeight"].is_number ())
            throw exception {} << "invalid BUMP JSON format";

        const JSON &height = j["blockHeight"];
        if (!height.is_number () || height < 0) throw exception {} << "invalid BUMP JSON format: invalid field 'blockHeight'";

        Path = read_paths (j["path"]);
        BlockHeight = uint64 (j["blockHeight"]);
    }

    BUMP::BUMP (uint64 block_height, map m): BlockHeight {block_height}, Path {} {
        auto b = m.begin ();
        if (b == m.end ()) return;
        for (uint64 i = 0; i < size ((*b).Value.Digests); i++) Path <<= ordst<node> {};
        for (const auto &e : m) *this = *this + branch {e.Key, e.Value};
    }

    namespace {
        ordst<BUMP::node> combine (ordst<BUMP::node> A, ordst<BUMP::node> B) {
            stack<BUMP::node> a = reverse (static_cast<stack<BUMP::node>> (A));
            stack<BUMP::node> b = reverse (static_cast<stack<BUMP::node>> (B));

            ordst<BUMP::node> result;
            while (!empty (a) || !empty (b))
                if (!empty (a) && (empty (b) || first (a).Offset < first (b).Offset)) {
                    result = result.insert (first (a));
                    a = rest (a);
                } else if (!empty (b) && (empty (a) || first (a).Offset > first (b).Offset)) {
                    result = result.insert (first (b));
                    b = rest (b);
                } else {
                    // in this case, we are combining two lists with the same node. It doesn't matter
                    // which one we pick unless one is a client tx and the other isn't.
                    // it is also possible that one of these says to duplicate the hash and the
                    // other doesn't. In that case we pick the one that says to duplicate.
                    result = result.insert (
                        first (a).Flag == BUMP::flag::client ? first (a) :
                        first (b).Flag == BUMP::flag::client ? first (b) :
                        first (a).Flag == BUMP::flag::duplicate ? first (a) :
                        first (b).Flag == BUMP::flag::duplicate ? first (b) : first (a));
                    a = rest (a);
                    b = rest (b);
                }
            return result;
        }

        // thrown when an error is found during validation.
        struct validation_error {};

        // calculate the next layer of merkle nodes as part of the validation process.
        ordst<BUMP::node> step (ordst<BUMP::node> x) {

            // the elements of the node should be organized in pairs, either
            // adjacent nodes of the full tree or a digest and a note saying
            // to duplicate it.
            if (size (x) % 2 == 1) throw validation_error {};

            stack<BUMP::node> nodes = reverse (static_cast<stack<BUMP::node>> (x));

            ordst<BUMP::node> result;
            while (size (nodes) > 0) {
                if ((nodes[0].Offset >> 1) != (nodes[1].Offset >> 1) || nodes[1].Offset + 1 != nodes[0].Offset) throw validation_error {};

                result = result.insert (BUMP::node {nodes[0].Offset >> 1, BUMP::flag::intermediate, hash_concatinated (*nodes[1].Digest,
                    nodes[0].Flag == BUMP::flag::duplicate ? *nodes[1].Digest : *nodes[0].Digest)});

                nodes = rest (rest (nodes));

            }

            return result;
        }
    }

    bool BUMP::validate (const Bitcoin::TXID &expected_root) const {
        try {
            return expected_root == root ();
        } catch (const validation_error &) {
            return false;
        }
    }

    BUMP operator + (const BUMP &a, const BUMP &b) {
        if (a.BlockHeight != b.BlockHeight) return {};

        BUMP::nodes left = a.Path;
        BUMP::nodes right = b.Path;
        BUMP::nodes result;

        uint32 height = 0;
        while (size (left) > 0) {
            result <<= combine (first (left), first (right));
            left = rest (left);
            right = rest (right);
            height++;
        }

        return BUMP {a.BlockHeight, result}.remove_unnecessary_nodes ();
    }

    digest256 BUMP::root () const {
        ordst<node> current {};

        for (const ordst<node> &next : Path)
            current = step (combine (current, next));

        return size (current) == 1 && bool (first (current).Digest) ? *first (current).Digest : digest256 {};
    }

    namespace {
        struct unnecessary_removed {
            ordst<uint64> AvailableNodesLastLevel {};

            ordst<BUMP::node> UnnecessaryRemoved {};
        };

        unnecessary_removed remove_unnecessary (ordst<BUMP::node> current, ordst<uint64> available_last_level) {
            ordst<uint64> generated_next_level;

            ordst<uint64> available = available_last_level;
            while (!empty (available)) {
                generated_next_level = generated_next_level.insert (first (available) >> 1);
                available = rest (rest (available));
            }

            unnecessary_removed result;

            while (!empty (current) || !empty (generated_next_level))
                if (!empty (current) && (empty (generated_next_level) ||
                    first (current).Offset <= first (generated_next_level))) {

                    while (!empty (available_last_level) && first (available_last_level) < (first (current).Offset << 1))
                        available_last_level = rest (available_last_level);

                    // if we didn't generate both of the lower nodes, then we can remove this one.
                    if (size (available_last_level) < 2 ||
                        available_last_level[0] != (first (current).Offset << 1) ||
                        available_last_level[1] != (first (current).Offset << 1) + 1)
                        result.UnnecessaryRemoved = result.UnnecessaryRemoved.insert (first (current));

                    result.AvailableNodesLastLevel = result.AvailableNodesLastLevel.insert (first (current).Offset);
                    if (!empty (generated_next_level) && first (current).Offset == first (generated_next_level))
                        generated_next_level = rest (generated_next_level);

                    current = rest (current);
                } else {
                    result.AvailableNodesLastLevel = result.AvailableNodesLastLevel.insert (first (generated_next_level));
                    generated_next_level = rest (generated_next_level);
                }

            return result;
        }
    }

    BUMP BUMP::remove_unnecessary_nodes () const {
        nodes paths;
        ordst<uint64> generated;
        for (const auto &level : Path) {
            auto removed = remove_unnecessary (level, generated);
            generated = removed.AvailableNodesLastLevel;
            paths <<= removed.UnnecessaryRemoved;
        }

        return BUMP {BlockHeight, paths};
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

        ordst<ptr<smash>> path_next_layer (ordst<ptr<smash>>, ordst<BUMP::node>);

        void read_down (map &, ptr<smash>, digests = {});
    }

    map BUMP::paths () const {
        ordst<ptr<smash>> smashes;
        for (const ordst<node> &n : Path) smashes = path_next_layer (smashes, n);
        map m;
        read_down (m, smashes[0]);
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

        ordst<ptr<smash>> path_next_layer (ordst<ptr<smash>> Generated, ordst<BUMP::node> Provided) {

            stack<ptr<smash>> generated = reverse (static_cast<stack<ptr<smash>>> (Generated));
            stack<BUMP::node> provided = reverse (static_cast<stack<BUMP::node>> (Provided));

            ordst<ptr<smash>> to_smash;
            while (!empty (generated) || !empty (provided)) {
                if (!empty (generated) && (empty (provided) || first (generated)->Offset < first (provided).Offset)) {
                    to_smash = to_smash.insert (first (generated));
                    generated = rest (generated);
                } else if (!empty (provided) && (empty (generated) || first (generated)->Offset > first (provided).Offset)) {
                    to_smash = to_smash.insert (std::make_shared<smash> (first (provided)));
                    provided = rest (provided);
                } else {
                    to_smash = to_smash.insert (first (generated));
                    generated = rest (generated);
                    provided = rest (provided);
                }
            }

            ordst<ptr<smash>> smashed;

            while (!empty (to_smash)) {
                smashed = smashed.insert (smash_together (to_smash[0], to_smash[1]));
                to_smash = rest (rest (to_smash));
            }

            return smashed;
        }

        void read_down (map &m, ptr<smash> z, digests d) {
            if (z->Flag == BUMP::flag::client) {
                m = m.insert (*z->Digest, path {z->Offset, d});
                return;
            }

            if (z->Right == nullptr && z->Left == nullptr) return;

            read_down (m, z->Left, d >> (z->Right->Flag == BUMP::flag::duplicate ? *z->Left->Digest : *z->Right->Digest));

            read_down (m, z->Right, d >> *z->Left->Digest);
        }
    }
}
