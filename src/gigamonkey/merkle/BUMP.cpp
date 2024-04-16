// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/merkle/BUMP.hpp>

namespace Gigamonkey::Merkle {

    BUMP::operator bytes () const {
        bytes b (serialized_size ());
        bytes_writer w {b.begin (), b.end ()};
        w << *this;
        return b;
    }

    BUMP::BUMP (bytes_view b) {
        try {
            bytes_reader r {b.begin (), b.end ()};
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

    BUMP::operator JSON () const {

        JSON::object_t jx;

        jx["blockHeight"] = BlockHeight;
        jx["path"] = JSON_write_paths (Path);

        return jx;

    }

    BUMP::nodes read_paths (const JSON &j);

    BUMP::BUMP (const JSON &j): BlockHeight {j["blockHeight"]}, Path {read_paths (j["path"])} {}

/*
    list<list<node>> BUMP::to (const Merkle::dual &) {}

    Merkle::dual BUMP::from (const list<ordered_list<node>>) {

    }
*/
}
