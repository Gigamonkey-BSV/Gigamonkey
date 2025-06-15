// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_P2P_CHECKSUM
#define GIGAMONKEY_P2P_CHECKSUM

#include <gigamonkey/hash.hpp>

namespace Gigamonkey::base58 {

    // A base 58 check encoded string. 
    // The first byte is a version byte. 
    // The rest is the payload. 

    // In base 58 check encoding, each initial
    // zero bytes are written as a '1'. The rest
    // is encoded as a base 58 number. 
    struct check : bytes {

        bool valid () const;

        byte version () const;

        slice<const byte> payload () const;

        static check decode (string_view);
        std::string encode () const;

        check (byte version, const bytes &data);
        check (string_view s);
        check (const bytes &p);
        
        // try all single letter replacements, insertions, and deletions
        // to see if we can find a valid base58 check encoded string. 
        static check recover (const string_view invalid);

        struct writer : data::crypto::hash::Bitcoin<32> {
            check finalize ();
        };

    private:
        check ();
    };

}

namespace Gigamonkey::Bitcoin {

    // A Bitcoin checksum takes the hash256 value of a string
    // and appends the last 4 bytes of the result. 
    check checksum (slice<const byte> b);

    bytes append_checksum (slice<const byte> b);

    slice<const byte> remove_checksum (slice<const byte> b);

}

namespace Gigamonkey::base58 {

    bool inline check::valid () const {
        return size () > 0;
    }

    byte inline check::version () const {
        if (!valid ()) return 0;
        return operator [] (0);
    }

    slice<const byte> inline check::payload () const {
        if (!valid ()) return {};
        return slice<const byte> (*this).drop (1);
    }

    inline check::check (byte version, const bytes &data) : bytes {write (data.size () + 1, version, data)} {}
    inline check::check (string_view s) : check {decode (s)} {}

    inline check::check () : bytes {} {};
    inline check::check (const bytes &p) : bytes {p} {}

}

#endif

