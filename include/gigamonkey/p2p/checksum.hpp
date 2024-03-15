// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_P2P_CHECKSUM
#define GIGAMONKEY_P2P_CHECKSUM

#include <gigamonkey/types.hpp>

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

        bytes_view payload () const;

        static check decode (string_view);
        std::string encode () const;

        check (byte version, bytes data);
        check (string_view s);
        check (bytes p);
        
        // try all single letter replacements, insertions, and deletions
        // to see if we can find a valid base58 check encoded string. 
        static check recover (const string_view invalid);

    private:
        check ();
    };

}

namespace Gigamonkey::Bitcoin {

    // A Bitcoin checksum takes the hash256 value of a string
    // and appends the last 4 bytes of the result. 
    check checksum (bytes_view b);

    bytes append_checksum (bytes_view b);

    bytes_view remove_checksum (bytes_view b);

}

namespace Gigamonkey::base58 {

    bool inline check::valid () const {
        return size() > 0;
    }

    byte inline check::version () const {
        if (!valid ()) return 0;
        return operator [] (0);
    }

    bytes_view inline check::payload () const {
        if (!valid ()) return {};
        return bytes_view (*this).substr (1);
    }

    inline check::check (byte version, bytes data) : bytes {write (data.size () + 1, version, data)} {}
    inline check::check (string_view s) : check {decode (s)} {}

    inline check::check () : bytes {} {};
    inline check::check (bytes p) : bytes {p} {}

}

#endif

