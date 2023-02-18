// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/wif.hpp>
#include <gigamonkey/timechain.hpp>
#include <gigamonkey/p2p/checksum.hpp>

namespace Gigamonkey::Bitcoin {
    
    secret WIF::decode (string_view s) {
        base58::check b58 (s);
        if (!b58.valid ()) return Bitcoin::secret {};
        Bitcoin::secret w {};

        if (b58.size () == 33) {
            w.Compressed = false;
        } else if (b58.size () == 34) {
            w.Compressed = true;
        } else return {};

        bytes_reader r (b58.data (), b58.data () + b58.size ());
        r >> (byte&) (w.Prefix);
        r.read(w.Secret.Value.data (), secp256k1::secret::Size);
        
        if (w.Compressed) {
            byte suffix;
            r >> suffix;
            if (suffix != CompressedSuffix) return Bitcoin::secret {};
        } 
        
        return w;
    }
    
    WIF WIF::encode (byte prefix, const secp256k1::secret& s, bool compressed) {
        bytes data (compressed ? CompressedSize - 1: UncompressedSize - 1);
        bytes_writer w (data.begin (), data.end ());
        w << bytes_view (s.Value);
        if (compressed) w << CompressedSuffix;

        WIF wif;
        static_cast<string&> (wif) = base58::check {prefix, data}.encode ();
        return wif;
    }
    
}

