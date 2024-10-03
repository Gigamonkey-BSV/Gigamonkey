// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/p2p/checksum.hpp>
#include <gigamonkey/schema/hd.hpp>
#include <data/encoding/base58.hpp>
#include <data/arithmetic/endian.hpp>
#include <data/io/unimplemented.hpp>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hmac.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/pwdbased.h>
#include <boost/locale.hpp>
#include <cmath>
//#include <unicode/normalizer2.h>
//#include <unicode/utypes.h>
//#include <unicode/unistr.h>
#include <bitset>

namespace Gigamonkey::HD::BIP_32 {

    uint256 CURVE_ORDER = secp256k1::secret::order ();

    uint32_t fp (const digest160 &hash) {
        const byte *hsh = hash.data ();
        return (uint32_t) hsh[0] << 24 | (uint32_t) hsh[1] << 16 | (uint32_t) hsh[2] << 8 | (uint32_t) hsh[3];
    }

    secret derive (const secret &sec, uint32 child) {
        Bitcoin::pubkey pub = sec.Secret.to_public ();
        
        secret derived;
        derived.Depth = sec.Depth + 1;
        derived.Parent = fp (Bitcoin::Hash160 (pub));
        derived.Sequence = child;
        derived.Net = sec.Net;
        
        bool is_hardened = child >= 0x80000000;
        
        data::bytes data_bytes (32);
        
        if (is_hardened) {
            std::copy (sec.Secret.Value.begin (), sec.Secret.Value.end (), data_bytes.begin ());
            data_bytes.insert (data_bytes.begin (), (byte) 0);
        } else {
            data_bytes.clear ();
            for (byte &b : pub) {
                data_bytes.push_back (b);
            }
        }
        
        data_bytes.push_back (child >> 24);
        data_bytes.push_back ((child >> 16) & 0xff);
        data_bytes.push_back ((child >> 8) & 0xff);
        data_bytes.push_back (child & 0xff);
        
        byte hmaced[CryptoPP::HMAC<CryptoPP::SHA512>::DIGESTSIZE];
        try {
            CryptoPP::HMAC<CryptoPP::SHA512> hmac (sec.ChainCode.data (), sec.ChainCode.size ());
            hmac.Update (reinterpret_cast<const byte *> (data_bytes.data()), data_bytes.size ());
            hmac.Final (hmaced);
        } catch (const CryptoPP::Exception &e) {
            std::cerr << e.what () << std::endl;
        }
        
        bytes left;
        for (int i = 0; i < 32; i++) left.push_back (hmaced[i]);
        
        std::reverse (left.begin (), left.end ());
        uint256 ll = uint256 {};
        
        std::copy (left.begin (), left.end (), ll.begin ());
        
        if (ll > CURVE_ORDER) return derive (sec, child + 1);
        
        uint256 k = uint256 {};
        std::copy (sec.Secret.Value.begin (), sec.Secret.Value.end (), k.begin ());
        std::reverse (k.begin (), k.end ());
        
        auto keyCode = (N) ll;
        keyCode += (N) k;
        keyCode %= (N) CURVE_ORDER;
        
        if (keyCode == 0)
            return derive (sec, child + 1);

        bytes child_key;
        
        for (unsigned char &itr2 : k)
            child_key.push_back (itr2);
        
        uint256 key = uint256 (keyCode);
        std::reverse (key.begin (), key.end ());
        derived.Secret = secp256k1::secret {key};
        for (int i = 32; i < 64; i++)
            derived.ChainCode.push_back (hmaced[i]);
        return derived;
    }
    
    pubkey derive (const pubkey &pub, uint32 child) {
        pubkey derived;
        derived.Depth = pub.Depth + 1;
        derived.Parent = fp (Bitcoin::Hash160 (pub.Pubkey));
        derived.Sequence = child;
        derived.Net = pub.Net;

        bool is_hardened = child >= 0x80000000;

        data::bytes data_bytes (0);

        if (is_hardened)
            return pubkey ();
        data_bytes.clear ();
        for (auto &b : pub.Pubkey)
            data_bytes.push_back (b);

        data_bytes.push_back (child >> 24);
        data_bytes.push_back ((child >> 16) & 0xff);
        data_bytes.push_back ((child >> 8) & 0xff);
        data_bytes.push_back (child & 0xff);

        byte hmaced[CryptoPP::HMAC<CryptoPP::SHA512>::DIGESTSIZE];
        try {
            CryptoPP::HMAC<CryptoPP::SHA512> hmac (pub.ChainCode.data (), pub.ChainCode.size ());
            hmac.Update (reinterpret_cast<const byte *> (data_bytes.data ()), data_bytes.size ());
            hmac.Final (hmaced);
        } catch (const CryptoPP::Exception &e) {
            std::cerr << e.what () << std::endl;
        }

        bytes left;
        for (int i = 0; i < 32; i++)
            left.push_back (hmaced[i]);
        uint256 ll = uint256 {};

        std::copy (left.begin (), left.end (), ll.begin ());

        if (ll > CURVE_ORDER)
            return derive (pub, child + 1);

        secp256k1::secret key;
        std::copy (left.begin (), left.end (), key.Value.begin ());
        secp256k1::pubkey pubkey = pub.Pubkey + key;
        derived.Pubkey = pubkey;
        bytes child_key;
        for (int i = 32; i < 64; i++)
            derived.ChainCode.push_back (hmaced[i]);
        return derived;
    }

    secret secret::read (string_view str) {
        Gigamonkey::base58::check tmp (str);
        secret secret1;
        if (!tmp.valid ())
            return secret ();

        auto view = tmp.payload ();
        if (view.length () != 77)
            return secret ();

        secret1.Net = main;
        bytes prv = bytes ({0x88, 0xAD, 0xE4});

        auto check = view.substr (0, 3);
        if (prv != check)
            return secret ();

        iterator_reader r (view.begin () + 3, view.end ());
        
        byte depth;
        r >> depth;
        secret1.Depth = depth;
        uint32_big parent;
        r >> parent;
        secret1.Parent = parent;
        uint32_big sequence;
        
        r >> sequence;
        secret1.Sequence = sequence;
        bytes_view chain_code = view.substr (12, 32);
        bytes_view key = view.substr (12 + 32 + 1);

        uint256 keyuint;

        auto tmpItr = key.begin ();
        auto keyItr = keyuint.begin ();
        while (tmpItr != key.end ()) {
            *keyItr = *tmpItr;
            keyItr++;
            tmpItr++;
        }

        secret1.ChainCode = bytes (32);
        std::copy (chain_code.begin (), chain_code.end (), secret1.ChainCode.begin ());
        secret1.Secret = secp256k1::secret {keyuint};
        return secret1;
    }

    secret secret::from_seed (seed entropy, type net) {
        const char *keyText = "Bitcoin seed";
        byte hmaced[CryptoPP::HMAC<CryptoPP::SHA512>::DIGESTSIZE];
        try {
            CryptoPP::HMAC<CryptoPP::SHA512> hmac (reinterpret_cast<const unsigned char *> (keyText), strlen (keyText));
            hmac.Update (entropy.data (), entropy.size ());
            hmac.Final (hmaced);
        } catch (const CryptoPP::Exception &e) {
            std::cerr << e.what () << std::endl;
        }

        secret secret1;
        std::copy (std::begin (hmaced), std::begin (hmaced) + 32, secret1.Secret.Value.begin ());
        secret1.ChainCode = chain_code ();
        for (int i = 0; i < 32; i++)
            secret1.ChainCode.push_back (hmaced[32 + i]);

        secret1.Net = net;
        secret1.Depth = 0;
        secret1.Parent = 0;
        secret1.Sequence = 0;
        return secret1;
    }

    string secret::write () const {
        bytes output;

        bytes prv = bytes ({0x88, 0xAD, 0xE4});
        for (int i = 0; i < prv.size (); i++)
            output.push_back (prv[i]);
        output.push_back (Depth);
        output.push_back ((uint32_t) Parent >> 24);
        output.push_back (((uint32_t) Parent >> 16) & 0xff);
        output.push_back (((uint32_t) Parent >> 8) & 0xff);
        output.push_back ((uint32_t) Parent & 0xff);
        output.push_back ((uint32_t) Sequence >> 24);
        output.push_back (((uint32_t) Sequence >> 16) & 0xff);
        output.push_back (((uint32_t) Sequence >> 8) & 0xff);
        output.push_back ((uint32_t) Sequence & 0xff);
        bytes chain_value (ChainCode.size ());
        std::reverse_copy (ChainCode.begin (), ChainCode.end (), chain_value.begin ());
        auto itr2 = ChainCode.begin ();
        while (itr2 != ChainCode.end ())
            output.push_back (*itr2++);

        output.push_back (0);
        bytes sec_value (Secret.Value.size ());
        std::reverse_copy (Secret.Value.begin (), Secret.Value.end(), sec_value.begin());
        auto itr = Secret.Value.begin ();

        while (itr != Secret.Value.end ()) {
            output.push_back (*itr++);
        }
        Gigamonkey::base58::check outputString (0x04, output);
        return outputString.encode ();
    }

    pubkey secret::to_public () const {
        pubkey pu;
        pu.Depth = Depth;
        pu.Sequence = Sequence;
        pu.Net = Net;
        pu.ChainCode = bytes (32);
        std::copy (ChainCode.begin (), ChainCode.end(), pu.ChainCode.begin());
        pu.Parent = Parent;
        pu.Pubkey = Secret.to_public ();
        return pu;
    }

    bool secret::operator == (const secret &rhs) const {
        return std::tie (Secret, ChainCode, Net, Depth, Parent, Sequence) ==
               std::tie (rhs.Secret, rhs.ChainCode, rhs.Net, rhs.Depth, rhs.Parent, rhs.Sequence);
    }

    bool secret::operator != (const secret &rhs) const {
        return !(rhs == *this);
    }

    string pubkey::write () const {
        bytes output;
        bytes prv = bytes ({0x88, 0xB2, 0x1E});
        for (int i = 0; i < prv.size (); i++)
            output.push_back (prv[i]);
        output.push_back (Depth);
        output.push_back ((uint32_t) Parent >> 24);
        output.push_back (((uint32_t) Parent >> 16) & 0xff);
        output.push_back (((uint32_t) Parent >> 8) & 0xff);
        output.push_back ((uint32_t) Parent & 0xff);
        output.push_back ((uint32_t) Sequence >> 24);
        output.push_back (((uint32_t) Sequence >> 16) & 0xff);
        output.push_back (((uint32_t) Sequence >> 8) & 0xff);
        output.push_back ((uint32_t) Sequence & 0xff);
        auto itr2 = ChainCode.begin ();
        while (itr2 != ChainCode.end ())
            output.push_back (*itr2++);

        auto itr = Pubkey.begin ();
        while (itr != Pubkey.end ())
            output.push_back (*itr++);

        Gigamonkey::base58::check outputString (0x04, output);
        return outputString.encode ();
    }

    pubkey pubkey::from_seed (seed entropy, type net) {
        return secret::from_seed (entropy, net).to_public ();
    }

    pubkey pubkey::read (string_view str) {
        Gigamonkey::base58::check tmp (str);
        pubkey pubkey1;
        if (!tmp.valid ()) return pubkey ();
        auto view = tmp.payload ();
        if (view.length () != 77) return pubkey ();

        pubkey1.Net = main;
        bytes prv = bytes ({0x88, 0xB2, 0x1E});
        auto check = view.substr (0, 3);
        if (prv != check) return pubkey ();
        iterator_reader r (view.begin () + 3, view.end ());
        
        byte depth;
        r >> depth;
        pubkey1.Depth = depth;
        uint32_big parent;
        r >> parent;
        pubkey1.Parent = parent;
        uint32_big sequence;
        
        r >> sequence;
        pubkey1.Sequence = sequence;
        //sequence |= view[12] & 0xff;
        bytes_view chain_code = view.substr (12, 32);
        bytes_view key = view.substr (12 + 32);

        pubkey1.Pubkey.resize (33);
        std::copy (key.begin (), key.end (), pubkey1.Pubkey.begin ());
        pubkey1.ChainCode.resize (32);
        std::copy (chain_code.begin (), chain_code.end (), pubkey1.ChainCode.begin ());
        return pubkey1;
    }

    bool pubkey::operator == (const pubkey &rhs) const {
        return std::tie (Pubkey, ChainCode, Net, Depth, Parent, Sequence) ==
               std::tie (rhs.Pubkey, rhs.ChainCode, rhs.Net, rhs.Depth, rhs.Parent, rhs.Sequence);
    }

    bool pubkey::operator != (const pubkey &rhs) const {
        return !(rhs == *this);
    }
    
    path read_path (string_view p) {
        if (p.empty ()) return {};
        list<uint32> paths;
        uint32_t i = 0;
        uint64_t n = 0;
        while (i < p.size ()) {
            char current = p[i];
            if (current >= '0' && current <= '9') {
                n *= 10;
                n += current - '0';
                if (n >= 0x80000000)
                    return {};
                i++;
                if (i >= p.size ())
                    paths = paths << n;
            } else if (current == '\'') {
                n |= 0x80000000;
                paths = paths << n;
                n = 0;
                i += 2;
            } else if (current == '/') {
                if (i + 1 >= p.size () || p[i + 1] < '0' || p[i + 1] > '9')
                    return {};
                paths = paths << n;
                n = 0;
                i++;
            }
        }

        return paths;
    }
}
