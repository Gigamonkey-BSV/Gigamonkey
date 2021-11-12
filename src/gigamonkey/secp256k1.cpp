// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2018-2019 Bitcoin Association
// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/secp256k1.hpp>
#include <data/encoding/integer.hpp>
#include <secp256k1.h>

namespace Gigamonkey::secp256k1 {
    
    bool signature::valid(bytes_view x) {
        size_t size = x.size();
        if (size < 6 || x[0] != 0x30 || x[1] != size - 2 || x[2] != 0x02) return false;
        size_t r_size = x[3];
        if (size < r_size + 6 || x[4 + r_size] != 0x02) return false;
        size_t s_size = x[5 + r_size];
        return size >= r_size + s_size + 6;
    }
    
    bool signature::minimal(bytes_view x) {
        if (!valid(x)) return false; 
        size_t size = x.size();
        size_t r_size = x[3];
        size_t s_size = x[5 + r_size];
        return size == 6 + r_size + s_size && r_size != 0 && s_size != 0 && 
            (x[4] != 0 || (r_size > 1 && x[5] & 0x80)) && 
            (x[6 + r_size] != 0 || (s_size > 1 && x[7 + r_size] & 0x80));
    }
    
    /**
    * This function is taken from the libsecp256k1 distribution and implements DER
    * parsing for ECDSA signatures, while supporting an arbitrary subset of format
    * violations.
    *
    * Supported violations include negative integers, excessive padding, garbage at
    * the end, and overly long length descriptors. This is safe to use in Bitcoin
    * because since the activation of BIP66, signatures are verified to be strict
    * DER before being passed to this module, and we know it supports all
    * violations present in the blockchain before that point.
    */
    static int ecdsa_signature_parse_der_lax(const secp256k1_context *ctx,
                                            secp256k1_ecdsa_signature *sig,
                                            const uint8_t *input,
                                            size_t inputlen) {
        size_t rpos, rlen, spos, slen;
        size_t pos = 0;
        size_t lenbyte;
        uint8_t tmpsig[64] = {0};
        int overflow = 0;

        /* Hack to initialize sig with a correctly-parsed but invalid signature. */
        secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);

        /* Sequence tag byte */
        if (pos == inputlen || input[pos] != 0x30) {
            return 0;
        }
        pos++;

        /* Sequence length bytes */
        if (pos == inputlen) {
            return 0;
        }
        lenbyte = input[pos++];
        if (lenbyte & 0x80) {
            lenbyte -= 0x80;
            if (pos + lenbyte > inputlen) {
                return 0;
            }
            pos += lenbyte;
        }

        /* Integer tag byte for R */
        if (pos == inputlen || input[pos] != 0x02) {
            return 0;
        }
        pos++;

        /* Integer length for R */
        if (pos == inputlen) {
            return 0;
        }
        lenbyte = input[pos++];
        if (lenbyte & 0x80) {
            lenbyte -= 0x80;
            if (pos + lenbyte > inputlen) {
                return 0;
            }
            while (lenbyte > 0 && input[pos] == 0) {
                pos++;
                lenbyte--;
            }
            if (lenbyte >= sizeof(size_t)) {
                return 0;
            }
            rlen = 0;
            while (lenbyte > 0) {
                rlen = (rlen << 8) + input[pos];
                pos++;
                lenbyte--;
            }
        } else {
            rlen = lenbyte;
        }
        if (rlen > inputlen - pos) {
            return 0;
        }
        rpos = pos;
        pos += rlen;

        /* Integer tag byte for S */
        if (pos == inputlen || input[pos] != 0x02) {
            return 0;
        }
        pos++;

        /* Integer length for S */
        if (pos == inputlen) {
            return 0;
        }
        lenbyte = input[pos++];
        if (lenbyte & 0x80) {
            lenbyte -= 0x80;
            if (pos + lenbyte > inputlen) {
                return 0;
            }
            while (lenbyte > 0 && input[pos] == 0) {
                pos++;
                lenbyte--;
            }
            if (lenbyte >= sizeof(size_t)) {
                return 0;
            }
            slen = 0;
            while (lenbyte > 0) {
                slen = (slen << 8) + input[pos];
                pos++;
                lenbyte--;
            }
        } else {
            slen = lenbyte;
        }
        if (slen > inputlen - pos) {
            return 0;
        }
        spos = pos;
        pos += slen;

        /* Ignore leading zeroes in R */
        while (rlen > 0 && input[rpos] == 0) {
            rlen--;
            rpos++;
        }
        /* Copy R value */
        if (rlen > 32) {
            overflow = 1;
        } else {
            memcpy(tmpsig + 32 - rlen, input + rpos, rlen);
        }

        /* Ignore leading zeroes in S */
        while (slen > 0 && input[spos] == 0) {
            slen--;
            spos++;
        }
        /* Copy S value */
        if (slen > 32) {
            overflow = 1;
        } else {
            memcpy(tmpsig + 64 - slen, input + spos, slen);
        }

        if (!overflow) {
            overflow = !secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
        }
        if (overflow) {
            /* Overwrite the result again with a correctly-parsed but invalid
            signature if parsing failed. */
            memset(tmpsig, 0, 64);
            secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
        }
        return 1;
    }
    
    class context {
        mutable secp256k1_context* Context;
    public:
        int Flags;
        
        context(int flags) : Context{nullptr}, Flags{flags} {}
        
        secp256k1_context* operator()() const {
            if (Context == nullptr) Context = secp256k1_context_create(Flags);
            return Context;
        }
        
        ~context() {
            if (Context != nullptr) secp256k1_context_destroy(Context);
        }
    } Verification{SECP256K1_CONTEXT_VERIFY}, Signing{SECP256K1_CONTEXT_SIGN};
    
    bool signature::normalized(const bytes_view vchSig) {
        secp256k1_ecdsa_signature sig;
        if (!ecdsa_signature_parse_der_lax(Verification(), &sig, &vchSig[0], vchSig.size())) return false;
        return (!secp256k1_ecdsa_signature_normalize(Verification(), nullptr, &sig));
    }
    
    bool secret::valid(bytes_view sk) {
        return secp256k1_ec_seckey_verify(Verification(), sk.data()) == 1;
    }
    
    bool pubkey::valid(bytes_view pk) {
        secp256k1_pubkey pubkey;
        return secp256k1_ec_pubkey_parse(Verification(), &pubkey, pk.data(), pk.size());
    }
    
    bool serialize(const secp256k1_context* context, bytes& p, const secp256k1_pubkey& pubkey) {
        auto size = p.size();
        secp256k1_ec_pubkey_serialize(context, p.data(), &size, &pubkey, 
            size == pubkey::CompressedSize ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
        return size == p.size();
    }
    
    bytes secret::to_public_compressed(bytes_view sk) {
        bytes p = bytes(pubkey::CompressedSize);
        secp256k1_pubkey pubkey;
        auto context = Signing();
        return secp256k1_ec_pubkey_create(context, &pubkey, sk.data()) == 1 && serialize(context, p, pubkey) ? p : 0;
    }
    
    bytes secret::to_public_uncompressed(bytes_view sk) {
        bytes p = bytes(pubkey::UncompressedSize);
        secp256k1_pubkey pubkey;
        auto context = Signing();
        return secp256k1_ec_pubkey_create(context, &pubkey, sk.data()) == 1 && serialize(context, p, pubkey) ? p : 0;
    }
    
    bool parse(const secp256k1_context* context, secp256k1_pubkey& out, bytes_view pk) {
        return secp256k1_ec_pubkey_parse(context, &out, pk.data(), pk.size()) == 1;
    }
    
    bytes pubkey::compress(bytes_view pk) {
        if (pk.size() == pubkey::CompressedSize) return bytes{pk};
        secp256k1_pubkey pubkey;
        bytes p(pubkey::CompressedSize);
        const auto context = Verification();
        return parse(context, pubkey, pk) && serialize(context, p, pubkey) ? p : 0;
    }
    
    bytes pubkey::decompress(bytes_view pk) {
        if (pk.size() == pubkey::UncompressedSize) return bytes{pk};
        secp256k1_pubkey pubkey;
        bytes p(pubkey::UncompressedSize);
        const auto context = Verification();
        return parse(context, pubkey, pk) && serialize(context, p, pubkey) ? p : 0;
    }
    
    coordinate pubkey::x() const {
        coordinate v{0};
        if (valid()) std::copy(this->begin() + 1, this->begin() + 33, v.begin());
        return v;
    }
        
    coordinate pubkey::y() const {
        coordinate v{0}; 
        if (valid()) {
            bytes_view decompressed = type() == uncompressed ? static_cast<bytes>(*this) : decompress(*this);
            std::copy(decompressed.begin() + 33, decompressed.end(), v.begin());
        };
        return v;
    }
    
    signature secret::sign(bytes_view sk, const digest& d) {
        secp256k1_ecdsa_signature x;
        auto context = Signing();
        if (secp256k1_ecdsa_sign(context, &x, d.Value.data(), sk.data(),
            secp256k1_nonce_function_rfc6979, nullptr) != 1) return {};
        
        signature sig{};
        sig.resize(signature::MaxSize);
        size_t size = sig.size();
        secp256k1_ecdsa_signature_serialize_der(context, sig.data(), &size, &x);
        sig.resize(size);
        return sig;
    }
    
    bool verify_signature(const secp256k1_context* context,
        const secp256k1_pubkey point, bytes_view hash,
        const secp256k1_ecdsa_signature& s) {
        
        secp256k1_ecdsa_signature normal;
        secp256k1_ecdsa_signature_normalize(context, &normal, &s);
        return secp256k1_ecdsa_verify(context, &normal, hash.data(), &point) == 1;
    }
    
    bool pubkey::verify(bytes_view pk, const digest& d, bytes_view s) {
        secp256k1_pubkey pubkey;
        const auto context = Verification();
        secp256k1_ecdsa_signature parsed;
        secp256k1_ecdsa_signature_parse_der(context, &parsed, s.data(), s.size());
        return parse(context, pubkey, pk) && verify_signature(context, pubkey, d, parsed);
    }
    
    uint256 secret::negate(const uint256& sk) {
        uint256 out{sk};
        return secp256k1_ec_privkey_negate(Verification(), out.data()) == 1 ? out : 0;
    }
    
    bytes pubkey::negate(bytes_view pk) {
        const auto context = Verification();
        secp256k1_pubkey pubkey;
        bytes out = bytes(pk.size());
        return parse(context, pubkey, pk) &&
            secp256k1_ec_pubkey_negate(context, &pubkey) == 1 &&
            serialize(context, out, pubkey) ? out : 0;
    }
    
    uint256 secret::plus(const uint256& sk_a, const uint256& sk_b) {
        const auto context = Verification();
        coordinate out{sk_a};
        return secp256k1_ec_privkey_tweak_add(context, out.data(),
            sk_b.data()) == 1;
    }
    
    uint256 secret::times(const uint256& sk_a, const uint256& sk_b) {
        const auto context = Verification();
        coordinate out{sk_a};
        return secp256k1_ec_privkey_tweak_mul(context, out.data(),
            sk_b.data()) == 1;
    }
    
    bytes pubkey::plus_pubkey(const bytes_view pk_a, bytes_view pk_b) {
        const auto context = Verification();
        secp256k1_pubkey pubkey;
        secp256k1_pubkey b;
        secp256k1_pubkey* keys[1];
        keys[0] = &b;
        if (!parse(context, b, pk_b)) return 0;
        
        bytes out = bytes(pk_a.size());
        return secp256k1_ec_pubkey_combine(context, &pubkey, keys, 1) == 1 && serialize(context, out, pubkey) ? out : 0;
    }
    
    bytes pubkey::plus_secret(const bytes_view pk, const uint256& sk) {
        const auto context = Verification();
        bytes out = bytes(pk.size());
        secp256k1_pubkey pubkey;
        return parse(context, pubkey, pk) &&
            secp256k1_ec_pubkey_tweak_add(context, &pubkey, sk.data()) == 1 &&
            serialize(context, out, pubkey) ? out : 0;
    }
    
    bytes pubkey::times(const bytes_view pk, bytes_view sk) {
        const auto context = Verification();
        bytes out{pk};
        secp256k1_pubkey pubkey;
        return parse(context, pubkey, pk) &&
            secp256k1_ec_pubkey_tweak_mul(context, &pubkey, sk.data()) == 1 &&
            serialize(context, out, pubkey) ? out : 0;
    }
    
}
