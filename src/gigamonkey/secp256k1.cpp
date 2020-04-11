// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/secp256k1.hpp>
#include <data/encoding/integer.hpp>

namespace Gigamonkey::secp256k1 {
    
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
            size == CompressedPubkeySize ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
        return size == p.size();
    }
    
    bytes secret::to_public_compressed(bytes_view sk) {
        bytes p = bytes(CompressedPubkeySize);
        secp256k1_pubkey pubkey;
        auto context = Signing();
        return secp256k1_ec_pubkey_create(context, &pubkey, sk.data()) == 1 && serialize(context, p, pubkey) ? p : 0;
    }
    
    bytes secret::to_public_uncompressed(bytes_view sk) {
        bytes p = bytes(UncompressedPubkeySize);
        secp256k1_pubkey pubkey;
        auto context = Signing();
        return secp256k1_ec_pubkey_create(context, &pubkey, sk.data()) == 1 && serialize(context, p, pubkey) ? p : 0;
    }
    
    bool parse(const secp256k1_context* context, secp256k1_pubkey& out, bytes_view pk) {
        return secp256k1_ec_pubkey_parse(context, &out, pk.data(), pk.size()) == 1;
    }
    
    bytes pubkey::compress(bytes_view pk) {
        if (pk.size() == CompressedPubkeySize) return bytes{pk};
        secp256k1_pubkey pubkey;
        bytes p(CompressedPubkeySize);
        const auto context = Verification();
        return parse(context, pubkey, pk) && serialize(context, p, pubkey) ? p : 0;
    }
    
    bytes pubkey::decompress(bytes_view pk) {
        if (pk.size() == UncompressedPubkeySize) return bytes{pk};
        secp256k1_pubkey pubkey;
        bytes p(UncompressedPubkeySize);
        const auto context = Verification();
        return parse(context, pubkey, pk) && serialize(context, p, pubkey) ? p : 0;
    }
    
    coordinate pubkey::x() const {
        coordinate v{0};
        if (valid()) std::copy(Value.begin() + 1, Value.begin() + 33, v.begin());
        return v;
    }
        
    coordinate pubkey::y() const {
        coordinate v{0}; 
        if (valid()) {
            bytes_view decompressed = type() == uncompressed ? Value : decompress(Value);
            std::copy(decompressed.begin() + 33, decompressed.end(), v.begin());
        };
        return v;
    }
    
    signature secret::sign(bytes_view sk, const digest& d) {
        signature sig;
        const auto context = Signing();

        if (secp256k1_ecdsa_sign(context, &sig.Data, d.Value.data(), sk.data(),
            secp256k1_nonce_function_rfc6979, nullptr) != 1)
            return {};

        return sig;
    }
    
    bool verify_signature(const secp256k1_context* context,
        const secp256k1_pubkey point, bytes_view hash,
        const signature& s) {
        secp256k1_ecdsa_signature parsed;
        std::copy_n(s.begin(), signature::Size, std::begin(parsed.data));
        
        secp256k1_ecdsa_signature normal;
        secp256k1_ecdsa_signature_normalize(context, &normal, &parsed);
        return secp256k1_ecdsa_verify(context, &normal, hash.data(), &point) == 1;
    }
    
    bool pubkey::verify(bytes_view pk, const digest& d, const signature& s) {
        secp256k1_pubkey pubkey;
        const auto context = Verification();
        return parse(context, pubkey, pk) &&
            verify_signature(context, pubkey, d, s);
    }
    
    coordinate secret::negate(const coordinate& sk) {
        coordinate out{sk};
        return secp256k1_ec_privkey_negate(Verification(), out.data()) == 1 ? out : 0;
    }
    
    bytes pubkey::negate(const bytes& pk) {
        const auto context = Verification();
        secp256k1_pubkey pubkey;
        bytes out = bytes(pk.size());
        return parse(context, pubkey, pk) &&
            secp256k1_ec_pubkey_negate(context, &pubkey) == 1 &&
            serialize(context, out, pubkey) ? out : 0;
    }
    
    coordinate secret::plus(const coordinate& sk_a, bytes_view sk_b) {
        const auto context = Verification();
        coordinate out{sk_a};
        return secp256k1_ec_privkey_tweak_add(context, out.data(),
            sk_b.data()) == 1;
    }
    
    coordinate secret::times(const coordinate& sk_a, bytes_view sk_b) {
        const auto context = Verification();
        coordinate out{sk_a};
        return secp256k1_ec_privkey_tweak_mul(context, out.data(),
            sk_b.data()) == 1;
    }
    
    bytes pubkey::plus_pubkey(const bytes& pk_a, bytes_view pk_b) {
        const auto context = Verification();
        secp256k1_pubkey pubkey;
        secp256k1_pubkey b;
        secp256k1_pubkey* keys[1];
        keys[0] = &b;
        if (!parse(context, b, pk_b)) return 0;
        
        bytes out = bytes(pk_a.size());
        return secp256k1_ec_pubkey_combine(context, &pubkey, keys, 1) == 1 && serialize(context, out, pubkey) ? out : 0;
    }
    
    bytes pubkey::plus_secret(const bytes& pk, bytes_view sk) {
        const auto context = Verification();
        bytes out = bytes(pk.size());
        secp256k1_pubkey pubkey;
        return parse(context, pubkey, pk) &&
            secp256k1_ec_pubkey_tweak_add(context, &pubkey, sk.data()) == 1 &&
            serialize(context, out, pubkey) ? out : 0;
    }
    
    bytes pubkey::times(const bytes& pk, bytes_view sk) {
        const auto context = Verification();
        bytes out{pk};
        secp256k1_pubkey pubkey;
        return parse(context, pubkey, pk) &&
            secp256k1_ec_pubkey_tweak_mul(context, &pubkey, sk.data()) == 1 &&
            serialize(context, out, pubkey) ? out : 0;
    }
    
}
