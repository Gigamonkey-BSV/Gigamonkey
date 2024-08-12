#include <gigamonkey/boost/boost.hpp>
#include <gigamonkey/script/pattern.hpp>
#include <data/arithmetic/halves.hpp>
#include <gigamonkey/p2p/var_int.hpp>
#include <iostream>

namespace Gigamonkey::Bitcoin {
    // The Bitcoin script pattern which takes a target in 
    // exponential format and converts it to expanded format. 
    const program expand_target {
        OP_SIZE, push_data (4), OP_EQUALVERIFY, push_data (3), OP_SPLIT,
        OP_DUP, OP_BIN2NUM, push_data (3), push_data (33), OP_WITHIN, OP_VERIFY, OP_TOALTSTACK,
        OP_DUP, OP_BIN2NUM, OP_0, OP_GREATERTHAN, OP_VERIFY, // significant must be positive
        push_data (bytes (29, 0x00)),
        OP_CAT, OP_FROMALTSTACK, push_data (3), OP_SUB, push_data (8), OP_MUL, OP_RSHIFT};
    
    // check top stack element for positive zero (as opposed to negative zero) 
    // and replace it with true or false. 
    const program check_positive_zero {OP_DUP, OP_NOTIF, OP_1, OP_RSHIFT,
        OP_NOTIF, OP_TRUE, OP_ELSE, OP_FALSE, OP_ENDIF, OP_ELSE, OP_DROP, OP_FALSE, OP_ENDIF};
    
    const program check_negative_zero {OP_DUP, OP_NOTIF, OP_1, OP_RSHIFT,
        push_data (bytes {0x40}), OP_EQUAL, OP_IF, OP_TRUE, OP_ELSE, OP_FALSE, OP_ENDIF, OP_ELSE, OP_DROP, OP_FALSE, OP_ENDIF};
    
    const program ensure_positive {push_data (bytes {0x00}), OP_CAT, OP_BIN2NUM};
}   

namespace Gigamonkey::Boost {
    
    using namespace Bitcoin;
    
    input_script input_script::read (bytes b) {
        input_script x {};
        bytes MinerPubkey;
        bytes Timestamp;
        bytes Nonce;
        bytes ExtraNonce1;
        bytes GeneralPurposeBits;
        bytes MinerPubkeyHash;
        
        if (!pattern {
            push {x.Signature},
            pubkey_pattern (MinerPubkey),
            push_size {4, Nonce},
            push_size {4, Timestamp},
            push {x.ExtraNonce2},
            push_size {4, ExtraNonce1},
            optional {push_size {4, GeneralPurposeBits}},
            optional {push_size {20, MinerPubkeyHash}}}.match (b)) return {};
        
        x.Type = MinerPubkeyHash.size () == 0 ? Boost::contract : Boost::bounty;
        
        if (GeneralPurposeBits.size () != 0) {
            if (x.ExtraNonce2.size () > 32) return {};
            x.GeneralPurposeBits = 0;
            std::copy (GeneralPurposeBits.begin (), GeneralPurposeBits.end (), x.GeneralPurposeBits->begin ());
        } else if (x.ExtraNonce2.size () != 8) return {};
        
        if (x.Type == Boost::bounty) std::copy (
            MinerPubkeyHash.begin (),
            MinerPubkeyHash.end (),
            x.MinerPubkeyHash.begin ());
        
        x.Pubkey.resize (MinerPubkey.size ());
        std::copy (
            MinerPubkey.begin (),
            MinerPubkey.end (),
            x.Pubkey.begin ());
        
        std::copy (
            Timestamp.begin (),
            Timestamp.end (),
            x.Timestamp.data ());
        
        std::copy (
            Nonce.begin (),
            Nonce.end (),
            x.Nonce.data ());
        
        std::copy (
            ExtraNonce1.begin (),
            ExtraNonce1.end (),
            x.ExtraNonce1.data ());
        
        return x;
    }
    
    output_script output_script::read (bytes b) {
        output_script x {};
        bytes Category {};
        bytes Content {};
        bytes Target {};
        bytes UserNonce {};
        bytes MinerPubkeyHash {};

        pattern output_script_pattern_no_asicboost = pattern {
            push {bytes {0x62, 0x6F, 0x6F, 0x73, 0x74, 0x70, 0x6F, 0x77}}, OP_DROP,
            optional {push_size {20, MinerPubkeyHash}},
            push_size {4, Category},
            push_size {32, Content},
            push_size {4, Target},
            push {x.Tag},
            push_size {4, UserNonce},
            push {x.AdditionalData}, OP_CAT, OP_SWAP,
            // copy mining pool’s pubkey hash to alt stack. A copy remains on the stack.
            push {5}, OP_ROLL, OP_DUP, OP_TOALTSTACK, OP_CAT,
            // copy target and push to altstack. 
            push {2}, OP_PICK, OP_TOALTSTACK,
            // check size of extra_nonce_1
            push {5}, OP_ROLL, OP_SIZE, push {4}, OP_EQUALVERIFY, OP_CAT,
            // check size of extra_nonce_2
            push {5}, OP_ROLL, OP_SIZE, push {8}, OP_EQUALVERIFY, OP_CAT,
            // create metadata document and hash it.
            OP_SWAP, OP_CAT, OP_HASH256,                       
            OP_SWAP, OP_TOALTSTACK, OP_CAT, OP_CAT,              // target to altstack. 
            OP_SWAP, OP_SIZE, push {4}, OP_EQUALVERIFY, OP_CAT,   // check size of timestamp.
            OP_FROMALTSTACK, OP_CAT,                             // attach target
            // check size of nonce. Boost POW string is constructed. 
            OP_SWAP, OP_SIZE, push {4}, OP_EQUALVERIFY, OP_CAT,
            // Take hash of work string and ensure that it is positive and minimally encoded.
            OP_HASH256, ensure_positive, 
            // Get target, transform to expanded form, and ensure that it is positive and minimally encoded.
            OP_FROMALTSTACK, expand_target, ensure_positive, 
            // check that the hash of the Boost POW string is less than the target
            OP_LESSTHAN, OP_VERIFY,
            // check that the given address matches the pubkey and check signature.
            OP_DUP, OP_HASH160, OP_FROMALTSTACK, OP_EQUALVERIFY, OP_CHECKSIG};
            
        pattern output_script_pattern = pattern {
            push {bytes {0x62, 0x6F, 0x6F, 0x73, 0x74, 0x70, 0x6F, 0x77}}, OP_DROP,
            optional {push_size {20, MinerPubkeyHash}},
            push_size {4, Category},
            push_size {32, Content},
            push_size {4, Target},
            push {x.Tag},
            push_size {4, UserNonce},
            push {x.AdditionalData}, OP_CAT, OP_SWAP,
            // copy mining pool’s pubkey hash to alt stack. A copy remains on the stack.
            push {5}, OP_ROLL, OP_DUP, OP_TOALTSTACK, OP_CAT,
            // copy target and push to altstack. 
            push {2}, OP_PICK, OP_TOALTSTACK,
            // check size of extra_nonce_1
            push {6}, OP_ROLL, OP_SIZE, push {4}, OP_EQUALVERIFY, OP_CAT,
            // check size of extra_nonce_2
            push {6}, OP_ROLL, OP_SIZE, push {32}, OP_LESSTHANOREQUAL, OP_VERIFY, OP_CAT,
            // create metadata document and hash it.
            OP_SWAP, OP_CAT, OP_HASH256, 
            // target and content + merkleroot to altstack. 
            OP_SWAP, OP_TOALTSTACK, OP_CAT, OP_TOALTSTACK, 
            push_data (work::ASICBoost::Mask), OP_DUP, OP_INVERT, OP_TOALTSTACK, OP_AND,
            // check size of general purpose bits 
            OP_SWAP, OP_FROMALTSTACK, OP_AND, OP_OR, 
            OP_FROMALTSTACK, OP_CAT,                             // attach content + merkleroot
            OP_SWAP, OP_SIZE, push {4}, OP_EQUALVERIFY, OP_CAT,   // check size of timestamp.
            OP_FROMALTSTACK, OP_CAT,                             // attach target
            // check size of nonce. Boost PoW string is constructed. 
            OP_SWAP, OP_SIZE, push {4}, OP_EQUALVERIFY, OP_CAT,
            // Take hash of work string and ensure that it is positive and minimally encoded.
            OP_HASH256, ensure_positive, 
            // Get target, transform to expanded form, and ensure that it is positive and minimally encoded.
            OP_FROMALTSTACK, expand_target, ensure_positive, 
            // check that the hash of the Boost POW string is less than the target
            OP_LESSTHAN, OP_VERIFY,
            // check that the given address matches the pubkey and check signature.
            OP_DUP, OP_HASH160, OP_FROMALTSTACK, OP_EQUALVERIFY, OP_CHECKSIG};
        
        if (output_script_pattern.match (b)) {
            x.UseGeneralPurposeBits = true;
        } else if (output_script_pattern_no_asicboost.match (b)) {
            x.UseGeneralPurposeBits = false;
        } else return {};
        
        std::copy (
            Category.begin (),
            Category.end (),
            x.Category.data ());
        
        if (x.Tag.size () > 20) return {};
        
        x.Type = MinerPubkeyHash.size () == 0 ? Boost::bounty : Boost::contract;
        
        if (x.Type == Boost::contract) std::copy (
            MinerPubkeyHash.begin (),
            MinerPubkeyHash.end (),
            x.MinerPubkeyHash.begin ());
        
        std::copy (
            Target.begin (),
            Target.end (),
            x.Target.data ());
        
        std::copy (
            UserNonce.begin (),
            UserNonce.end (),
            x.UserNonce.data ());
        
        std::copy (
            Content.begin (),
            Content.end (),
            x.Content.data ());
        
        return x;
    }
    
    program input_script::program () const {
        if (Type == Boost::invalid) return {};
        Bitcoin::program p {
            push_data (bytes_view (Signature)),
            push_data (Pubkey),
            push_data (Nonce),
            push_data (bytes_view (Timestamp)),
            push_data (bytes_view (ExtraNonce2)),
            push_data (bytes_view (ExtraNonce1))};
        if (GeneralPurposeBits) p = p << push_data (bytes_view (*GeneralPurposeBits));
        if (Type == Boost::bounty) p = p << push_data (MinerPubkeyHash);
        return p;
    }
    
    script output_script::write () const {
        if (Type == Boost::invalid) return {};
        program boost_output_script = program {push_data (bytes {0x62, 0x6F, 0x6F, 0x73, 0x74, 0x70, 0x6F, 0x77}), OP_DROP}; // "boostpow"
        
        if (Type == Boost::contract) 
            boost_output_script = boost_output_script.append (push_data (MinerPubkeyHash));
        
        boost_output_script = UseGeneralPurposeBits ? boost_output_script.append (
            push_data (Category),
            push_data (Content),
            push_data (Target),
            push_data (Tag),
            push_data (UserNonce),
            push_data (bytes_view (AdditionalData)),
            OP_CAT, OP_SWAP, 
            // copy mining pool’s pubkey hash to alt stack. A copy remains on the stack.
            OP_5, OP_ROLL, OP_DUP, OP_TOALTSTACK, OP_CAT,              
            // expand compact form of target and push to altstack. 
            OP_2, OP_PICK, OP_TOALTSTACK, 
            // check size of extra_nonce_1
            OP_6, OP_ROLL, OP_SIZE, OP_4, OP_EQUALVERIFY, OP_CAT,   
            // check size of extra_nonce_2
            OP_6, OP_ROLL, OP_SIZE, push_data (32), OP_LESSTHANOREQUAL, OP_VERIFY, OP_CAT,
            // create metadata document and hash it.
            OP_SWAP, OP_CAT, OP_HASH256,    
            // target and content + merkleroot to altstack. 
            OP_SWAP, OP_TOALTSTACK, OP_CAT, OP_TOALTSTACK, 
            push_data (work::ASICBoost::Mask), OP_DUP, OP_INVERT, OP_TOALTSTACK, OP_AND,
            // general purpose bits 
            OP_SWAP, OP_FROMALTSTACK, OP_AND, OP_OR, 
            OP_FROMALTSTACK, OP_CAT,                                // attach content + merkleroot
            OP_SWAP, OP_SIZE, OP_4, OP_EQUALVERIFY, OP_CAT,         // check size of timestamp.
            OP_FROMALTSTACK, OP_CAT,                                // attach target
            // check size of nonce. Boost POW string is constructed. 
            OP_SWAP, OP_SIZE, OP_4, OP_EQUALVERIFY, OP_CAT,
            // Take hash of work string and ensure that it is positive and minimally encoded.
            OP_HASH256, ensure_positive, 
            // Get target, transform to expanded form, and ensure that it is positive and minimally encoded.
            OP_FROMALTSTACK, expand_target, ensure_positive, 
            // check that the hash of the Boost POW string is less than the target
            OP_LESSTHAN, OP_VERIFY,
            // check that the given address matches the pubkey and check signature.
            OP_DUP, OP_HASH160, OP_FROMALTSTACK, OP_EQUALVERIFY, OP_CHECKSIG) : boost_output_script.append (
            push_data (Category),
            push_data (Content),
            push_data (Target),
            push_data (Tag),
            push_data (UserNonce),
            push_data (bytes_view(AdditionalData)),
            OP_CAT, OP_SWAP, 
            // copy mining pool’s pubkey hash to alt stack. A copy remains on the stack.
            OP_5, OP_ROLL, OP_DUP, OP_TOALTSTACK, OP_CAT,              
            // expand compact form of target and push to altstack. 
            OP_2, OP_PICK, OP_TOALTSTACK, 
            OP_5, OP_ROLL, OP_SIZE, OP_4, OP_EQUALVERIFY, OP_CAT,   // check size of extra_nonce_1
            OP_5, OP_ROLL, OP_SIZE, OP_8, OP_EQUALVERIFY, OP_CAT,   // check size of extra_nonce_2
            // create metadata document and hash it.
            OP_SWAP, OP_CAT, OP_HASH256,    
            OP_SWAP, OP_TOALTSTACK, OP_CAT, OP_CAT,                 // target to altstack. 
            OP_SWAP, OP_SIZE, OP_4, OP_EQUALVERIFY, OP_CAT,         // check size of timestamp.
            OP_FROMALTSTACK, OP_CAT,                                // attach target
            // check size of nonce. Boost POW string is constructed. 
            OP_SWAP, OP_SIZE, OP_4, OP_EQUALVERIFY, OP_CAT,
            // Take hash of work string and ensure that it is positive and minimally encoded.
            OP_HASH256, ensure_positive, 
            // Get target, transform to expanded form, and ensure that it is positive and minimally encoded.
            OP_FROMALTSTACK, expand_target, ensure_positive, 
            // check that the hash of the Boost POW string is less than the target
            OP_LESSTHAN, OP_VERIFY,
            // check that the given address matches the pubkey and check signature.
            OP_DUP, OP_HASH160, OP_FROMALTSTACK, OP_EQUALVERIFY, OP_CHECKSIG);
        
        return compile (boost_output_script);
    }
    
    inline bool between_inclusive (int x, int y, int z) {
        return x <= y && y <= z;
    }
    
    input_script from_solution (
                const signature &signature,
                const pubkey &pubkey,
                const work::solution &x, Boost::type t,
                bool category_mask) {
        
        input_script in {};
        
        if (t == Boost::invalid || !x.valid () || (!category_mask && x.Share.Bits)) return in;
        
        in = t == Boost::bounty ? 
            input_script::bounty (signature, pubkey, x.Share.Nonce, x.Share.Timestamp, x.Share.ExtraNonce2, x.ExtraNonce1, Hash160 (pubkey)) :
            input_script::contract (signature, pubkey, x.Share.Nonce, x.Share.Timestamp, x.Share.ExtraNonce2, x.ExtraNonce1);
        
        if (category_mask) in.GeneralPurposeBits = x.Share.Bits ? *x.Share.Bits : int32_little {0};
        
        return in;
    }
    
    input_script::input_script (
        const Bitcoin::signature &signature,
        const Bitcoin::pubkey &pubkey,
        const work::solution &x, Boost::type t,
        bool category_mask) : input_script {from_solution (signature, pubkey, x, t, category_mask)} {}
    
    std::ostream &operator << (std::ostream &o, const Gigamonkey::Boost::output_script s) {
        using namespace Gigamonkey::Boost;
        if (s.Type == invalid) return o << "BoostOutputScript{Type : invalid}";
        o << "BoostOutputScript{Type : ";
        if (s.Type == contract) o << "contract, MinerPubkeyHash : " << s.MinerPubkeyHash;
        else o << "bounty";
        return o << 
            ", Category : " << s.Category << 
            ", Masked : " << (s.UseGeneralPurposeBits ? "true" : "false" ) << 
            ", Content : " << s.Content << 
            ", Target : " << s.Target << 
            ", Tag : " << s.Tag << 
            ", UserNonce : " << s.UserNonce << 
            ", AdditionalData : " << s.AdditionalData << "}";
    }

    std::ostream &operator << (std::ostream &o, const Gigamonkey::Boost::input_script s) {
        using namespace Gigamonkey::Boost;
        if (s.Type == invalid) return o << "BoostInputScript{Type : invalid}";
        o << "BoostInputScript{Type : " << (s.Type == contract ? "contract" : "bounty") << 
            ", Signature : " << s.Signature << 
            ", Pubkey : " << s.Pubkey << 
            ", Nonce : " << s.Nonce << 
            ", Timestamp : " << s.Timestamp << 
            ", ExtraNonce2 : " << s.ExtraNonce2 << 
            ", ExtraNonce1 : " << static_cast<uint32_big>(s.ExtraNonce1);
        if (s.Type == bounty) o << ", MinerPubkeyHash: " << s.MinerPubkeyHash;
        return o << "}";
    }

    proof::proof (const Boost::output_script &out, const Boost::input_script &in) : proof{} {
        if (out.Type == invalid || in.Type != out.Type) return;
        auto miner_pubkey_hash = out.Type == bounty ? in.MinerPubkeyHash : out.MinerPubkeyHash;
        if (out.UseGeneralPurposeBits && bool (in.GeneralPurposeBits)) {
            int32_little gpr = *in.GeneralPurposeBits;
            *this = proof {work::job {work::puzzle{
                        out.Category, out.Content, out.Target, Merkle::path {},
                        puzzle::header (out.Tag, miner_pubkey_hash),
                        puzzle::body (out.UserNonce, out.AdditionalData),
                        work::ASICBoost::Mask}, 
                    in.ExtraNonce1},
                work::share {in.Timestamp, in.Nonce, in.ExtraNonce2, gpr}, out.Type, in.Signature, in.Pubkey};
            return; 
        } else if (!out.UseGeneralPurposeBits && !bool (in.GeneralPurposeBits)) {
            *this = proof {work::job {work::puzzle {
                        out.Category, out.Content, out.Target, Merkle::path {},
                        puzzle::header (out.Tag, miner_pubkey_hash),
                        puzzle::body (out.UserNonce, out.AdditionalData),
                        int32_little {-1}},
                    in.ExtraNonce1},
                work::share {in.Timestamp, in.Nonce, in.ExtraNonce2}, out.Type, in.Signature, in.Pubkey};
            return;
        }
    }
        
    work::puzzle work_puzzle (const output_script &script, const digest160 &address) {
        if (!script.valid ()) return {};
        digest160 miner_pubkey_hash = script.Type == contract ? script.MinerPubkeyHash : address;
        if (!miner_pubkey_hash.valid ()) return {};
        return {script.Category, script.Content, script.Target, Merkle::path {},
            puzzle::header (script.Tag, miner_pubkey_hash),
            puzzle::body (script.UserNonce, script.AdditionalData),
            script.UseGeneralPurposeBits ? work::ASICBoost::Mask : int32_little {-1}};
    }
    
    bool puzzle::valid () const {
        if (!candidate::valid () || !MinerKey.valid ()) return false;
    
        output_script x {this->Script};
        
        // If this is a contract script, we need to check that the key we have been given corresponds 
        // to the miner address in the script. 
        return x.valid () && (x.Type == Boost::bounty || x.MinerPubkeyHash == Bitcoin::Hash160 (this->MinerKey.to_public ()));
    }
    
    bytes puzzle::redeem (const work::solution &solution, list<Bitcoin::output> outs) const {
        
        // construct the incomplete inputs
        list<incomplete::input> incomplete_inputs = data::for_each (
            [] (const Boost::candidate::prevout &prev) -> incomplete::input {
                return incomplete::input {static_cast<Bitcoin::outpoint> (prev), Bitcoin::input::Finalized};
            }, Prevouts);
        
        bytes script = Script;
        Boost::output_script boost_script {script};
        
        secret sk = MinerKey;
        Bitcoin::satoshi val = value ();

        incomplete::transaction incomplete {1, incomplete_inputs, outs, 0};
        pubkey pk = sk.to_public ();
        Boost::type boost_type = boost_script.Type;
        bool category_mask = boost_script.UseGeneralPurposeBits;
        
        uint32 index = 0;
        
        return bytes (transaction {1, data::map_thread (
            [&sk, &script, &incomplete, &pk, &solution, boost_type, category_mask, &index](
                const incomplete::input &i, 
                const prevout &prev) -> input {
                return input {i.Reference, input_script {
                    sk.sign (sighash::document {prev.Value, script, incomplete, index++}, directive (sighash::all)),
                pk, solution, boost_type, category_mask}.write (), i.Sequence};
            }, incomplete_inputs, Prevouts.values ()), outs, 0});
        
    }
    
    size_t puzzle::expected_size () const {
        output_script x {Script};
        size_t input_script_size = input_script::expected_size (x.Type, x.UseGeneralPurposeBits, MinerKey.Compressed);
        return Bitcoin::var_int::size (Prevouts.size ()) +
            Prevouts.size () * (input_script_size + Bitcoin::var_int::size (input_script_size) + 40);
    }

}
