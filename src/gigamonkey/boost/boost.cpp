#include <gigamonkey/boost/boost.hpp>
#include <gigamonkey/script/pattern.hpp>
#include <data/encoding/halves.hpp>
#include <iostream>

namespace Gigamonkey::Bitcoin::interpreter {
    // The Bitcoin script pattern which takes a target in 
    // exponential format and converts it to expanded format. 
    const program expand_target = program{
        OP_SIZE, push_value(4), OP_EQUALVERIFY, push_value(3), OP_SPLIT,
        OP_DUP, OP_BIN2NUM, push_value(3), push_value(33), OP_WITHIN, OP_VERIFY, OP_TOALTSTACK,
        OP_DUP, OP_BIN2NUM, OP_0, OP_GREATERTHAN, OP_VERIFY, // significant must be positive
        push_hex("0000000000000000000000000000000000000000000000000000000000"), 
        OP_CAT, OP_FROMALTSTACK, push_value(3), OP_SUB, push_value(8), OP_MUL, OP_RSHIFT};
    
    // check top stack element for positive zero (as opposed to negative zero) 
    // and replace it with true or false. 
    const program check_positive_zero = program{OP_DUP, OP_NOTIF, OP_1, OP_RSHIFT, 
        OP_NOTIF, OP_TRUE, OP_ELSE, OP_FALSE, OP_ENDIF, OP_ELSE, OP_DROP, OP_FALSE, OP_ENDIF};
    
    const program check_negative_zero = program{OP_DUP, OP_NOTIF, OP_1, OP_RSHIFT, 
        push_hex("40"), OP_EQUAL, OP_IF, OP_TRUE, OP_ELSE, OP_FALSE, OP_ENDIF, OP_ELSE, OP_DROP, OP_FALSE, OP_ENDIF};
    
    const program ensure_positive = program{push_hex("00"), OP_CAT, OP_BIN2NUM};
}

namespace Gigamonkey::Boost {
    
    input_script input_script::read(bytes b) {
        using namespace Bitcoin::interpreter;
        using namespace Bitcoin;
        input_script x{};
        bytes MinerPubkey;
        bytes Timestamp;
        bytes Nonce;
        bytes ExtraNonce1;
        bytes ExtraNonce2;
        bytes GeneralPurposeBits;
        bytes MinerAddress;
        
        if (!pattern{
            push{x.Signature.Data}, 
            pubkey_pattern(MinerPubkey), 
            push_size{4, Nonce}, 
            push_size{4, Timestamp}, 
            push_size{8, ExtraNonce2}, 
            push_size{4, ExtraNonce1}, 
            interpreter::optional{push_size{4, GeneralPurposeBits}}, 
            interpreter::optional{push_size{20, MinerAddress}}}.match(b)) return {};
        
        x.Type = MinerAddress.size() == 0 ? Boost::contract : Boost::bounty;
        
        if (GeneralPurposeBits.size() != 0) {
            x.GeneralPurposeBits = 0;
            std::copy(GeneralPurposeBits.begin(), GeneralPurposeBits.end(), x.GeneralPurposeBits->begin());
        }
        
        if (x.Type == Boost::bounty) std::copy(
            MinerAddress.begin(), 
            MinerAddress.end(), 
            x.MinerAddress.begin());
        
        x.Pubkey.resize(MinerPubkey.size());
        std::copy(
            MinerPubkey.begin(), 
            MinerPubkey.end(), 
            x.Pubkey.begin());
        
        std::copy(
            Timestamp.begin(), 
            Timestamp.end(), 
            x.Timestamp.data());
        
        std::copy(
            Nonce.begin(), 
            Nonce.end(), 
            x.Nonce.data());
        
        std::copy(
            ExtraNonce1.begin(), 
            ExtraNonce1.end(), 
            x.ExtraNonce1.data());
        
        std::copy(
            ExtraNonce2.begin(), 
            ExtraNonce2.end(), 
            x.ExtraNonce2.data());
        
        return x;
    }
    
    output_script output_script::read(bytes b) {
        using namespace Bitcoin::interpreter;
        using namespace Bitcoin;
        output_script x{};
        bytes Category{};
        bytes Content{};
        bytes Target{};
        bytes UserNonce{};
        bytes MinerAddress{};
        
        pattern output_script_pattern_no_asicboost = pattern{
            push{bytes{0x62, 0x6F, 0x6F, 0x73, 0x74, 0x70, 0x6F, 0x77}}, OP_DROP, 
            interpreter::optional{push_size{20, MinerAddress}},
            push_size{4, Category},
            push_size{32, Content},
            push_size{4, Target},
            push{x.Tag}, 
            push_size{4, UserNonce}, 
            push{x.AdditionalData}, OP_CAT, OP_SWAP, 
            // copy mining pool’s pubkey hash to alt stack. A copy remains on the stack.
            push{5}, OP_ROLL, OP_DUP, OP_TOALTSTACK, OP_CAT,              
            // copy target and push to altstack. 
            push{2}, OP_PICK, OP_TOALTSTACK, 
            push{5}, OP_ROLL, OP_SIZE, push{4}, OP_EQUALVERIFY, OP_CAT,   // check size of extra_nonce_1
            push{5}, OP_ROLL, OP_SIZE, push{8}, OP_EQUALVERIFY, OP_CAT,   // check size of extra_nonce_2
            // create metadata document and hash it.
            OP_SWAP, OP_CAT, OP_HASH256,                       
            OP_SWAP, OP_TOALTSTACK, OP_CAT, OP_CAT,              // target to altstack. 
            OP_SWAP, OP_SIZE, push{4}, OP_EQUALVERIFY, OP_CAT,   // check size of timestamp.
            OP_FROMALTSTACK, OP_CAT,                             // attach target
            // check size of nonce. Boost POW string is constructed. 
            OP_SWAP, OP_SIZE, push{4}, OP_EQUALVERIFY, OP_CAT,  
            // Take hash of work string and ensure that it is positive and minimally encoded.
            OP_HASH256, ensure_positive, 
            // Get target, transform to expanded form, and ensure that it is positive and minimally encoded.
            OP_FROMALTSTACK, expand_target, ensure_positive, 
            // check that the hash of the Boost POW string is less than the target
            OP_LESSTHAN, OP_VERIFY,
            // check that the given address matches the pubkey and check signature.
            OP_DUP, OP_HASH160, OP_FROMALTSTACK, OP_EQUALVERIFY, OP_CHECKSIG};
            
        pattern output_script_pattern = pattern{
            push{bytes{0x62, 0x6F, 0x6F, 0x73, 0x74, 0x70, 0x6F, 0x77}}, OP_DROP, 
            interpreter::optional{push_size{20, MinerAddress}},
            push_size{4, Category},
            push_size{32, Content},
            push_size{4, Target},
            push{x.Tag}, 
            push_size{4, UserNonce}, 
            push{x.AdditionalData}, OP_CAT, OP_SWAP, 
            // copy mining pool’s pubkey hash to alt stack. A copy remains on the stack.
            push{5}, OP_ROLL, OP_DUP, OP_TOALTSTACK, OP_CAT, 
            // copy target and push to altstack. 
            push{2}, OP_PICK, OP_TOALTSTACK, 
            push{6}, OP_ROLL, OP_SIZE, push{4}, OP_EQUALVERIFY, OP_CAT,   // check size of extra_nonce_1
            push{6}, OP_ROLL, OP_SIZE, push{8}, OP_EQUALVERIFY, OP_CAT,   // check size of extra_nonce_2
            // create metadata document and hash it.
            OP_SWAP, OP_CAT, OP_HASH256,                       
            OP_SWAP, OP_TOALTSTACK, OP_CAT, OP_TOALTSTACK, // target and content + merkleroot to altstack. 
            push_hex("ff1f00e0"), OP_DUP, OP_INVERT, OP_TOALTSTACK, OP_AND, 
            // check size of general purpose bits 
            OP_SWAP, OP_FROMALTSTACK, OP_AND, OP_OR, 
            OP_FROMALTSTACK, OP_CAT,                             // attach content + merkleroot
            OP_SWAP, OP_SIZE, push{4}, OP_EQUALVERIFY, OP_CAT,   // check size of timestamp.
            OP_FROMALTSTACK, OP_CAT,                             // attach target
            // check size of nonce. Boost PoW string is constructed. 
            OP_SWAP, OP_SIZE, push{4}, OP_EQUALVERIFY, OP_CAT,  
            // Take hash of work string and ensure that it is positive and minimally encoded.
            OP_HASH256, ensure_positive, 
            // Get target, transform to expanded form, and ensure that it is positive and minimally encoded.
            OP_FROMALTSTACK, expand_target, ensure_positive, 
            // check that the hash of the Boost POW string is less than the target
            OP_LESSTHAN, OP_VERIFY,
            // check that the given address matches the pubkey and check signature.
            OP_DUP, OP_HASH160, OP_FROMALTSTACK, OP_EQUALVERIFY, OP_CHECKSIG};
        
        if (output_script_pattern.match(b)) {
            x.UseGeneralPurposeBits = true;
        } else if (output_script_pattern_no_asicboost.match(b)) {
            x.UseGeneralPurposeBits = false;
        } else return {};
        
        std::copy(
            Category.begin(), 
            Category.end(), 
            x.Category.data());
        
        if (x.Tag.size() > 20) return {};
        
        x.Type = MinerAddress.size() == 0 ? Boost::bounty : Boost::contract;
        
        if (x.Type == Boost::contract) std::copy(
            MinerAddress.begin(), 
            MinerAddress.end(), 
            x.MinerAddress.begin());
        
        std::copy(
            Target.begin(), 
            Target.end(), 
            x.Target.data());
        
        std::copy(
            UserNonce.begin(), 
            UserNonce.end(), 
            x.UserNonce.data());
        
        std::copy(
            Content.begin(), 
            Content.end(), 
            x.Content.data());
        
        return x;
    }
    
    Bitcoin::interpreter::program input_script::program() const {
        using namespace Bitcoin::interpreter;
        using namespace Bitcoin;
        if (Type == Boost::invalid) return {};
        interpreter::program p{
            push_data(bytes_view(Signature)), 
            push_data(Pubkey),
            push_data(Nonce),
            push_data(bytes_view(Timestamp)),
            push_data(bytes_view(ExtraNonce2)),
            push_data(bytes_view(ExtraNonce1))};
        if (GeneralPurposeBits) p = p << push_data(bytes_view(*GeneralPurposeBits));
        if (Type == Boost::bounty) p = p << push_data(MinerAddress);
        return p;
    }
    
    script output_script::write() const {
        using namespace Bitcoin::interpreter;
        if (Type == Boost::invalid) return {};
        program boost_output_script = program{push_hex("626F6F7374706F77"), OP_DROP}; // "boostpow"
        
        if (Type == Boost::contract) 
            boost_output_script = boost_output_script.append(push_data(MinerAddress));
        
        boost_output_script = UseGeneralPurposeBits ? boost_output_script.append(
            push_data(Category),
            push_data(Content), 
            push_data(Target), 
            push_data(Tag), 
            push_data(UserNonce), 
            push_data(bytes_view(AdditionalData)), 
            OP_CAT, OP_SWAP, 
            // copy mining pool’s pubkey hash to alt stack. A copy remains on the stack.
            OP_5, OP_ROLL, OP_DUP, OP_TOALTSTACK, OP_CAT,              
            // expand compact form of target and push to altstack. 
            OP_2, OP_PICK, OP_TOALTSTACK, 
            OP_6, OP_ROLL, OP_SIZE, OP_4, OP_EQUALVERIFY, OP_CAT,   // check size of extra_nonce_1
            OP_6, OP_ROLL, OP_SIZE, OP_8, OP_EQUALVERIFY, OP_CAT,   // check size of extra_nonce_2
            // create metadata document and hash it.
            OP_SWAP, OP_CAT, OP_HASH256,    
            // target and content + merkleroot to altstack. 
            OP_SWAP, OP_TOALTSTACK, OP_CAT, OP_TOALTSTACK, 
            push_hex("ff1f00e0"), OP_DUP, OP_INVERT, OP_TOALTSTACK, OP_AND, 
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
            OP_DUP, OP_HASH160, OP_FROMALTSTACK, OP_EQUALVERIFY, OP_CHECKSIG) : boost_output_script.append(
            push_data(Category),
            push_data(Content), 
            push_data(Target), 
            push_data(Tag), 
            push_data(UserNonce), 
            push_data(bytes_view(AdditionalData)), 
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
        
        return compile(boost_output_script);
    }
    /*
    work::puzzle puzzle(Boost::output_script o, digest160 miner) { 
        if (o.Type == Boost::invalid || (o.Type == Boost::contract && o.MinerAddress != miner)) return {};
        
        return work::puzzle{
            o.Category, o.Content, o.Target, 
            Merkle::path{list<digest256>{}, 0}, 
            write(o.Tag.size() + 168, o.Tag, o.UserNonce, o.MinerAddress), 
            o.AdditionalData};
    }*/
    
    inline bool between_inclusive(int x, int y, int z) {
        return x <= y && y <= z;
    }
    
    input_script from_solution(
                const Bitcoin::signature& signature, 
                const Bitcoin::pubkey& pubkey, 
                const work::solution& x, Boost::type t, 
                bool category_mask) {
        
        input_script in{};
        
        if (t == Boost::invalid || !x.valid() || (!category_mask && x.Share.Bits)) return in;
        
        in = t == Boost::bounty ? 
            input_script::bounty(signature, pubkey, x.Share.Nonce, x.Share.Timestamp, x.Share.ExtraNonce2, x.ExtraNonce1, hash160(pubkey)) : 
            input_script::contract(signature, pubkey, x.Share.Nonce, x.Share.Timestamp, x.Share.ExtraNonce2, x.ExtraNonce1);
        
        if (category_mask) in.GeneralPurposeBits = x.Share.Bits ? *x.Share.Bits : int32_little{0};
            
        return in;
    }
    
    input_script::input_script(
        const Bitcoin::signature& signature, 
        const Bitcoin::pubkey& pubkey, 
        const work::solution& x, Boost::type t, 
        bool category_mask) : input_script{from_solution(signature, pubkey, x, t, category_mask)} {}
    
    Boost::output_script job::output_script() const {
        
        if (!valid()) return Boost::output_script();
        
        size_t puzzle_header_size = job::Puzzle.Header.size();
        size_t puzzle_body_size = job::Puzzle.Body.size();
        
        if (puzzle_header_size < 20) return Boost::output_script();
        if (puzzle_body_size < 4) return Boost::output_script();
        
        size_t tag_size = puzzle_header_size - 20;
        size_t data_size = puzzle_body_size - 4;
        
        Boost::output_script out = Type == bounty ? 
            Boost::output_script::bounty(job::Puzzle.Candidate.Category, 
                job::Puzzle.Candidate.Digest, job::Puzzle.Candidate.Target, 
                bytes(tag_size), 0, bytes(data_size), use_general_purpose_bits()) :
            Boost::output_script::contract(job::Puzzle.Candidate.Category, 
                job::Puzzle.Candidate.Digest, job::Puzzle.Candidate.Target, 
                bytes(tag_size), 0, bytes(data_size), miner_address(), use_general_purpose_bits());
        
        std::copy(job::Puzzle.Header.begin(), job::Puzzle.Header.begin() + tag_size, out.Tag.begin());
        std::copy(job::Puzzle.Body.begin(), job::Puzzle.Body.begin() + 4, out.UserNonce.begin());
        std::copy(job::Puzzle.Body.begin() + 4, job::Puzzle.Body.end(), out.AdditionalData.begin());
        
        return out;
        
    }
    
    digest160 job::miner_address() const {
        size_t puzzle_header_size = job::Puzzle.Header.size();
        if (puzzle_header_size < 20) return {};
        digest160 x;
        std::copy(job::Puzzle.Header.end() - 20, 
                  job::Puzzle.Header.end(), 
                  x.begin());
        return x;
    }

    std::ostream& operator<<(std::ostream& o, const Gigamonkey::Boost::output_script s) {
        using namespace Gigamonkey::Boost;
        if (s.Type == invalid) return o << "BoostOutputScript{Type : invalid}";
        o << "BoostOutputScript{Type : ";
        if (s.Type == contract) o << "contract, MinerAddress : " << s.MinerAddress;
        else o << "bounty";
        return o << 
            ", Category : " << s.Category << 
            ", Masked : " << (s.UseGeneralPurposeBits ? "true" : "false" ) << 
            ", Content : " << s.Content << 
            ", Target : " << s.Target << 
            ", Tag : " << data::encoding::hexidecimal::write(s.Tag, data::endian::little) << 
            ", UserNonce : " << s.UserNonce << 
            ", AdditionalData : " << data::encoding::hexidecimal::write(s.AdditionalData, data::endian::little) << "}";
    }

    std::ostream& operator<<(std::ostream& o, const Gigamonkey::Boost::input_script s) {
        using namespace Gigamonkey::Boost;
        if (s.Type == invalid) return o << "BoostInputScript{Type : invalid}";
        o << "BoostInputScript{Type : " << (s.Type == contract ? "contract" : "bounty") << 
            ", Signature : " << s.Signature << 
            ", Pubkey : " << s.Pubkey << 
            ", Nonce : " << s.Nonce << 
            ", Timestamp : " << s.Timestamp << 
            ", ExtraNonce2 : " << s.ExtraNonce2 << 
            ", ExtraNonce1 : " << s.ExtraNonce1;
        if (s.Type == bounty) o << ", MinerAddress: " << s.MinerAddress;
        return o << "}";
    }
        
    proof::proof(const Boost::output_script& out, const Boost::input_script& in) : proof{} {
        if (out.Type == invalid || in.Type != out.Type) return;
        if (out.UseGeneralPurposeBits && bool(in.GeneralPurposeBits)) {
            int32_little gpr = *in.GeneralPurposeBits;
            *this = proof{Boost::job{out.Type, out.Category, out.Content, 
                    out.Target, out.Tag, out.UserNonce, out.AdditionalData, 
                    out.Type == bounty ? in.MinerAddress : out.MinerAddress, in.ExtraNonce1, true},
                work::share{in.Timestamp, in.Nonce, in.ExtraNonce2, gpr}, in.Signature, in.Pubkey};
            return; 
        } else if (!out.UseGeneralPurposeBits && !bool(in.GeneralPurposeBits)) {
            *this = proof{Boost::job{out.Type, out.Category, out.Content, 
                    out.Target, out.Tag, out.UserNonce, out.AdditionalData, 
                    out.Type == bounty ? in.MinerAddress : out.MinerAddress, in.ExtraNonce1, false},
                work::share{in.Timestamp, in.Nonce, in.ExtraNonce2}, in.Signature, in.Pubkey};
            return;
        }
    }

}
