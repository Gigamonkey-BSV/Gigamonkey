// Copyright (c) 2020-2023 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_BOOST_BOOST
#define GIGAMONKEY_BOOST_BOOST

#include <gigamonkey/fees.hpp>
#include <gigamonkey/work/proof.hpp>
#include <gigamonkey/wif.hpp>

namespace Gigamonkey {
    
    namespace Boost {
        
        enum type {invalid, bounty, contract};
        
        struct output_script;
        struct input_script;
        
        bool operator == (const output_script &, const output_script &);
        bool operator == (const input_script &, const input_script &);

        std::ostream& operator << (std::ostream &o, const output_script s);
        std::ostream& operator << (std::ostream &o, const input_script s);
        
        // A candidate is a boost script and a set of of utxos that contain it. 
        struct candidate;
        
        bool operator == (const candidate &, const candidate &);
        
        // A puzzle is created after ExtraNonce is assigned by the mining pool.
        struct puzzle;
        struct proof;
        
        struct output_script {
            
            // if the miner address is provided then this is a contract script
            // that can only be redeemed by the miner who owns the address. 
            // if not then it is a bounty script that any miner can redeem.
            Boost::type Type;
            
            digest160 MinerPubkeyHash;
            
            // Bitcoin adopted BIP 320 (https://en.bitcoin.it/wiki/BIP_0320) 
            // which allowed some of the version bits to be overwritten. 
            // The original version of the Boost PoW script didn't allow for this. 
            int32_little Category;
            bool UseGeneralPurposeBits;
            
            // The content that is boosted. 
            uint256 Content;
            
            // The difficulty target. 
            work::compact Target;
            
            // Association of the boost with a tag, max 20 characters. 
            bytes Tag;
            
            // A number that should be random to prevent a user from creating an identical script accidentally. 
            uint32_little UserNonce;
            
            // whatever you want. 
            bytes AdditionalData;
            
            output_script ();
            
            static output_script bounty (
                int32_little category,
                const uint256 &content,
                work::compact target, 
                const bytes &tag,
                uint32_little user_nonce, 
                const bytes &data,
                bool use_general_purpose_bits = true);
            
            static output_script contract (
                int32_little category,
                const uint256 &content,
                work::compact target, 
                const bytes &tag,
                uint32_little user_nonce, 
                const bytes &data,
                const digest160 &miner_pubkey_hash,
                bool use_general_purpose_bits = true);
            
            bool valid () const;
            
            Bitcoin::script write () const;
            
            static output_script read (bytes);
            
            explicit output_script (bytes b);
            
            size_t serialized_size () const;
            
            static Boost::type type (Bitcoin::script x);
            static bool valid (Bitcoin::script x);
            
            // same as category
            static int32_little version (Bitcoin::script x);
            
            // We can use the remaining 16 bits of category as a magic number. 
            static uint16_little magic_number (Bitcoin::script x);
            
            static uint256 content (Bitcoin::script x);
            static work::compact target (Bitcoin::script x);
            static bytes tag (Bitcoin::script x);
            static uint32_little user_nonce (Bitcoin::script x);
            static bytes additional_data (Bitcoin::script x);
            static digest160 miner_pubkey_hash (Bitcoin::script x);
            
        private:
            output_script (
                int32_little category, 
                const uint256 &content,
                work::compact target, 
                const bytes &tag,
                uint32_little user_nonce, 
                const bytes &data,
                bool use_general_purpose_bits = true);
            
            output_script (
                int32_little category, 
                const uint256 &content,
                work::compact target, 
                const bytes &tag,
                uint32_little user_nonce, 
                const bytes &data,
                const digest160& miner_pubkey_hash,
                bool use_general_purpose_bits = true);
            
            output_script (
                Boost::type type, 
                int32_little category, 
                const uint256 &content,
                work::compact target, 
                const bytes &tag,
                uint32_little user_nonce, 
                const bytes &data,
                const digest160 &miner_pubkey_hash,
                bool use_general_purpose_bits = true);
            
        };
        
        struct input_script {
            
            Boost::type Type;
            Bitcoin::signature Signature;
            Bitcoin::pubkey Pubkey;
            uint32_little Nonce;
            Bitcoin::timestamp Timestamp;
            bytes ExtraNonce2;
            Stratum::session_id ExtraNonce1;
            maybe<int32_little> GeneralPurposeBits;
            digest160 MinerPubkeyHash;
            
        private:
            // bounty type, no ASICBoost
            input_script (
                const Bitcoin::signature &signature,
                const Bitcoin::pubkey &pubkey,
                uint32_little nonce,
                Bitcoin::timestamp timestamp,
                const bytes &extra_nonce_2,
                Stratum::session_id extra_nonce_1,
                const digest160 &miner_pubkey_hash);
            
            // contract type, no ASICBoost
            input_script (
                const Bitcoin::signature &signature,
                const Bitcoin::pubkey &pubkey,
                uint32_little nonce,
                Bitcoin::timestamp timestamp,
                const bytes &extra_nonce_2,
                Stratum::session_id extra_nonce_1);
            
            // bounty type compatible with ASICBoost
            input_script (
                const Bitcoin::signature &signature,
                const Bitcoin::pubkey &pubkey,
                uint32_little nonce,
                Bitcoin::timestamp timestamp,
                const bytes &extra_nonce_2,
                Stratum::session_id extra_nonce_1,
                int32_little general_purpose_bits, 
                const digest160 &miner_pubkey_hash);
            
            // contract type compatible with ASICBoost;
            input_script (
                const Bitcoin::signature &signature,
                const Bitcoin::pubkey &pubkey,
                uint32_little nonce,
                Bitcoin::timestamp timestamp,
                const bytes &extra_nonce_2,
                Stratum::session_id extra_nonce_1,
                int32_little general_purpose_bits);
                
        public:
            input_script () = default;
            
            bool valid () const;
            
            Bitcoin::program program () const;
            
            Bitcoin::script write () const;
            
            size_t serialized_size () const;

            work::solution solution () const;
            
            // construct a Boost bounty input script. 
            static input_script bounty (
                const Bitcoin::signature &signature,
                const Bitcoin::pubkey &pubkey,
                uint32_little nonce,
                Bitcoin::timestamp timestamp,
                const bytes &extra_nonce_2,
                Stratum::session_id extra_nonce_1, 
                const digest160 &miner_pubkey_hash);
            
            // construct a Boost contract input script.
            static input_script contract (
                const Bitcoin::signature &signature,
                const Bitcoin::pubkey &pubkey,
                uint32_little nonce,
                Bitcoin::timestamp timestamp,
                const bytes &extra_nonce_2,
                Stratum::session_id extra_nonce_1);
            
            // construct a Boost bounty input script. 
            static input_script bounty (
                const Bitcoin::signature &signature,
                const Bitcoin::pubkey &pubkey,
                uint32_little nonce,
                Bitcoin::timestamp timestamp,
                const bytes &extra_nonce_2,
                Stratum::session_id extra_nonce_1, 
                int32_little category_bits, 
                const digest160 &miner_pubkey_hash);
            
            // construct a Boost contract input script.
            static input_script contract (
                const Bitcoin::signature &signature,
                const Bitcoin::pubkey &pubkey,
                uint32_little nonce,
                Bitcoin::timestamp timestamp,
                const bytes &extra_nonce_2,
                Stratum::session_id extra_nonce_1, 
                int32_little category_bits);
            
            static input_script read (bytes);
            
            explicit input_script (bytes b);
            
            static Boost::type type (Bitcoin::script x);
            static bool valid (Bitcoin::script x);
            static Bitcoin::signature signature (Bitcoin::script x);
            static Bitcoin::pubkey pubkey (Bitcoin::script x);
            static Bitcoin::timestamp timestamp (Bitcoin::script x);
            static uint32_little nonce (Bitcoin::script x);
            static digest160 miner_pubkey_hash (Bitcoin::script x);
            static work::solution solution (Bitcoin::script x);
            
            input_script (
                const Bitcoin::signature &signature,
                const Bitcoin::pubkey &pubkey,
                const work::solution &, Boost::type,
                bool category_mask);
            
            static uint64 expected_size (Boost::type t, bool use_general_purpose_bits, bool compressed_pubkey = true);
            
        };
        
        // construct a work::puzzle from an output_script. 
        // for script type contract, we don't need a miner key. 
        work::puzzle work_puzzle (const output_script &script, const digest160 &key = {});
        
        struct proof : work::proof {
            type Type;
            Bitcoin::signature Signature;
            Bitcoin::pubkey Pubkey;
            
            proof ();
            
            proof (const Boost::output_script &out, const Boost::input_script &in);
            proof (type t, const work::string &w, const bytes &h,
                const Stratum::session_id &n1, const bytes &n2, const bytes &b, 
                const Bitcoin::signature &x, const Bitcoin::pubkey &p);
            
            proof (const work::job &j, const work::share &h, type t, const Bitcoin::signature &x, const Bitcoin::pubkey &p);
            
            Boost::output_script output_script () const;
            Boost::input_script input_script () const;
            
            bool valid () const;
            
        };
        
        struct candidate {
            
            struct prevout : Bitcoin::outpoint {
                Bitcoin::satoshi Value;
                prevout (const Bitcoin::outpoint &o, Bitcoin::satoshi v) : Bitcoin::outpoint {o}, Value {v} {}
                prevout (): Bitcoin::outpoint {}, Value {} {}
                
                bool operator == (const prevout &p) const {
                    return static_cast<Bitcoin::outpoint> (*this) == static_cast<Bitcoin::outpoint> (p)
                        && Value == p.Value;
                }
                
                std::strong_ordering operator <=> (const prevout &p) const {
                    return static_cast<const Bitcoin::outpoint &> (*this) <=> static_cast<const Bitcoin::outpoint &> (p);
                }
                
            };
            
            bytes Script;
            set<prevout> Prevouts;
            
            digest256 id () const;
            
            candidate (): Script {}, Prevouts {} {};

            // all prevouts must be valid boost outputs that correspond to the same puzzle.
            candidate (list<Bitcoin::prevout> utxos);
            
            bool valid () const;
            double difficulty () const;
            double profitability () const;
            
            Bitcoin::satoshi value () const;
            
            candidate add (const Bitcoin::prevout &p) const;
            
            explicit operator work::candidate () const;
            
        public:
            candidate (const bytes &script, set<prevout> prevouts) :
                Script {script}, Prevouts {prevouts} {}
        };
        
        // A boost output cannot be redeemed until after a miner address
        // is assigned. A puzzle represnts a boost after an address has
        // been assigned. IT is possible for more than one output to 
        // have the same output script. 
        struct puzzle : candidate {
            Bitcoin::secret MinerKey;
            
            bool valid () const;
            
            digest160 miner_pubkey_hash () const;
            
            puzzle ();
            puzzle (const candidate &c, const Bitcoin::secret &addr) :
                candidate {c}, MinerKey {addr} {}
            
            static bytes header (const bytes &tag, const digest160 &miner_pubkey_hash);
            static bytes body (uint32_little user_nonce, const bytes &data);
            
            bytes header () const;
            bytes body () const;
            
            explicit operator work::puzzle () const {
                return work_puzzle (output_script {this->Script}, miner_pubkey_hash ());
            }
            
            // construct a transaction out of a solution and outputs. 
            bytes redeem (const work::solution &, list<Bitcoin::output>) const;
            
            // estimate the size of the inputs in a transaction. 
            size_t expected_size () const;
            
        };
        
        bool inline operator == (const output_script &a, const output_script &b) {
            return a.Type == b.Type && 
                a.Category == b.Category && 
                a.UseGeneralPurposeBits == b.UseGeneralPurposeBits && 
                a.Content == b.Content && 
                a.Target == b.Target && 
                a.Tag == b.Tag && 
                a.UserNonce == b.UserNonce && 
                a.AdditionalData == b.AdditionalData && 
                a.MinerPubkeyHash == b.MinerPubkeyHash;
        }
        
        bool inline operator == (const input_script &a, const input_script &b) {
            return a.Type == b.Type && 
                a.Signature == b.Signature && 
                a.Pubkey == b.Pubkey && 
                a.Nonce == b.Nonce &&
                a.Timestamp == b.Timestamp && 
                a.ExtraNonce1 == b.ExtraNonce1 && 
                a.ExtraNonce2 == b.ExtraNonce2 && 
                a.GeneralPurposeBits == b.GeneralPurposeBits && 
                a.MinerPubkeyHash == b.MinerPubkeyHash;
        }
        
        bool inline operator == (const proof &a, const proof &b) {
            return a.Type == b.Type && work::operator == (static_cast<const work::proof &> (a), static_cast<const work::proof &> (b));
        }
        
        inline output_script::output_script () : Type {Boost::invalid},
            MinerPubkeyHash {}, Category {}, UseGeneralPurposeBits {},
            Content {}, Target {}, Tag {}, UserNonce {},
            AdditionalData {} {}
            
        inline output_script::output_script (
            Boost::type type, 
            int32_little category, 
            const uint256 &content, 
            work::compact target, 
            const bytes &tag, 
            uint32_little user_nonce, 
            const bytes &data, 
            const digest160& miner_pubkey_hash,
            bool masked_category) : output_script {type == Boost::invalid ? output_script {} :
                type == Boost::bounty ? output_script::bounty (category, content, target, tag, user_nonce, data, masked_category) :
                output_script::contract (category, content, target, tag, user_nonce, data, miner_pubkey_hash, masked_category)} {}
        
        output_script inline output_script::bounty (
            int32_little category,
            const uint256 &content,
            work::compact target, 
            const bytes &tag, 
            uint32_little user_nonce, 
            const bytes &data,
            bool masked_category) {
            if (tag.size() > 20) return output_script {};
            return output_script{category, content, target, tag, user_nonce, data, masked_category};
        }
        
        output_script inline output_script::contract (
            int32_little category,
            const uint256 &content,
            work::compact target, 
            const bytes &tag, 
            uint32_little user_nonce, 
            const bytes &data, 
            const digest160& miner_pubkey_hash,
            bool masked_category) {
            return output_script {category,
                content, target, tag, user_nonce, data, 
                miner_pubkey_hash, masked_category};
        }
        
        bool inline output_script::valid () const {
            return Type != Boost::invalid;
        }
        
        inline output_script::output_script (bytes b) : output_script {read (b)} {}
        
        size_t inline output_script::serialized_size () const {
            using namespace Bitcoin;
            return Type == Boost::invalid ? 0 : 
                instruction::min_push_size (Tag) +
                instruction::min_push_size (AdditionalData) +
                (Type == Boost::contract ? 21 : 0) + 112 + 
                (UseGeneralPurposeBits ? 76 : 59);
        }
        
        Boost::type inline output_script::type (Bitcoin::script x) {
            return read (x).Type;
        }
        
        bool inline output_script::valid (Bitcoin::script x) {
            return read (x).valid ();
        }
        
        int32_little inline output_script::version (Bitcoin::script x) {
            return read (x).Type;
        }
        
        uint256 inline output_script::content (Bitcoin::script x) {
            return read (x).Content;
        }
        
        work::compact inline output_script::target (Bitcoin::script x) {
            return read (x).Target;
        }
        
        bytes inline output_script::tag (Bitcoin::script x) {
            return read (x).Tag;
        }
        
        uint32_little inline output_script::user_nonce (Bitcoin::script x) {
            return read (x).UserNonce;
        }
        
        bytes inline output_script::additional_data (Bitcoin::script x) {
            return read (x).AdditionalData;
        }
        
        digest160 inline output_script::miner_pubkey_hash (Bitcoin::script x) {
            return read (x).MinerPubkeyHash;
        }
        
        inline output_script::output_script (
            int32_little category, 
            const uint256 &content,
            work::compact target, 
            const bytes &tag, 
            uint32_little user_nonce, 
            const bytes &data, bool use_general_purpose_bits) : Type {Boost::bounty},
            MinerPubkeyHash {},
            Category {category},
            UseGeneralPurposeBits {use_general_purpose_bits},
            Content {content},
            Target {target},
            Tag {tag},
            UserNonce {user_nonce},
            AdditionalData {data} {}
        
        inline output_script::output_script (
            int32_little category, 
            const uint256 &content,
            work::compact target, 
            const bytes &tag, 
            uint32_little user_nonce, 
            const bytes &data,
            const digest160 &miner_pubkey_hash,
            bool use_general_purpose_bits) : Type {Boost::contract},
            MinerPubkeyHash {miner_pubkey_hash},
            Category {category},
            UseGeneralPurposeBits {use_general_purpose_bits},
            Content {content},
            Target {target},
            Tag {tag},
            UserNonce {user_nonce},
            AdditionalData {data} {}
        
        inline input_script::input_script (
            const Bitcoin::signature &signature, 
            const Bitcoin::pubkey &pubkey, 
            uint32_little nonce,
            Bitcoin::timestamp timestamp,
            const bytes &extra_nonce_2,
            Stratum::session_id extra_nonce_1,
            const digest160 &miner_pubkey_hash) : Type {Boost::bounty},
            Signature {signature},
            Pubkey {pubkey},
            Nonce {nonce},
            Timestamp {timestamp},
            ExtraNonce2 {extra_nonce_2},
            ExtraNonce1 {extra_nonce_1},
            GeneralPurposeBits {},
            MinerPubkeyHash {miner_pubkey_hash} {}
        
        inline input_script::input_script (
            const Bitcoin::signature &signature, 
            const Bitcoin::pubkey &pubkey, 
            uint32_little nonce,
            Bitcoin::timestamp timestamp,
            const bytes &extra_nonce_2,
            Stratum::session_id extra_nonce_1) : Type {Boost::contract},
            Signature {signature},
            Pubkey {pubkey},
            Nonce {nonce},
            Timestamp {timestamp},
            ExtraNonce2 {extra_nonce_2},
            ExtraNonce1 {extra_nonce_1},
            GeneralPurposeBits {},
            MinerPubkeyHash {} {}
        
        inline input_script::input_script (
            const Bitcoin::signature &signature, 
            const Bitcoin::pubkey &pubkey, 
            uint32_little nonce,
            Bitcoin::timestamp timestamp,
            const bytes &extra_nonce_2,
            Stratum::session_id extra_nonce_1,
            int32_little general_purpose_bits, 
            const digest160 &miner_pubkey_hash) : Type {Boost::bounty},
            Signature {signature},
            Pubkey {pubkey},
            Nonce {nonce},
            Timestamp {timestamp},
            ExtraNonce2 {extra_nonce_2},
            ExtraNonce1 {extra_nonce_1},
            GeneralPurposeBits {general_purpose_bits},
            MinerPubkeyHash {miner_pubkey_hash} {}
        
        inline input_script::input_script (
            const Bitcoin::signature &signature, 
            const Bitcoin::pubkey &pubkey, 
            uint32_little nonce,
            Bitcoin::timestamp timestamp,
            const bytes &extra_nonce_2,
            Stratum::session_id extra_nonce_1,
            int32_little general_purpose_bits) : Type {Boost::contract},
            Signature {signature},
            Pubkey {pubkey},
            Nonce {nonce},
            Timestamp {timestamp},
            ExtraNonce2 {extra_nonce_2},
            ExtraNonce1 {extra_nonce_1},
            GeneralPurposeBits {general_purpose_bits},
            MinerPubkeyHash {} {}
        
        bool inline input_script::valid () const {
            return Type != Boost::invalid && 
                (ExtraNonce2.size () == 8 || (bool (GeneralPurposeBits) && ExtraNonce2.size () <= 32));
        }
        
        Bitcoin::script inline input_script::write () const {
            return Bitcoin::compile (program ());
        }
        
        size_t inline input_script::serialized_size () const {
            using namespace Bitcoin;
            return Type == Boost::invalid ? 0 :
                instruction::min_push_size (Signature) +
                instruction::min_push_size (Pubkey) +
                instruction::min_push_size (ExtraNonce2) +
                    (Type == Boost::bounty ? 21 : 0) + 
                    (bool (GeneralPurposeBits) ? 5 : 0) + 15;
        }
        
        // construct a Boost bounty input script. 
        input_script inline input_script::bounty (
            const Bitcoin::signature &signature, 
            const Bitcoin::pubkey &pubkey,  
            uint32_little nonce,
            Bitcoin::timestamp timestamp,
            const bytes &extra_nonce_2,
            Stratum::session_id extra_nonce_1, 
            const digest160 &miner_pubkey_hash) {
            return input_script {signature, pubkey, nonce, timestamp, extra_nonce_2, extra_nonce_1, miner_pubkey_hash};
        }
        
        // construct a Boost bounty input script. 
        input_script inline input_script::bounty (
            const Bitcoin::signature &signature, 
            const Bitcoin::pubkey &pubkey,  
            uint32_little nonce,
            Bitcoin::timestamp timestamp,
            const bytes &extra_nonce_2,
            Stratum::session_id extra_nonce_1, 
            int32_little category_bits, 
            const digest160 &miner_pubkey_hash) {
            return input_script {signature, pubkey, nonce, timestamp, extra_nonce_2, extra_nonce_1, category_bits, miner_pubkey_hash};
        }
        
        // construct a Boost contract input script.
        input_script inline input_script::contract (
            const Bitcoin::signature &signature, 
            const Bitcoin::pubkey &pubkey,  
            uint32_little nonce,
            Bitcoin::timestamp timestamp,
            const bytes &extra_nonce_2,
            Stratum::session_id extra_nonce_1) {
            return input_script {signature, pubkey, nonce, timestamp, extra_nonce_2, extra_nonce_1};
        }
        
        input_script inline input_script::contract (
            const Bitcoin::signature &signature, 
            const Bitcoin::pubkey &pubkey,  
            uint32_little nonce,
            Bitcoin::timestamp timestamp,
            const bytes &extra_nonce_2,
            Stratum::session_id extra_nonce_1, 
            int32_little category_bits) {
            return input_script {signature, pubkey, nonce, timestamp, extra_nonce_2, extra_nonce_1, category_bits};
        }
        
        inline input_script::input_script (bytes b) : input_script {read (b)} {}
        
        Boost::type inline input_script::type (Bitcoin::script x) {
            return read (x).Type;
        }
        
        bool inline input_script::valid (Bitcoin::script x) {
            return read (x).valid ();
        }
        
        Bitcoin::signature inline input_script::signature (Bitcoin::script x) {
            return read (x).Signature;
        }
        
        Bitcoin::pubkey inline input_script::pubkey (Bitcoin::script x) {
            return read (x).Pubkey;
        }
        
        Bitcoin::timestamp inline input_script::timestamp (Bitcoin::script x) {
            return read (x).Timestamp;
        }
        
        uint32_little inline input_script::nonce (Bitcoin::script x) {
            return read (x).Nonce;
        }
        
        digest160 inline input_script::miner_pubkey_hash (Bitcoin::script x) {
            return read (x).MinerPubkeyHash;
        }
            
        uint64 inline input_script::expected_size (Boost::type t, bool use_general_purpose_bits, bool compressed_pubkey) {
            return t == Boost::invalid ? 0 : 
                Bitcoin::signature::MaxSize + 
                (compressed_pubkey ? 34 : 66) + 
                (t == Boost::bounty ? 21 : 0) + 
                (use_general_purpose_bits ? 5 : 0) + 24;
        }

        work::solution inline input_script::solution (Bitcoin::script x) {
            return read (x).solution ();
        }

        work::solution inline input_script::solution () const {
            return work::solution {Timestamp, Nonce, ExtraNonce2, ExtraNonce1};
        }
        
        inline proof::proof () : work::proof {}, Type {invalid} {}
        
        inline proof::proof (type t, const work::string &w, const bytes &h,
            const Stratum::session_id &n1, const bytes &n2, const bytes &b, 
            const Bitcoin::signature &x, const Bitcoin::pubkey &p) :
            work::proof {w, {}, h, n1, n2, b}, Type {t}, Signature {x}, Pubkey {p} {}
        
        inline proof::proof (const work::job &j, const work::share &h, type t, const Bitcoin::signature &x, const Bitcoin::pubkey &p) :
                work::proof {j, h}, Type{t}, Signature {x}, Pubkey {p} {}
        
        digest160 inline puzzle::miner_pubkey_hash () const {
            return Bitcoin::Hash160 (MinerKey.to_public ());
        }
        
        input_script inline proof::input_script () const {
            return Boost::input_script {Signature, Pubkey, work::proof::Solution, Type, work::proof::Puzzle.Mask != 0};
        }

        bool inline proof::valid () const {
            return (work::proof::Puzzle.Mask == -1 || work::proof::Puzzle.Mask == work::ASICBoost::Mask) && work::proof::valid ();
        }
        
        inline candidate::candidate (list<Bitcoin::prevout> utxos) :
            Script {first (utxos).script ()}, Prevouts {
                data::fold ([] (set<prevout> x, const Bitcoin::prevout &p) -> set<prevout> {
                    return x.insert (prevout {p.outpoint (), p.value ()});
                }, set<prevout> {}, utxos)} {}
        
        double inline candidate::difficulty () const {
            return double (work::difficulty (output_script {Script}.Target));
        }
        
        double inline candidate::profitability () const {
            return double (value ()) / difficulty ();
        }
        
        bool inline operator == (const candidate &a, const candidate &b) {
            return a.Script == b.Script && b.Prevouts == b.Prevouts;
        }
        
        candidate inline candidate::add (const Bitcoin::prevout &p) const {
            prevout pp {p.outpoint (), p.value ()};
            return Prevouts.size () == 0 ? candidate {p.script (), {pp}} :
                Prevouts.contains (pp) ? *this : candidate {Script, Prevouts.insert (pp)};
        }
        
        digest256 inline candidate::id () const {
            return SHA2_256 (Script);
        }
        
        Bitcoin::satoshi inline candidate::value () const {
            Bitcoin::satoshi so_far {0};
            for (const prevout &u : Prevouts) so_far += u.Value;
            return so_far;
        }

        bool inline candidate::valid () const {
            return Prevouts.size () > 0 && Prevouts.valid () && output_script {Script}.valid ();
        }

        bytes inline puzzle::header (const bytes &tag, const digest160 &miner_pubkey_hash) {
            return write (tag.size () + 20, tag, miner_pubkey_hash);
        }

        bytes inline puzzle::body (uint32_little user_nonce, const bytes& data) {
            return write (data.size () + 4, user_nonce, data);
        }

        bytes inline puzzle::header () const {
            return header (output_script {Script}.Tag, miner_pubkey_hash ());
        }

        bytes inline puzzle::body () const {
            return body (output_script {Script}.UserNonce, output_script {Script}.AdditionalData);
        }

        inline puzzle::puzzle (): candidate {}, MinerKey {} {}
        
    }
    
}

#endif
