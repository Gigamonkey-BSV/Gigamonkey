#ifndef GIGAMONKEY_BOOST_BOOST
#define GIGAMONKEY_BOOST_BOOST

#include <gigamonkey/script.hpp>
#include <gigamonkey/address.hpp>
#include <gigamonkey/work/proof.hpp>
#include <gigamonkey/redeem.hpp>

namespace Gigamonkey {
    
    using price = double; 
    
    namespace Boost {
        
        enum type {invalid, bounty, contract};
        
        struct output_script;
        struct input_script;
        
        bool operator==(const output_script&, const output_script&);
        bool operator!=(const output_script&, const output_script&);
        
        bool operator==(const input_script&, const input_script&);
        bool operator!=(const input_script&, const input_script&);

        std::ostream& operator<<(std::ostream& o, const output_script s);
        std::ostream& operator<<(std::ostream& o, const input_script s);
        
        // A job is a work::puzzle without ExtraNonce1 and with a Boost type. 
        // Both an address and key are associated with it.  
        struct job;
        
        // A puzzle is created after ExtraNonce is assigned by the mining pool.
        struct puzzle;
        
        struct proof;
        
        bool operator==(const job&, const job&);
        bool operator!=(const job&, const job&);
        
        bool operator==(const puzzle&, const puzzle&);
        bool operator!=(const puzzle&, const puzzle&);
        
        // for wallets
        struct output;
        struct redeem_boost;
        
        struct output_script {
            Boost::type Type;
            int32_little Category;
            uint256 Content;
            work::compact Target;
            bytes Tag;
            uint32_little UserNonce;
            bytes AdditionalData;
            digest160 MinerAddress;
            
            output_script();
                
            output_script(
                Boost::type type, 
                int32_little category, 
                uint256 content, 
                work::compact target, 
                bytes tag, 
                uint32_little user_nonce, 
                bytes data, 
                digest160 miner_address);
            
            static output_script bounty(
                int32_little category,
                uint256 content,
                work::compact target, 
                bytes_view tag, 
                uint32_little user_nonce, 
                bytes_view data);
            
            static output_script contract(
                int32_little category,
                uint256 content,
                work::compact target, 
                bytes_view tag, 
                uint32_little user_nonce, 
                bytes_view data, 
                digest160 miner_address);
            
            bool valid() const;
            
            script write() const; 
            
            digest256 hash() const;
            
            static output_script read(bytes);
            
            explicit output_script(bytes b);
            
            size_t serialized_size() const;
            static Boost::type type(script x);
            static bool valid(script x);
            static uint256 hash(script x);
            static int32_little version(script x);
            static uint256 content(script x);
            static work::compact target(script x);
            static bytes tag(script x);
            static uint32_little user_nonce(script x);
            static bytes additional_data(script x);
            static digest160 miner_address(script x);
            
        private:
            output_script(
                int32_little category, 
                uint256 content,
                work::compact target, 
                bytes_view tag, 
                uint32_little user_nonce, 
                bytes_view data);
            
            output_script(
                int32_little category, 
                uint256 content,
                work::compact target, 
                bytes_view tag, 
                uint32_little user_nonce, 
                bytes_view data,
                digest160 miner_address);
                
            static output_script from_data(
                Boost::type type, 
                int32_little category, 
                uint256 content, 
                work::compact target, 
                bytes tag, 
                uint32_little user_nonce, 
                bytes data, 
                digest160 miner_address);
            
        };
        
        struct input_script {
            Boost::type Type;
            Bitcoin::signature Signature;
            Bitcoin::pubkey Pubkey;
            uint32_little Nonce;
            Bitcoin::timestamp Timestamp;
            uint64_big ExtraNonce2;
            Stratum::session_id ExtraNonce1;
            digest160 MinerAddress;
            
        private:
            input_script(
                Bitcoin::signature signature, 
                Bitcoin::pubkey pubkey, 
                uint32_little nonce,
                Bitcoin::timestamp timestamp,
                uint64_big extra_nonce_2,
                Stratum::session_id extra_nonce_1,
                digest160 miner_address);
            
            input_script(
                Bitcoin::signature signature, 
                Bitcoin::pubkey pubkey, 
                uint32_little nonce,
                Bitcoin::timestamp timestamp,
                uint64_big extra_nonce_2,
                Stratum::session_id extra_nonce_1);
                
        public:
            input_script() = default;
            
            bool valid() const;
            
            Bitcoin::program program() const; 
            
            script write() const;
            
            size_t serialized_size() const;
            
            // construct a Boost bounty input script. 
            static input_script bounty(
                Bitcoin::signature signature, 
                Bitcoin::pubkey pubkey,  
                uint32_little nonce,
                Bitcoin::timestamp timestamp,
                uint64_big extra_nonce_2,
                Stratum::session_id extra_nonce_1, 
                digest160 miner_address);
            
            // construct a Boost contract input script.
            static input_script contract(
                Bitcoin::signature signature, 
                Bitcoin::pubkey pubkey,  
                uint32_little nonce,
                Bitcoin::timestamp timestamp,
                uint64_big extra_nonce_2,
                Stratum::session_id extra_nonce_1);
            
            static input_script read(bytes); 
            
            explicit input_script(bytes b);
            
            static Boost::type type(script x);
            static bool valid(script x);
            static Bitcoin::signature signature(script x);
            static Bitcoin::pubkey pubkey(script x);
            static Bitcoin::timestamp timestamp(script x);
            static uint32_little nonce(script x);
            static digest160 miner_address(script x);
            
            input_script(
                Bitcoin::signature signature, 
                Bitcoin::pubkey pubkey, 
                Stratum::session_id nonce1,
                work::solution, Boost::type);
        };
        
        // A job is a work::puzzle without ExtraNonce1 and with a Boost type. 
        // Both an address and key are associated with it.  
        struct job {
            type Type;
            int32_little Category;
            uint256 Content;
            work::compact Target;
            bytes Tag;
            uint32_little UserNonce;
            bytes AdditionalData;
            Bitcoin::secret MinerKey;
            
            bool valid() const;
            
            job();
            job(Boost::type type, 
                int32_little category, 
                const uint256& content, 
                work::compact target, 
                const bytes& tag, 
                uint32_little user_nonce, 
                const bytes& data, 
                const Bitcoin::secret& miner_key);
            job(const Boost::output_script& x, const Bitcoin::secret& addr);
            
            Boost::output_script output_script() const;
            digest160 miner_address() const;
        };
        
        // A puzzle is created after ExtraNonce is assigned by the mining pool. 
        struct puzzle : work::puzzle {
            type Type;
            
            bool valid() const;
            
            puzzle();
            puzzle(Boost::type type, 
                int32_little category, 
                const uint256& content, 
                work::compact target, 
                const bytes& tag, 
                uint32_little user_nonce, 
                const bytes& data, 
                const digest160& miner_address, 
                Stratum::session_id extra_nonce_1);
            puzzle(const Boost::output_script& x, const digest160& miner_address, Stratum::session_id extra_nonce_1);
            
            Boost::output_script output_script() const; 
            digest160 miner_address() const;

        private:
            puzzle(work::puzzle p, type t);
            
            static puzzle make(Boost::type type, 
                int32_little category, 
                const uint256& content, 
                work::compact target, 
                const bytes& tag, 
                uint32_little user_nonce, 
                const bytes& data, 
                const digest160& miner_address, 
                Stratum::session_id extra_nonce_1);
            
            friend struct proof;
        };
        
        struct proof : work::proof {
            type Type;
            
            proof();
            proof(const Boost::puzzle& p, const work::solution& x);
            proof(const Boost::output_script& out, const Boost::input_script& in);
            proof(type t, const work::string& w, const bytes& h, 
                const Stratum::session_id& n1, const uint64_big& n2, const bytes& b);
                
            Boost::puzzle puzzle() const;
            Boost::output_script output_script() const;
            Boost::input_script input_script() const;
        };
        
        struct output {
            Bitcoin::outpoint Reference;
            output_script Script;
            satoshi Value;
            digest256 ID;
            
            output() : Reference{}, Script{}, Value{0}, ID{} {}
            output(const Bitcoin::outpoint& o, const output_script& s, satoshi v) : 
                Reference{o}, Script{s}, Value{v}, ID{s.hash()} {}
                
            bool valid() const {
                return Reference != Bitcoin::outpoint::coinbase() && Script.valid() && ID.valid();
            }
            
        private:
            output(const Bitcoin::outpoint& o, const output_script& j, satoshi v, const uint256& id) : 
                Reference{o}, Script{j}, Value{v}, ID{id} {}
        };
        
        struct redeem_boost final : Bitcoin::redeemable {
            Bitcoin::secret Secret;
            Bitcoin::pubkey Pubkey;
            Stratum::session_id ExtraNonce1;
            work::solution Solution;
            type Type;
            
            Bitcoin::redemption::incomplete redeem(Bitcoin::sighash::directive d) const override {
                Bitcoin::program p = input_script{Bitcoin::signature{}, Pubkey, ExtraNonce1, Solution, Type}.program();
                if (p.empty()) return {};
                return {Bitcoin::redemption::element{&Secret, d}, compile(p.rest())};
            }
            
            uint32 expected_size() const override;
            
            uint32 sigops() const override;
        };
        
        inline bool operator==(const output_script& a, const output_script& b) {
            return a.Type == b.Type && 
                a.Category == b.Category && 
                a.Content == b.Content && 
                a.Target == b.Target && 
                a.Tag == b.Tag && 
                a.UserNonce == b.UserNonce && 
                a.AdditionalData == b.AdditionalData && 
                a.MinerAddress == b.MinerAddress;
        }
            
        inline bool operator!=(const output_script& a, const output_script& b) {
            return !(a == b);
        }
        
        inline bool operator==(const input_script& a, const input_script& b) {
            return a.Type == b.Type && 
                a.Signature == b.Signature && 
                a.Pubkey == b.Pubkey && 
                a.Nonce == b.Nonce &&
                a.Timestamp == b.Timestamp && 
                a.ExtraNonce1 == b.ExtraNonce1 && 
                a.ExtraNonce2 == b.ExtraNonce2 && 
                a.MinerAddress == b.MinerAddress;
        }
        
        inline bool operator!=(const input_script& a, const input_script& b) {
            return !(a == b);
        }
        
        inline bool operator==(const job& a, const job& b) {
            return a.Type == b.Type && a.Category == b.Category && a.Content == b.Content && 
                a.Target == b.Target && a.Tag == b.Tag && a.UserNonce == b.UserNonce && 
                a.AdditionalData == b.AdditionalData && a.MinerKey == b.MinerKey;
        }
        
        inline bool operator!=(const job& a, const job& b) {
            return !(a == b);
        }
        
        inline bool operator==(const puzzle& a, const puzzle& b) {
            return a.Type == b.Type && 
                work::operator==(static_cast<const work::puzzle&>(a), static_cast<const work::puzzle&>(b));
        }
        
        inline bool operator!=(const puzzle& a, const puzzle& b) {
            return !(a == b);
        }
        
        inline bool operator==(const proof& a, const proof& b) {
            return a.Type == b.Type && work::operator==(static_cast<const work::proof&>(a), static_cast<const work::proof&>(b));
        }
        
        inline bool operator!=(const proof& a, const proof& b) {
            return !(a == b);
        }
        
        inline output_script::output_script() : Type{Boost::invalid}, 
            Category{}, Content{}, Target{}, 
            Tag{}, UserNonce{}, 
            AdditionalData{}, MinerAddress{} {} 
            
        inline output_script::output_script(
            Boost::type type, 
            int32_little category, 
            uint256 content, 
            work::compact target, 
            bytes tag, 
            uint32_little user_nonce, 
            bytes data, 
            digest160 miner_address) : 
            output_script{from_data(type, category, content, target, tag, user_nonce, data, miner_address)} {}
        
        output_script inline output_script::bounty(
            int32_little category,
            uint256 content,
            work::compact target, 
            bytes_view tag, 
            uint32_little user_nonce, 
            bytes_view data) {
            if (tag.size() > 20) return output_script{};
            return output_script{category, 
                content, target, tag, user_nonce, data};    
        }
        
        output_script inline output_script::contract(
            int32_little category,
            uint256 content,
            work::compact target, 
            bytes_view tag, 
            uint32_little user_nonce, 
            bytes_view data, 
            digest160 miner_address) {
            return output_script{category, 
                content, target, tag, user_nonce, data, 
                miner_address}; 
        }
        
        bool inline output_script::valid() const {
            return Type != Boost::invalid;
        }
        
        digest256 inline output_script::hash() const {
            return valid() ? Bitcoin::hash256(write()) : digest256{};
        }
        
        inline output_script::output_script(bytes b) : output_script{read(b)} {}
        
        size_t inline output_script::serialized_size() const {
            return write().size();
        }
        
        Boost::type inline output_script::type(script x) {
            return read(x).Type;
        }
        
        bool inline output_script::valid(script x) {
            return read(x).valid();
        }
        
        uint256 inline output_script::hash(script x) {
            return read(x).hash();
        }
        
        int32_little inline output_script::version(script x) {
            return read(x).Type;
        }
        
        uint256 inline output_script::content(script x) {
            return read(x).Content;
        }
        
        work::compact inline output_script::target(script x) {
            return read(x).Target;
        }
        
        bytes inline output_script::tag(script x) {
            return read(x).Tag;
        }
        
        uint32_little inline output_script::user_nonce(script x) {
            return read(x).UserNonce;
        }
        
        bytes inline output_script::additional_data(script x) {
            return read(x).AdditionalData;
        }
        
        digest160 inline output_script::miner_address(script x) {
            return read(x).MinerAddress;
        }
        
        inline output_script::output_script(
            int32_little category, 
            uint256 content,
            work::compact target, 
            bytes_view tag, 
            uint32_little user_nonce, 
            bytes_view data) : Type{Boost::bounty}, 
            Category{category},
            Content{content}, 
            Target{target}, 
            Tag{tag}, 
            UserNonce{user_nonce}, 
            AdditionalData{data}, 
            MinerAddress{} {}
        
        inline output_script::output_script(
            int32_little category, 
            uint256 content,
            work::compact target, 
            bytes_view tag, 
            uint32_little user_nonce, 
            bytes_view data,
            digest160 miner_address) : Type{Boost::contract}, 
            Category{category},
            Content{content}, 
            Target{target}, 
            Tag{tag}, 
            UserNonce{user_nonce}, 
            AdditionalData{data}, 
            MinerAddress{miner_address} {} 
            
        output_script inline output_script::from_data(
            Boost::type type, 
            int32_little category, 
            uint256 content, 
            work::compact target, 
            bytes tag, 
            uint32_little user_nonce, 
            bytes data, 
            digest160 miner_address) {
            if (type == Boost::invalid) return {};
            if (type == Boost::bounty) return output_script::bounty(category, content, target, tag, user_nonce, data);
            return output_script::contract(category, content, target, tag, user_nonce, data, miner_address);
        }
        
        inline input_script::input_script(
            Bitcoin::signature signature, 
            Bitcoin::pubkey pubkey, 
            uint32_little nonce,
            Bitcoin::timestamp timestamp,
            uint64_big extra_nonce_2,
            Stratum::session_id extra_nonce_1,
            digest160 miner_address) : Type{Boost::bounty}, 
            Signature{signature}, 
            Pubkey{pubkey}, 
            Nonce{nonce},
            Timestamp{timestamp},
            ExtraNonce2{extra_nonce_2},
            ExtraNonce1{extra_nonce_1},
            MinerAddress{miner_address} {}
        
        inline input_script::input_script(
            Bitcoin::signature signature, 
            Bitcoin::pubkey pubkey, 
            uint32_little nonce,
            Bitcoin::timestamp timestamp,
            uint64_big extra_nonce_2,
            Stratum::session_id extra_nonce_1) : Type{Boost::contract}, 
            Signature{signature}, 
            Pubkey{pubkey}, 
            Nonce{nonce}, 
            Timestamp{timestamp},
            ExtraNonce2{extra_nonce_2},
            ExtraNonce1{extra_nonce_1},
            MinerAddress{} {}
        
        bool inline input_script::valid() const {
            return Type != Boost::invalid;
        }
        
        script inline input_script::write() const {
            return Bitcoin::compile(program());
        }
        
        size_t inline input_script::serialized_size() const {
            return write().size();
        }
        
        // construct a Boost bounty input script. 
        input_script inline input_script::bounty(
            Bitcoin::signature signature, 
            Bitcoin::pubkey pubkey,  
            uint32_little nonce,
            Bitcoin::timestamp timestamp,
            uint64_big extra_nonce_2,
            Stratum::session_id extra_nonce_1, 
            digest160 miner_address) {
            return input_script{signature, pubkey, nonce, timestamp, extra_nonce_2, extra_nonce_1, miner_address};
        }
        
        // construct a Boost contract input script.
        input_script inline input_script::contract(
            Bitcoin::signature signature, 
            Bitcoin::pubkey pubkey,  
            uint32_little nonce,
            Bitcoin::timestamp timestamp,
            uint64_big extra_nonce_2,
            Stratum::session_id extra_nonce_1) {
            return input_script{signature, pubkey, nonce, timestamp, extra_nonce_2, extra_nonce_1};
        }
        
        inline input_script::input_script(bytes b) : input_script{read(b)} {}
        
        Boost::type inline input_script::type(script x) {
            return read(x).Type;
        }
        
        bool inline input_script::valid(script x) {
            return read(x).valid();
        }
        
        Bitcoin::signature inline input_script::signature(script x) {
            return read(x).Signature;
        }
        
        Bitcoin::pubkey inline input_script::pubkey(script x) {
            return read(x).Pubkey;
        }
        
        Bitcoin::timestamp inline input_script::timestamp(script x) {
            return read(x).Timestamp;
        }
        
        uint32_little inline input_script::nonce(script x) {
            return read(x).Nonce;
        }
        
        digest160 inline input_script::miner_address(script x) {
            return read(x).MinerAddress;
        }
        
        bool inline job::valid() const { 
            return Target.valid() && MinerKey.valid() && 
                (Type == Boost::bounty || Type == Boost::contract);
        }
        
        inline job::job() : Type{invalid}, Category{}, Content{}, Target{}, Tag{}, UserNonce{}, AdditionalData{}, MinerKey{} {}
        
        inline job::job(Boost::type type, 
            int32_little category, 
            const uint256& content, 
            work::compact target, 
            const bytes& tag, 
            uint32_little user_nonce, 
            const bytes& data, 
            const Bitcoin::secret& miner_key) : 
            Type{type}, Category{category}, Content{content}, Target{target}, Tag{tag}, UserNonce{user_nonce}, 
            AdditionalData{data}, MinerKey{miner_key} {}
        
        inline job::job(const Boost::output_script& x, const Bitcoin::secret& addr) : job{} {
            if (x.Type == invalid) return;
            if (x.Type == contract && x.MinerAddress != addr.address().Digest) return;
            *this = job{x.Type, x.Category, x.Content, x.Target, x.Tag, x.UserNonce, x.AdditionalData, addr};
        }
        
        Boost::output_script inline job::output_script() const {
            switch (Type) {
                case bounty : 
                    return Boost::output_script::bounty(
                        Category, Content, Target, Tag, 
                        UserNonce, AdditionalData);
                case contract : 
                    return Boost::output_script::contract(
                        Category, Content, Target, Tag, 
                        UserNonce, AdditionalData, miner_address());
                default: return Boost::output_script{};
            }
        }
            
        digest160 inline job::miner_address() const {
            return MinerKey.address().Digest;
        }
        
        bool inline puzzle::valid() const {
            return Type != Boost::invalid && work::puzzle::valid();
        }
        
        inline puzzle::puzzle() : work::puzzle{}, Type{invalid} {}
        
        inline puzzle::puzzle(Boost::type type, 
            int32_little category, 
            const uint256& content, 
            work::compact target, 
            const bytes& tag, 
            uint32_little user_nonce, 
            const bytes& data, 
            const digest160& miner_address, 
            Stratum::session_id extra_nonce_1) : 
            puzzle(make(type, category, content, target, tag, user_nonce, data, miner_address, extra_nonce_1)) {}
        
        inline puzzle::puzzle(const Boost::output_script& x, const digest160& miner_address, Stratum::session_id extra_nonce_1) {
            if (x.Type == invalid) return;
            if (x.Type == contract && x.MinerAddress != miner_address) return;
            *this = puzzle{x.Type, x.Category, x.Content, x.Target, 
                x.Tag, x.UserNonce, x.AdditionalData, miner_address, extra_nonce_1};
        }
        
        inline puzzle::puzzle(work::puzzle p, type t) : work::puzzle{p}, Type{t} {}
        
        puzzle inline puzzle::make(Boost::type type, 
            int32_little category, 
            const uint256& content, 
            work::compact target, 
            const bytes& tag, 
            uint32_little user_nonce, 
            const bytes& data, 
            const digest160& miner_address, 
            Stratum::session_id extra_nonce_1) {
            if (type == invalid) return {};
            return puzzle{work::puzzle{category, content, target, Merkle::path{}, 
                write(tag.size() + 20, tag, miner_address), extra_nonce_1, 
                write(data.size() + 4, user_nonce, data)}, type};
        }
        
        inline proof::proof() : work::proof{}, Type{invalid} {}
        
        inline proof::proof(const Boost::puzzle& p, const work::solution& x) : 
            work::proof{static_cast<const work::puzzle&>(p), x}, Type{p.Type} {}
        
        inline proof::proof(const Boost::output_script& out, const Boost::input_script& in) : proof{} {
            if (out.Type == invalid || in.Type != out.Type) return;
            *this = proof{Boost::puzzle{out.Type, out.Category, out.Content, 
                    out.Target, out.Tag, out.UserNonce, out.AdditionalData, 
                    out.Type == bounty ? in.MinerAddress : out.MinerAddress, in.ExtraNonce1},
                work::solution{in.Timestamp, in.Nonce, in.ExtraNonce2}};
        }
        
        inline proof::proof(type t, const work::string& w, const bytes& h, 
            const Stratum::session_id& n1, const uint64_big& n2, const bytes& b) : 
            work::proof{w, {}, h, n1, n2, b}, Type{t} {}
            
        puzzle inline proof::puzzle() const {
            return Boost::puzzle{work::proof::Puzzle, Type};
        }
        
        output_script inline proof::output_script() const {
            return puzzle().output_script();
        }
        
    }
    
}

#endif

