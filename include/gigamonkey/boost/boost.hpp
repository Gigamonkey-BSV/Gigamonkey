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
        
        struct output_script {
            Boost::type Type;
            int32_little Category;
            uint256 Content;
            work::target Target;
            bytes Tag;
            uint32_little UserNonce;
            bytes AdditionalData;
            digest160 MinerAddress;
            
            output_script() : Type{Boost::invalid}, 
                Category{}, Content{}, Target{}, 
                Tag{}, UserNonce{}, 
                AdditionalData{}, MinerAddress{} {} 
                
            output_script(
                Boost::type type, 
                int32_little category, 
                uint256 content, 
                work::target target, 
                bytes tag, 
                uint32_little user_nonce, 
                bytes data, 
                digest160 miner_address) : 
                output_script{from_data(type, category, content, target, tag, user_nonce, data, miner_address)} {}
            
            static output_script bounty(
                int32_little category,
                uint256 content,
                work::target target, 
                bytes_view tag, 
                uint32_little user_nonce, 
                bytes_view data) {
                if (tag.size() > 20) return output_script{};
                return output_script{category, 
                    content, target, tag, user_nonce, data};    
            }
            
            static output_script contract(
                int32_little category,
                uint256 content,
                work::target target, 
                bytes_view tag, 
                uint32_little user_nonce, 
                bytes_view data, 
                digest160 miner_address) {
                return output_script{category, 
                    content, target, tag, user_nonce, data, 
                    miner_address}; 
            }
            
            bool valid() const {
                return Type != Boost::invalid;
            }
            
            script write() const; 
            
            digest256 hash() const {
                return valid() ? Bitcoin::hash256(write()) : digest256{};
            }
            
            static output_script read(bytes);
            
            explicit output_script(bytes b) : output_script{read(b)} {}
        
            bool operator==(const output_script& o) const {
                return Type == o.Type && 
                    Category == o.Category && 
                    Content == o.Content && 
                    Target == o.Target && 
                    Tag == o.Tag && 
                    UserNonce == o.UserNonce && 
                    AdditionalData == o.AdditionalData && 
                    MinerAddress == o.MinerAddress;
            }
            
            bool operator!=(const output_script& o) const {
                return !operator==(o);
            }
            
            static Boost::type type(script x) {
                return read(x).Type;
            }
            
            static bool valid(script x) {
                return read(x).valid();
            }
            
            static uint256 hash(script x) {
                return read(x).hash();
            }
            
            static int32_little version(script x) {
                return read(x).Type;
            }
            
            static uint256 content(script x) {
                return read(x).Content;
            }
            
            static work::target target(script x) {
                return read(x).Target;
            }
            
            static bytes tag(script x) {
                return read(x).Tag;
            }
            
            static uint32_little user_nonce(script x) {
                return read(x).UserNonce;
            }
            
            static bytes additional_data(script x) {
                return read(x).AdditionalData;
            }
            
            static digest160 miner_address(script x) {
                return read(x).MinerAddress;
            }
            
        private:
            output_script(
                int32_little category, 
                uint256 content,
                work::target target, 
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
            
            output_script(
                int32_little category, 
                uint256 content,
                work::target target, 
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
                
            static output_script from_data(
                Boost::type type, 
                int32_little category, 
                uint256 content, 
                work::target target, 
                bytes tag, 
                uint32_little user_nonce, 
                bytes data, 
                digest160 miner_address) {
                if (type == Boost::invalid) return {};
                if (type == Boost::bounty) return output_script::bounty(category, content, target, tag, user_nonce, data);
                return output_script::contract(category, content, target, tag, user_nonce, data, miner_address);
            }
            
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
                return Reference.valid() && Script.valid() && ID.valid();
            }
            
        private:
            output(const Bitcoin::outpoint& o, const output_script& j, satoshi v, const uint256& id) : 
                Reference{o}, Script{j}, Value{v}, ID{id} {}
        };
        
        struct input_script {
            Boost::type Type;
            Bitcoin::signature Signature;
            Bitcoin::pubkey Pubkey;
            uint32_little Nonce;
            Gigamonkey::timestamp Timestamp;
            uint64_little ExtraNonce2;
            uint32_little ExtraNonce1;
            digest160 MinerAddress;
            
        private:
            input_script(
                Bitcoin::signature signature, 
                Bitcoin::pubkey pubkey, 
                uint32_little nonce,
                Gigamonkey::timestamp timestamp,
                uint64_little extra_nonce_2,
                uint32_little extra_nonce_1,
                digest160 miner_address) : Type{Boost::bounty}, 
                Signature{signature}, 
                Pubkey{pubkey}, 
                Nonce{nonce},
                Timestamp{timestamp},
                ExtraNonce2{extra_nonce_2},
                ExtraNonce1{extra_nonce_1},
                MinerAddress{miner_address} {}
            
            input_script(
                Bitcoin::signature signature, 
                Bitcoin::pubkey pubkey, 
                uint32_little nonce,
                Gigamonkey::timestamp timestamp,
                uint64_little extra_nonce_2,
                uint32_little extra_nonce_1) : Type{Boost::contract}, 
                Signature{signature}, 
                Pubkey{pubkey}, 
                Nonce{nonce}, 
                Timestamp{timestamp},
                ExtraNonce2{extra_nonce_2},
                ExtraNonce1{extra_nonce_1},
                MinerAddress{} {}
                
        public:
            input_script() = default;
            
            bool valid() const {
                return Type != Boost::invalid;
            }
            
            Bitcoin::program program() const; 
            
            script write() const {
                return Bitcoin::compile(program());
            }
            
            // construct a Boost bounty input script. 
            static input_script bounty(
                Bitcoin::signature signature, 
                Bitcoin::pubkey pubkey,  
                uint32_little nonce,
                Gigamonkey::timestamp timestamp,
                uint64_little extra_nonce_2,
                uint32_little extra_nonce_1, 
                digest160 miner_address) {
                return input_script{signature, pubkey, nonce, timestamp, extra_nonce_2, extra_nonce_1, miner_address};
            }
            
            // construct a Boost contract input script.
            static input_script contract(
                Bitcoin::signature signature, 
                Bitcoin::pubkey pubkey,  
                uint32_little nonce,
                Gigamonkey::timestamp timestamp,
                uint64_little extra_nonce_2,
                uint32_little extra_nonce_1) {
                return input_script{signature, pubkey, nonce, timestamp, extra_nonce_2, extra_nonce_1};
            }
            
            static input_script read(bytes); 
            
            explicit input_script(bytes b) : input_script{read(b)} {}
        
            bool operator==(const input_script& i) const {
                return Type == i.Type && 
                    Signature == i.Signature && 
                    Pubkey == i.Pubkey && 
                    Nonce == i.Nonce &&
                    Timestamp == i.Timestamp && 
                    ExtraNonce1 == i.ExtraNonce1 && 
                    ExtraNonce2 == i.ExtraNonce2 && 
                    MinerAddress == i.MinerAddress;
            }
            
            bool operator!=(const input_script& i) const {
                return !operator==(i);
            }
            
            static Boost::type type(script x) {
                return read(x).Type;
            }
            
            static bool valid(script x) {
                return read(x).valid();
            }
            
            static Bitcoin::signature signature(script x) {
                return read(x).Signature;
            }
            
            static Bitcoin::pubkey pubkey(script x) {
                return read(x).Pubkey;
            }
            
            static Gigamonkey::timestamp timestamp(script x) {
                return read(x).Timestamp;
            }
            
            static uint32_little nonce(script x) {
                return read(x).Nonce;
            }
            
            static digest160 miner_address(script x) {
                return read(x).MinerAddress;
            }
            
            input_script(
                Bitcoin::signature signature, 
                Bitcoin::pubkey pubkey, 
                uint32_little nonce1,
                work::solution, Boost::type);
        };
        
        // A job is a work::puzzle without ExtraNonce and with a Boost type. 
        // This type always has an address associated with it. 
        struct job {
            type Type;
            int32_little Category;
            uint256 Content;
            work::target Target;
            bytes Tag;
            uint32_little UserNonce;
            bytes AdditionalData;
            digest160 MinerAddress;
            
            bool valid() const { 
                return (Type == Boost::bounty || Type == Boost::contract) && 
                    Target.valid() && MinerAddress.valid();
            }
            
            job() : Type{invalid}, Category{}, Content{}, Target{}, Tag{}, UserNonce{}, AdditionalData{}, MinerAddress{} {}
            
            job(Boost::type type, 
                int32_little category, 
                const uint256& content, 
                work::target target, 
                const bytes& tag, 
                uint32_little user_nonce, 
                const bytes& data, 
                const digest160& miner_address) : 
                Type{type}, Category{category}, Content{content}, Target{target}, Tag{tag}, UserNonce{user_nonce}, 
                AdditionalData{data}, MinerAddress{miner_address} {}
            
            job(const Boost::output_script& x, const digest160& addr) : job{} {
                if (x.Type == invalid) return;
                if (x.Type == contract && x.MinerAddress != addr) return;
                *this = job{x.Type, x.Category, x.Content, x.Target, x.Tag, x.UserNonce, x.AdditionalData, addr};
            }
            
            bool operator==(const job& j) const {
                return Type == j.Type && Category == j.Category && Content == j.Content && 
                    Target == j.Target && Tag == j.Tag && UserNonce == j.UserNonce && 
                    AdditionalData == j.AdditionalData && MinerAddress == j.MinerAddress;
            }
            
            bool operator!=(const job& j) const {
                return !operator==(j);
            }
            
            operator Boost::output_script() const; 
        };
        
        struct proof;
        
        // A puzzle is created after ExtraNonce is assigned by the mining pool. 
        struct puzzle : work::puzzle {
            type Type;
            
            bool valid() const {
                return (Type == Boost::bounty || Type == Boost::contract) && work::puzzle::valid();
            }
            
            puzzle() : work::puzzle{}, Type{invalid} {}
            
            puzzle(Boost::type type, 
                int32_little category, 
                const uint256& content, 
                work::target target, 
                const bytes& tag, 
                uint32_little user_nonce, 
                const bytes& data, 
                const digest160& miner_address, 
                uint32_little extra_nonce) : 
                puzzle(make(type, category, content, target, tag, user_nonce, data, miner_address, extra_nonce)) {}
            
            puzzle(const job& x, uint32_little extra_nonce) : 
                puzzle{x.Type, x.Category, x.Content, x.Target, x.Tag, 
                    x.UserNonce, x.AdditionalData, x.MinerAddress, extra_nonce} {}
            
            bool operator==(const puzzle& j) const {
                return Type == j.Type && work::puzzle::operator==(static_cast<const work::puzzle&>(j));
            }
            
            bool operator!=(const puzzle& j) const {
                return !operator==(j);
            }
            
            Boost::output_script output_script() const; 
            
            digest160 miner_address() const;

        private:
            puzzle(work::puzzle p, type t) : work::puzzle{p}, Type{t} {}
            
            static puzzle make(Boost::type type, 
                int32_little version, 
                const uint256& content, 
                work::target target, 
                const bytes& tag, 
                uint32_little user_nonce, 
                const bytes& data, 
                const digest160& miner_address, 
                uint32_little extra_nonce) {
                if (type == invalid) return {};
                return puzzle{work::puzzle{version, content, target, Merkle::path{}, 
                write(tag.size() + 20, tag, miner_address), extra_nonce, 
                write(data.size() + 4, user_nonce, data)}, type};
            }
            
            friend struct proof;
        };
        
        struct proof : work::proof {
            type Type;
            
            proof() : work::proof{}, Type{invalid} {}
            
            proof(const puzzle& p, const work::solution& x) : 
                work::proof{static_cast<const work::puzzle&>(p), x}, Type{p.Type} {}
            
            proof(Boost::output_script out, Boost::input_script in) : proof{} {
                if (out.Type == invalid || in.Type != out.Type) return;
                *this = proof{Boost::puzzle{job{out, out.Type == bounty ? in.MinerAddress : out.MinerAddress},
                    in.ExtraNonce1}, work::solution{in.Timestamp, in.Nonce, in.ExtraNonce2}};
            }
            
            proof(type t, const work::string& w, const bytes& h, 
                const uint32_little& n1, const uint64_little& n2, const bytes& b) : 
                work::proof{w, {}, h, n1, n2, b}, Type{t} {}
                
            Boost::puzzle puzzle() const {
                return Boost::puzzle{work::proof::Puzzle, Type};
            }
            
            Boost::output_script output_script() const {
                return puzzle().output_script();
            }
            
            Boost::input_script input_script() const;
            
            bool operator==(const proof& j) const {
                return Type == j.Type && work::proof::operator==(static_cast<const work::proof&>(j));
            }
            
            bool operator!=(const proof& j) const {
                return !operator==(j);
            }
        };
        
        struct redeem_boost final : Bitcoin::redeemable {
            Bitcoin::secret Secret;
            Bitcoin::pubkey Pubkey;
            uint32_little ExtraNonce1;
            work::solution Solution;
            type Type;
            Bitcoin::redemption::incomplete redeem(Bitcoin::sighash::directive d) const override {
                Bitcoin::program p = input_script{Bitcoin::signature{}, Pubkey, ExtraNonce1, Solution, Type}.program();
                if (p.empty()) return {};
                return {Bitcoin::redemption::element{&Secret, d}, compile(p.rest())};
            }
        };
        
    }
    
}

std::ostream& operator<<(std::ostream& o, const Gigamonkey::Boost::output_script s);

std::ostream& operator<<(std::ostream& o, const Gigamonkey::Boost::input_script s);

#endif

