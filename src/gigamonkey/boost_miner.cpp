#include <gigamonkey/boost/boost.hpp>

using namespace Gigamonkey;

// Content is what is to be boosted. Could be a hash or
// could be text that's 32 bytes or less. There is a
// BIG PROBLEM with the fact that hashes in Bitcoin are 
// often displayed reversed. This is a convention that
// got started long ago because people were stupid. 

// For average users of boost, we need to ensure that 
// the hash they are trying to boost actually exists. We 
// should not let them paste in hashes to boost; we should
// make them select content to be boosted. 

// In my library, we read the string backwards by putting
// an 0x at the front. 
string content_hash_hex_reversed = "0xdbe0f0cdeb0e399dde37764cdc84415d51c95a01c42a0037a3c639c7ae4fe0b3";

// a difficulty of 1/1000 should be easy to do on a cpu quickly. 
// Difficulty 1 is the difficulty of the genesis block. 
work::difficulty difficulty{0.001};

// This is the key that you will use to redeem boost. 
// This should not be the same key that you use to store
// the money that you earn. 
string miner_secret_key_WIF = "";

// Category has no particular meaning. We could use it for
// something like magic number if we wanted to imitate 21e8. 
int32_little category = 0;

// Tag/topic does not need to be anything. 
bytes topic{};

// additional data does not need to be anything but it 
// can be used to provide information about a boost or
// to add a comment. 
bytes additional_data{};

// If you use a bounty script, other people can 
// compete with you to mine a boost output if you 
// broadcast it before you broadcast the solution. 

// If you use a contract script, then you are the only
// one who can mine that boost output. 
Boost::type boost_type = Boost::bounty;

// This has to do with whether we use boost v2 which
// incorporates bip320 which is necessary for ASICBoost. 
// This is not necessary for CPU mining. 
bool use_general_purpose_bits = false;

// A cpu miner function. 
work::proof cpu_solve(const work::puzzle& p, const work::solution& initial) {
    using uint256 = Gigamonkey::uint256;
    
    uint256 target = p.Candidate.Target.expand();
    if (target == 0) return {};
    std::cout << " working " << p << std::endl;
    std::cout << " with target " << target << std::endl;
    
    uint256 best{"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    
    N total_hashes{0};
    N nonce_increment{"0x0100000000"};
    uint32 display_increment = 0x00800000;
    
    work::proof pr{p, initial};
    
    while(true) {
        uint256 hash = pr.string().hash();
        total_hashes++;
        
        if (hash < best) {
            best = hash;
            std::cout << " hashes: " << total_hashes << std::endl;
            std::cout << " new best hash: " << best << std::endl;
        } else if (pr.Solution.Share.Nonce % display_increment == 0) {
            pr.Solution.Share.Timestamp = Bitcoin::timestamp::now();
            std::cout << " hashes: " << total_hashes << std::endl;
        }
        
        if (hash < target) {
            std::cout << " solution found! " << std::endl;
            return pr;
        }
        
        pr.Solution.Share.Nonce++;
        
        if (pr.Solution.Share.Nonce == 0) {
            pr.Solution.Share.ExtraNonce2++;
        }
    }
    
    return pr;
}

// Some stuff having to do with random number generators. We do not need 
// strong cryptographic random numbers for boost. It is fine to use 
// basic random number generators that you would use in a game or something. 
template <typename engine>
double random_range01(engine& gen) {
    static std::uniform_real_distribution<double> dis(0.0, 1.0);
    return dis(gen);
}

template <typename engine>
data::uint64 random_uint64(engine& gen) {
    static std::uniform_int_distribution<data::uint64> dis(
        std::numeric_limits<data::uint64>::min(),
        std::numeric_limits<data::uint64>::max()
    );
    return dis(gen);
}

template <typename engine>
data::uint32 random_uint32(engine& gen) {
    static std::uniform_int_distribution<data::uint32> dis(
        std::numeric_limits<data::uint32>::min(),
        std::numeric_limits<data::uint32>::max()
    );
    return dis(gen);
}

int main(int arg_count, char** arg_values) {
    
    digest256 content{content_hash_hex_reversed};
    std::cout << "Content to be boosted: " << content << std::endl;
    
    work::compact target{difficulty};
    std::cout << "target: " << target << std::endl;
    
    Bitcoin::secret private_key{miner_secret_key_WIF};
    Bitcoin::pubkey public_key = private_key.to_public();
    Bitcoin::address miner_address = private_key.address();
    
    auto generator = data::get_random_engine();
    
    uint32_little user_nonce{random_uint32(generator)};
    Stratum::session_id extra_nonce_1{random_uint32(generator)};
    uint64_big extra_nonce_2{random_uint64(generator)};
    
    Boost::output_script output_script = boost_type == Boost::bounty ? 
        Boost::output_script::bounty(
            category, 
            content, 
            target, 
            topic, 
            user_nonce, 
            additional_data, 
            use_general_purpose_bits) : 
        Boost::output_script::contract(
            category, 
            content, 
            target, 
            topic, 
            user_nonce, 
            additional_data, 
            miner_address.Digest, 
            use_general_purpose_bits);
    
    std::cout << "The output script is " << output_script.write() << std::endl;
    
    std::cout << "Or in ASM: " << Bitcoin::interpreter::ASM(output_script.write()) << std::endl;
    
    std::cout << "now let's start mining." << std::endl;
    
    Boost::puzzle boost_puzzle{output_script, private_key};
    
    work::solution initial{Bitcoin::timestamp::now(), 0, extra_nonce_2, extra_nonce_1};
    
    if (use_general_purpose_bits) initial.Share.Bits = random_uint32(generator);
    
    work::proof proof = ::cpu_solve(work::puzzle(boost_puzzle), initial);
    
    // dummy signature
    Bitcoin::signature signature;
    
    Boost::input_script input_script = Boost::input_script(
            signature, public_key, proof.Solution, boost_type, use_general_purpose_bits);
    
    std::cout << "Here is the redeem script " << input_script.write() << std::endl;
    
    std::cout << "Or in ASM: " << Bitcoin::interpreter::ASM(input_script.write()) << std::endl;
    
    std::cout << "WARNING: this script uses a dummy signature. The first push needs to be replaced by a real signature. "
        << "Since we do not have a complete transaction, we cannot have a complete signature." << std::endl;
}

