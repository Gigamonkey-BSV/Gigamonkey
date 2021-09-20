#include <gigamonkey/boost/boost.hpp>

using namespace Gigamonkey;

// A cpu miner function. 
work::proof cpu_solve(const work::puzzle& p, const work::solution& initial) {
    using uint256 = Gigamonkey::uint256;
    
    if (initial.Share.ExtraNonce2.size() != 4) throw "Extra nonce 2 must have size 4. We will remove this limitation eventually.";
    
    uint64_big extra_nonce_2; 
    std::copy(initial.Share.ExtraNonce2.begin(), initial.Share.ExtraNonce2.end(), extra_nonce_2.begin());
    
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
            extra_nonce_2++;
            std::copy(extra_nonce_2.begin(), extra_nonce_2.end(), pr.Solution.Share.ExtraNonce2.begin());
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

int spend(int arg_count, char** arg_values) {
    if (arg_count < 4 || arg_count > 5) throw "invalid number of arguments; should be 4 or 5";
    
    string content_hash_hex{arg_values[0]};
    
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
    digest256 content{content_hash_hex};
    if (!content.valid()) throw (string{"could not read content: "} + content_hash_hex);
    
    std::cout << "content to be boosted: " << content << std::endl;
    
    double diff = 0;
    string difficulty_input{arg_values[1]};
    std::stringstream diff_stream{difficulty_input};
    diff_stream >> diff;
    
    // difficulty is a unit that is inversely proportional to 
    // target. One difficulty is proportional to 2^32
    // expected hash operations. 
    
    // a difficulty of 1/1000 should be easy to do on a cpu quickly. 
    // Difficulty 1 is the difficulty of the genesis block. 
    work::compact target{work::difficulty{diff}};
    if (!target.valid()) throw (string{"could not read difficulty: "} + difficulty_input);
    
    std::cout << "target: " << target << std::endl;
    
    // Tag/topic does not need to be anything. 
    ptr<bytes> topic = encoding::hex::read(string{arg_values[2]});
    if (topic == nullptr || topic->size() > 20) throw (string{"could not read topic: "} + string{arg_values[2]});
    
    // additional data does not need to be anything but it 
    // can be used to provide information about a boost or
    // to add a comment. 
    ptr<bytes> additional_data = encoding::hex::read(string{arg_values[3]});
    if (additional_data == nullptr) throw (string{"could not read additional_data: "} + string{arg_values[3]});
    
    // Category has no particular meaning. We could use it for
    // something like magic number if we wanted to imitate 21e8. 
    int32_little category = 0;
    
    // User nonce is for ensuring that no two scripts are identical. 
    // You can increase the bounty for a boost by making an identical script. 
    uint32_little user_nonce{random_uint32(get_random_engine())};
    
    // we are using version 1 for now. 
    // we will use version 2 when we know we have Stratum extensions right. 

    // This has to do with whether we use boost v2 which
    // incorporates bip320 which is necessary for ASICBoost. 
    // This is not necessary for CPU mining. 
    bool use_general_purpose_bits = false;
    
    Boost::output_script output_script;

    // If you use a bounty script, other people can 
    // compete with you to mine a boost output if you 
    // broadcast it before you broadcast the solution. 

    // If you use a contract script, then you are the only
    // one who can mine that boost output. 
    if (arg_count == 4) {
        output_script = Boost::output_script::bounty(
            category, 
            content, 
            target, 
            *topic, 
            user_nonce, 
            *additional_data, 
            use_general_purpose_bits);
    } else {
        Bitcoin::address miner_address{arg_values[4]};
        if (!miner_address.valid()) throw (string{"could not read miner address: "} + string{arg_values[4]});
        
        output_script = Boost::output_script::contract(
            category, 
            content, 
            target, 
            *topic, 
            user_nonce, 
            *additional_data, 
            miner_address.Digest, 
            use_general_purpose_bits);
    }
    
    std::cout << "The output script is " << Bitcoin::interpreter::ASM(output_script.write()) << std::endl;
    
    return 0;
}

Bitcoin::transaction mine(
    // an unredeemed Boost PoW output 
    Bitcoin::ledger::prevout prevout, 
    // The private key that you will use to redeem the boost output. This key 
    // corresponds to 'miner address' in the Boost PoW protocol. 
    Bitcoin::secret private_key, 
    // the address you want the bitcoins to go to once you have redeemed the boost output.
    // this is not the same as 'miner address'. This is just an address in your 
    // normal wallet and should not be the address that goes along with the key above.
    Bitcoin::address address) {
    using namespace Bitcoin;
    
    // Is this a boost output? 
    Boost::output_script output_script{prevout.value().Script}; 
    if (!output_script.valid()) throw "Not a valid Boost output script";
    
    // If this is a contract script, we need to check that the key we have been given corresponds 
    // to the miner address in the script. 
    if (output_script.Type == Boost::contract && output_script.MinerAddress != private_key.address().Digest)
        throw "Incorrect key provided to mine this output.";
        
    // is the difficulty too high?
    if (output_script.Target.difficulty() > 1.01) throw "Difficulty is too high for CPU mining.";
    
    // is the value in the output high enough? 
    satoshi value;
    
    std::cout << "now let's start mining." << std::endl;
    
    Boost::puzzle boost_puzzle{output_script, private_key};
    
    auto generator = data::get_random_engine();
    
    Stratum::session_id extra_nonce_1{random_uint32(generator)};
    uint64_big extra_nonce_2{random_uint64(generator)};
    
    work::solution initial{timestamp::now(), 0, bytes_view(extra_nonce_2), extra_nonce_1};
    
    if (output_script.UseGeneralPurposeBits) initial.Share.Bits = random_uint32(generator);
    
    work::proof proof = ::cpu_solve(work::puzzle(boost_puzzle), initial);
    
    // the incomplete transaction 
    incomplete::transaction incomplete{ 
        {incomplete::input{prevout.key()}},                       // one incomplete input 
        {output{value, pay_to_address::script(address.Digest)}}}; // one output 
    
    // signature
    signature signature = private_key.sign( 
        signature::document{
            prevout.value(),         // output being redeemed
            incomplete,              // the incomplete tx
            0});                     // index of input that will contain this signature
    
    Boost::input_script input_script = Boost::input_script(
            signature, private_key.to_public(), proof.Solution, output_script.Type, output_script.UseGeneralPurposeBits);
    
    std::cout << "Here is the redeem script: " << interpreter::ASM(input_script.write()) << std::endl;
    
    // the transaction 
    return incomplete.complete({input_script.write()});
    
}

int redeem(int arg_count, char** arg_values) {
    if (arg_count != 6) throw "invalid number of arguments; should be 6";
    
    string arg_script{arg_values[0]};
    string arg_value{arg_values[1]};
    string arg_txid{arg_values[2]};
    string arg_index{arg_values[3]};
    string arg_wif{arg_values[4]};
    string arg_address{arg_values[5]};
    
    ptr<bytes> script = encoding::hex::read(arg_script);
    if (script == nullptr) throw "could not read script"; 
    
    int64 value;
    std::stringstream{arg_value} >> value;
    
    Bitcoin::txid txid{arg_txid};
    if (!txid.valid()) throw "could not read txid";
    
    uint32 index;
    std::stringstream{arg_index} >> index;
    
    Bitcoin::address address{arg_address};
    if (!address.valid()) throw "could not read address";
    
    Bitcoin::secret key{arg_wif};
    if (!key.valid()) throw "could not read secret key";
    
    Bitcoin::transaction tx = mine(
        Bitcoin::ledger::prevout{
            Bitcoin::outpoint{txid, index}, 
            Bitcoin::output{Bitcoin::satoshi{value}, *script}}, 
        key, address);
    
    std::cout << "Here is the final transaction: " << tx << std::endl;
    
    return 0;
}

int help() {
    std::cout << "input should be \"function\" \"args\"... where function is "
        "\n\tspend      -- create a Boost output."
        "\n\tredeem     -- mine and redeem an existing boost output."
        "\nFor function \"spend\", remaining inputs should be "
        "\n\tcontent    -- hex for correct order, hexidecimal for reversed."
        "\n\tdifficulty -- "
        "\n\ttopic      -- string max 20 bytes."
        "\n\tadd. data  -- string, any size."
        "\n\taddress    -- OPTIONAL. If provided, a boost contract output will be created. Otherwise it will be boost bounty."
        "\nFor function \"redeem\", remaining inputs should be "
        "\n\tscript     -- boost output script."
        "\n\tvalue      -- value in satoshis of the output."
        "\n\ttxid       -- txid of the tx that contains this output."
        "\n\tindex      -- index of the output within that tx."
        "\n\twif        -- private key that will be used to redeem this output."
        "\n\taddress    -- your address where you will put the redeemed sats." << std::endl;
    
    return 0;
}

int main(int arg_count, char** arg_values) {
    if (arg_count != 5) return help();
    
    string function{arg_values[1]};
    
    try {
        if (function == "spend") return spend(arg_count - 2, arg_values + 2);
        if (function == "redeem") return redeem(arg_count - 2, arg_values + 2);
        if (function == "help") return help();
        help();
    } catch (string x) {
        std::cout << "Error: " << x << std::endl;
    }
    
    return 1;
}

