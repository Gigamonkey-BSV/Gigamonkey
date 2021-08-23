#include <gigamonkey/schema/hd.hpp>
#include <data/crypto/NIST_DRBG.hpp>
#include <data/crypto/secret_share.hpp>
#include <data/encoding/ascii.hpp>

std::ostream inline &operator<<(std::ostream &o, const data::crypto::secret_share &x) {
    return o << Gigamonkey::base58::check(static_cast<data::byte>(x.Index), x.Data).encode();
}

namespace Gigamonkey {
    
    struct exception {
        int ErrorCode;
        string Message;
        
        int code() const {
            return ErrorCode;
        }
        
        string message() const {
            return Message;
        }
        
        template <typename X>
        exception& operator<<(const X& x) {
            std::stringstream ss;
            ss << Message << x;
            Message = ss.str();
            return *this;
        }
        
        exception(int code) : ErrorCode{code}, Message{} {}
    };
    
    string secret_share_split(list<string> args) {
        
        if (args.size() != 3) throw exception(2) << "3 further arguments required for split";
        
        string message = args[0];
        
        std::cout << "arg 1 is " << args[1] << std::endl;
        
        uint64 shares;
        {
            std::stringstream ss(args[1]);
            ss >> shares;
        }
        
        if (shares > 10 || shares == 0) throw exception(4) << "argument 3 (shares) must be less than 10 and greater than zero; " << shares;
        
        uint64 threshold;
        {
            std::stringstream ss(args[2]);
            ss >> threshold;
        }
        
        if (threshold == 0 || threshold > shares) throw exception(6) << "argument 4 (threshold) must be greater than zero and less than shares.";
        
        ptr<crypto::entropy> entropy = std::static_pointer_cast<crypto::entropy>(std::make_shared<crypto::user_entropy>(
            "Please seed random number generator with entropy.", "Entropy accepted", std::cout, std::cin));
        
        crypto::nist::drbg random{crypto::nist::drbg::HMAC_DRBG, entropy, bytes{}, 302};
        
        cross<crypto::secret_share> secret_shares = 
            crypto::secret_share_split(*random.Random, bytes::from_string(message), static_cast<uint32>(shares), static_cast<uint32>(threshold));
        
        list<string> output; 
        for (const crypto::secret_share &x : secret_shares) {
            output = output << base58::check(static_cast<byte>(x.Index), x.Data).encode();
        }
        
        std::stringstream ss;
        ss << output;
        return ss.str();
        
    }
    
    string secret_share_merge(list<string> args) {
        
        ptr<N_bytes_little> threshold_arg = encoding::decimal::read<endian::little>(args.first());
    
        uint64 threshold;
        {
            std::stringstream ss(args[0]);
            ss >> threshold;
        }
        
        if (threshold == 0 || threshold > args.size() - 1) 
            throw exception(7) << "threshold must be greater than zero and the number of additional arguments provided must be at least the threshold.";
        
        cross<crypto::secret_share> shares(args.size() - 1);
        
        int i = 0;
        for (const string& x : args.rest()) {
            base58::check share = base58::check::recover(x);
            if (!share.valid()) throw exception(8) << "could not recover share " << i;
            shares[i] = crypto::secret_share{share.version(), share.payload()};
            i ++;
        }
        
        bytes merged = crypto::secret_share_merge(shares, static_cast<byte>(threshold));
        
        string merged_string = encoding::ascii::write(merged);
        if (!encoding::ascii::valid(merged_string)) 
            throw exception(8) << "invalid string recovered; here it is in hex: " << encoding::hex::write(merged);
        
        return merged_string;
        
    }
    
    string help() {
        return 
            "\thelp                                                  Show his message.\n"
            "\tversion                                               Show version.\n"
            "\tsplit <data:string> <shares:uint> <threshold:uint>    Split data into shares.\n"
            "\tmerge <threshold:uint> <shares:string...>             Merge shares into data.";
    }
    
    string version() {
        return "1.0";
    }
    
    string secret_share(list<string> args) {
        
        if (args.empty() || args.first() == string{"help"}) return help();
        
        if (args.first() == string{"version"}) return version();
        
        if (args.first() == string{"split"}) return secret_share_split(args.rest());
        
        if (args.first() == string{"merge"}) return secret_share_merge(args.rest());
        
        return help();
        
    }
    
}

int main(int num_args, char** arg) {
    
    using namespace Gigamonkey;
    
    list<string> args;
    for (int i = 1; i < num_args; i++) {
        args = args << string{arg[i]};
    }
    
    try {
        
        std::cout << secret_share(args) << std::endl;
        
    } catch (const exception& ex) {
        
        std::cout << "Error: " << ex.message() << std::endl;
        
        return ex.code();
    }
    
    return 0;
    
}
