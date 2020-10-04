// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/work/proof.hpp>
#include <gigamonkey/script.hpp>

namespace Gigamonkey {
    bool header_valid_work(slice<80> h) {
        return work::string::valid(h);
    }
    
    bool header_valid(const Bitcoin::header& h) {
        return h.Version >= 1 && h.MerkleRoot.valid() && h.Timestamp != Bitcoin::timestamp{};
    }
}

namespace Gigamonkey::Bitcoin {
    int32_little header::version(const slice<80> x) {
        int32_little version;
        slice<4> v = x.range<0, 4>();
        std::copy(v.begin(), v.end(), version.data());
        return version;
    }
    
    Bitcoin::timestamp header::timestamp(const slice<80> x) {
        Bitcoin::timestamp time;
        slice<4> v = x.range<68, 72>();
        std::copy(v.begin(), v.end(), time.data());
        return time;
    }
    
    work::compact header::target(const slice<80> x) {
        work::compact work;
        slice<4> v = x.range<72, 76>();
        std::copy(v.begin(), v.end(), work.data());
        return work;
    }
    
    uint32_little header::nonce(const slice<80> x) {
        uint32_little n;
        slice<4> v = x.range<76, 80>();
        std::copy(v.begin(), v.end(), n.data());
        return n;
    }
    
    bool header::valid(const slice<80> h) {
        return header_valid(Bitcoin::header::read(h)) && header_valid_work(h);
    }
    
    Gigamonkey::uint256 satoshi_uint256_to_uint256(::uint256 x) {
        Gigamonkey::uint256 y;
        std::copy(x.begin(), x.end(), y.begin());
        return y;
    }
    
    header::header(const CBlockHeader& b) : 
        Version{int32_little{b.nVersion}}, 
        Previous{satoshi_uint256_to_uint256(b.hashPrevBlock)}, 
        MerkleRoot{satoshi_uint256_to_uint256(b.hashMerkleRoot)}, 
        Timestamp{uint32_little{b.nTime}}, 
        Target{uint32_little{b.nBits}}, 
        Nonce{b.nNonce} {};
        
    header::operator CBlockHeader() const {
        CBlockHeader h;
        h.nVersion = Version;
        h.nTime = Timestamp.Value;
        h.nBits = Target;
        h.nNonce = Nonce;
        std::copy(Previous.Value.begin(), Previous.Value.end(), h.hashPrevBlock.begin());
        std::copy(MerkleRoot.Value.begin(), MerkleRoot.Value.end(), h.hashMerkleRoot.begin());
        return h;
    }
    
    bytes_writer write_var_int(bytes_writer, uint64) {
        throw data::method::unimplemented{"write_var_int"};
    }
    
    bytes_reader read_var_int(bytes_reader, uint64&) {
        throw data::method::unimplemented{"read_var_int"};
    }
    
    size_t var_int_size(uint64) {
        throw data::method::unimplemented{"var_int_size"};
    }
        
    bool header::valid() const {
        return header_valid_work(write()) && header_valid(*this);
    }
    
    bool input::valid() const {
        return decompile(Script) != program{};
    }
    
    bool output::valid() const {
        return Value < 2100000000000000 && decompile(Script) != program{};
    }
    
    size_t transaction::serialized_size() const {
        return 8 + var_int_size(Inputs.size()) + var_int_size(Inputs.size()) + 
            data::fold([](size_t size, const Bitcoin::input& i)->size_t{
                return size + i.serialized_size();
            }, 0, Inputs) + 
            data::fold([](size_t size, const Bitcoin::output& i)->size_t{
                return size + i.serialized_size();
            }, 0, Outputs);
    }
    
    size_t block::serialized_size() const {
        return 80 + var_int_size(Transactions.size()) + 
        data::fold([](size_t size, transaction x)->size_t{
            return size + x.serialized_size();
        }, 0, Transactions);
    }
    
}

