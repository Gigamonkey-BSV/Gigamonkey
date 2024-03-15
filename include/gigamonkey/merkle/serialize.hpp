// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_MERKLE_SERIALIZE
#define GIGAMONKEY_MERKLE_SERIALIZE

#include <gigamonkey/merkle/proof.hpp>
#include <gigamonkey/timechain.hpp>

namespace Gigamonkey::BitcoinAssociation {
    
    struct proofs_serialization_standard {

        // this file follows 
        //
        // https://tsc.bitcoinassociation.net/standards/merkle-proof-standardised-format/
        //
        // as this document explains, it describes an incomplete standardization. 
        // The full merkle proof serializaton format will eventually be able to
        // handle more than one proof from a single block. This is desirable because 
        // there would be duplicated information if such proofs were sent individually. 
        // however, this would be an optimization, not something absolutely necessary
        // right now. 
        // 
        // Thus, only the single proof format has been specified so far. The public 
        // interface for this type has been designed to allow for multiple proofs
        // as the new specification comes out. 
        
        // this only checks if the format is valid, but the information in the
        // serialized format isn't always enoughdoes not check the Merkle proof, 
        // so we don't try to check the proof itself. 
        bool valid () const;
        static bool valid (const JSON &);
        static bool valid (bytes_view);
        
        // the proof format has both a binary and a JSON representation. 
        static proofs_serialization_standard read_JSON (const JSON &);
        static proofs_serialization_standard read_binary (bytes_view);
        
        explicit operator JSON () const;
        explicit operator bytes () const;
        
        // whether the full transaction is included or just the txid. 
        static bool transaction_included (bytes_view);
        static bool transaction_included (const JSON &);
        bool transaction_included () const;
        
        // the target refers to the final element of the proof. 
        enum target_type_value {
            target_type_block_hash = 0, 
            target_type_block_header = 2, 
            target_type_Merkle_root = 4, 
            target_type_invalid = 6
        };
        
        static target_type_value target_type (bytes_view);
        static target_type_value target_type (const JSON &);
        target_type_value target_type () const;
        
        // only proof_type_branch is supported for now. 
        enum proof_type_value {
            proof_type_branch = 0, 
            proof_type_tree = 8
        };
        
        static proof_type_value proof_type (bytes_view);
        static proof_type_value proof_type (const JSON &);
        proof_type_value proof_type () const;
        
        // composite proofs are not yet supported, so these should always return false. 
        static bool composite_proof (bytes_view);
        static bool composite_proof (const JSON &);
        bool composite_proof () const;
        
        // transaction not included, target omitted. 
        proofs_serialization_standard (const Merkle::branch &);
        // transaction not included, target Merkle root. 
        proofs_serialization_standard (const Merkle::proof &);
        // transaction not included, target header. 
        proofs_serialization_standard (const Merkle::branch &, const Bitcoin::header &);
        // transaction not included, target block hash. 
        proofs_serialization_standard (const Merkle::branch &, const digest256 &block_hash);
        // transaction not included, target omitted. 
        proofs_serialization_standard (const Bitcoin::transaction &, const Merkle::path &);
        // transaction not included, target header. 
        proofs_serialization_standard (const Bitcoin::transaction &, const Merkle::path &, const Bitcoin::header &);
        // transaction not included, target merkle root or block header depending on the value of the target type. 
        proofs_serialization_standard (const Bitcoin::transaction &, const Merkle::path &, const digest256 &hash, target_type_value);
        
        // all paths that might be included in this message. 
        // since we are only doing single paths for now, there 
        // will only be one entry in this map. 
        map<digest256, Merkle::path> paths () const;
        static map<digest256, Merkle::path> paths (bytes_view);
        static map<digest256, Merkle::path> paths (const JSON &);
        
        // various kinds of targets that might be included.  
        maybe<digest256> block_hash () const;
        maybe<digest256> Merkle_root () const;
        maybe<Bitcoin::header> block_header () const;
        
        static maybe<digest256> block_hash (const JSON &);
        static maybe<digest256> Merkle_root (const JSON &);
        static maybe<Bitcoin::header> block_header (const JSON &);
        
        static maybe<digest256> block_hash (bytes_view);
        static maybe<digest256> Merkle_root (bytes_view);
        static maybe<Bitcoin::header> block_header (bytes_view);
        
        // We can always calculate a root from the given information
        // but not necessarily check the whole proof. 
        digest256 root() const;
        
    private:
        // Everything below this point is subject to change as 
        // more about the composite format is specified. 
        proofs_serialization_standard () {}
        
        // the first byte in the binary representation is the flags. 
        // the JSON representation omits flags as it can be derived from
        // the rest of the structure. 
        byte flags () const;
        static byte flags (const JSON &);
        static byte flags (bytes_view);
        
        static bool transaction_included (byte flags);
        static target_type_value target_type (byte flags);
        static proof_type_value proof_type (byte flags);
        static bool composite_proof (byte flags);
        
        uint32 index () const;
        static uint32 index (bytes_view);
        static uint32 index (const JSON &);
        
        digest256 txid () const;
        static digest256 txid (bytes_view);
        static digest256 txid (const JSON &);
        
        Merkle::leaf leaf () const;
        static Merkle::leaf leaf (bytes_view);
        static Merkle::leaf leaf (const JSON &);
        
        Merkle::path path () const;
        static Merkle::path path (bytes_view);
        static Merkle::path path (const JSON &);
        
        Merkle::branch branch () const;
        static Merkle::branch branch (bytes_view);
        static Merkle::branch branch (const JSON &);
        
        // one of these must be included. 
        maybe<bytes> Transaction;
        maybe<Bitcoin::txid> Txid;
        
        // there is always at least one path. 
        Merkle::path Path;
        
        // one of these must be included. 
        maybe<digest256> BlockHash;
        maybe<digest256> MerkleRoot;
        maybe<Bitcoin::header> BlockHeader;
        
    };
    
    digest256 read_digest (const string &);
    string write_digest (const digest256 &);
    
    bool inline proofs_serialization_standard::valid (bytes_view b) {
        return read_binary (b).valid ();
    }
    
    byte inline proofs_serialization_standard::flags (bytes_view b) {
        if (b.size () == 0) return 0;
        return b[0];
    }
    
    byte inline proofs_serialization_standard::flags () const {
        return (composite_proof () << 4) + proof_type () + target_type () + transaction_included ();
    }
    
    byte inline proofs_serialization_standard::flags (const JSON &j) {
        return (composite_proof (j) << 4) + proof_type (j) + target_type (j) + transaction_included (j);
    }
    
    bool inline proofs_serialization_standard::transaction_included (byte flags) {
        return flags & 1;
    }
    
    bool inline proofs_serialization_standard::transaction_included (bytes_view b) {
        return transaction_included (flags (b));
    }
    
    bool inline proofs_serialization_standard::transaction_included (const JSON &j) {
        return j["txOrId"].size () > 64;
    }
    
    bool inline proofs_serialization_standard::transaction_included () const {
        return bool (Transaction);
    }
        
    proofs_serialization_standard::target_type_value inline proofs_serialization_standard::target_type (byte flags) {
        return target_type_value (flags & target_type_invalid);
    }
    
    proofs_serialization_standard::target_type_value inline proofs_serialization_standard::target_type (bytes_view b) {
        return target_type (flags (b));
    }
        
    proofs_serialization_standard::proof_type_value inline proofs_serialization_standard::proof_type (byte flags) {
        return proof_type_value (flags & proof_type_tree);
    }
    
    proofs_serialization_standard::proof_type_value inline proofs_serialization_standard::proof_type (bytes_view b) {
        return proof_type (flags (b));
    }
    
    proofs_serialization_standard::proof_type_value inline proofs_serialization_standard::proof_type (const JSON &j) {
        if (!j.contains ("proofType") || j["proofType"] == "branch") return proof_type_branch;
        return proof_type_tree;
    }
    
    proofs_serialization_standard::proof_type_value inline proofs_serialization_standard::proof_type () const {
        return proof_type_branch;
    }
        
    bool inline proofs_serialization_standard::composite_proof (byte flags) {
        return 0 != (flags & 16);
    }
    
    bool inline proofs_serialization_standard::composite_proof (bytes_view b) {
        return composite_proof (flags (b));
    }
    
    bool inline proofs_serialization_standard::composite_proof (const JSON &j) {
        if (!j.contains ("composite") || j["composite"] == false) return false;
        return true;
    }
    
    bool inline proofs_serialization_standard::composite_proof () const {
        return false;
    }
    
    digest256 inline proofs_serialization_standard::root () const {
        return branch ().root ();
    }
    
    inline proofs_serialization_standard::proofs_serialization_standard (const Merkle::branch &b)
        : Txid {b.Leaf.Digest}, Path {Merkle::path (b)} {}
    
    inline proofs_serialization_standard::proofs_serialization_standard (const Merkle::proof& p)
        : Txid {p.Branch.Leaf.Digest}, Path {Merkle::path (p.Branch)}, MerkleRoot {p.Root} {}
    
    inline proofs_serialization_standard::proofs_serialization_standard (const Merkle::branch &b, const Bitcoin::header& h)
        : Txid {b.Leaf.Digest}, Path {Merkle::path (b)}, BlockHeader {h} {}
    
    inline proofs_serialization_standard::proofs_serialization_standard (const Merkle::branch &b, const digest256 &block_hash)
        : Txid{b.Leaf.Digest}, Path {Merkle::path (b)}, BlockHash {block_hash} {}
    
    inline proofs_serialization_standard::proofs_serialization_standard (const Bitcoin::transaction &t, const Merkle::path &p)
        : Transaction{bytes(t)}, Path{p} {}
    
    inline proofs_serialization_standard::proofs_serialization_standard (
        const Bitcoin::transaction &t, const Merkle::path &p, const Bitcoin::header &h)
        : Transaction {bytes (t)}, Path {p}, BlockHeader {h} {}
    
    maybe<digest256> inline proofs_serialization_standard::block_hash () const {
        return BlockHash;
    }
    
    maybe<Bitcoin::header> inline proofs_serialization_standard::block_header () const {
        return BlockHeader;
    }
    
    maybe<digest256> inline proofs_serialization_standard::Merkle_root () const {
        if (bool (MerkleRoot)) return MerkleRoot;
        if (bool (BlockHeader)) return BlockHeader->MerkleRoot;
        return {};
    }
    
    maybe<digest256> inline proofs_serialization_standard::block_hash (const JSON &j) {
        if (j.contains ("targetType") && j["targetType"] == "hash") return {digest256 {string {"0x"} + string (j["target"])}};
        return {};
    }
        
    maybe<digest256> inline proofs_serialization_standard::block_hash (bytes_view b) {
        auto x = read_binary (b);
        if (x.valid ()) return x.block_hash ();
        return {};
    }
    
    maybe<Bitcoin::header> inline proofs_serialization_standard::block_header (bytes_view b) {
        auto x = read_binary (b);
        if (x.valid ()) return x.block_header ();
        return {};
    }
    
    maybe<digest256> inline proofs_serialization_standard::Merkle_root (bytes_view b) {
        auto x = read_binary (b);
        if (x.valid ()) return x.Merkle_root ();
        return {};
    }
    
    uint32 inline proofs_serialization_standard::index () const {
        return Path.Index;
    }
    
    uint32 inline proofs_serialization_standard::index (const JSON &j) {
        if (!valid (j)) return 0;
        return j["index"];
    }
        
    digest256 inline proofs_serialization_standard::txid () const {
        if (bool (Txid)) return *Txid;
        return Bitcoin::Hash256 (*Transaction);
    }
    
    digest256 inline proofs_serialization_standard::txid (bytes_view b) {
        auto x = read_binary (b);
        if (x.valid ()) return x.txid ();
        return {};
    }
        
    Merkle::leaf inline proofs_serialization_standard::leaf () const {
        return {txid (), Path.Index};
    }
    
    Merkle::leaf inline proofs_serialization_standard::leaf (bytes_view b) {
        auto x = read_binary (b);
        if (x.valid ()) return x.leaf ();
        return {};
    }
    
    Merkle::leaf inline proofs_serialization_standard::leaf (const JSON &j) {
        return {txid (j), index (j)};
    }
        
    Merkle::path inline proofs_serialization_standard::path() const {
        return Path;
    }
    
    Merkle::path inline proofs_serialization_standard::path (bytes_view b) {
        auto x = read_binary (b);
        if (x.valid ()) return x.path ();
        return {};
    }
    
    Merkle::path inline proofs_serialization_standard::path (const JSON &j) {
        auto x = read_JSON (j);
        if (x.valid ()) return x.path ();
        return {};
    }
    
    Merkle::branch inline proofs_serialization_standard::branch () const {
        return {txid (), Path};
    }
    
    Merkle::branch inline proofs_serialization_standard::branch (bytes_view b) {
        auto x = read_binary (b);
        if (x.valid ()) return x.branch ();
        return {};
    }
    
    Merkle::branch inline proofs_serialization_standard::branch (const JSON &j) {
        auto x = read_JSON (j);
        if (x.valid ()) return x.branch ();
        return {};
    }
    
    map<digest256, Merkle::path> inline proofs_serialization_standard::paths () const {
        return {{txid (), path ()}};
    }
    
    map<digest256, Merkle::path> inline proofs_serialization_standard::paths (bytes_view b) {
        auto x = read_binary (b);
        if (x.valid ()) return x.paths ();
        return {};
    }
    
    map<digest256, Merkle::path> inline proofs_serialization_standard::paths (const JSON &j) {
        auto x = read_JSON (j);
        if (x.valid ()) return x.paths ();
        return {};
    }
    
}

#endif

