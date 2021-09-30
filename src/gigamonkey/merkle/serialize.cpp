#include<gigamonkey/merkle/serialize.hpp>

namespace Gigamonkey::BitcoinAssociation {
    
    digest256 read_digest(const string& x) {
        return digest256{string{"0x"} + x};
    }
    
    string write_digest(const digest256& x) {
        std::stringstream ss;
        ss << x.Value;
        return ss.str().substr(2);
    }
    
    Bitcoin::header read_header(const string& x) {
        ptr<bytes> b = encoding::hex::read(x);
        if (b == nullptr || b->size() != 80) return {};
        return Bitcoin::header{slice<80>{b->data()}};
    }
    
    string write_header(const Bitcoin::header& h) {
        return encoding::hex::write(h.write());
    }
    
    Merkle::digests read_path(const json::array_t& j, Merkle::leaf l) {
        Merkle::digests d;
        for (const json& n : j) {
            digest256 next = (n == "*" ? l.Digest : read_digest(n));
            d = d << next;
            l = l.next(next);
        }
        return data::reverse(d);
    }
    
    list<optional<digest256>> generate_path(Merkle::branch b) {
        list<optional<digest256>> l;
        while (b.Digests.size() > 0) {
            if (b.Leaf.Digest == b.Digests.first()) l = l << optional<digest256>{};
            else l = l << optional<digest256>{b.Digests.first()};
            b = b.rest();
        }
        return l;
    }
    
    json write_path(Merkle::branch b) {
        json::array_t nodes(b.Digests.size());
        for (json& j : nodes) {
            if (b.Leaf.Digest == b.Digests.first()) j = "*";
            else j = write_digest(b.Digests.first());
            b = b.rest();
        }
        return nodes;
    }
    
    bool proofs_serialization_standard::valid() const {
        if ((bool(Transaction) && bool(Txid)) || (!bool(Transaction) && !bool(Txid))) return false; 
        if (bool(BlockHash)) return !bool(BlockHeader) && !bool(MerkleRoot);
        if (bool(BlockHeader)) return !bool(BlockHash) && !bool(MerkleRoot);
        if (bool(MerkleRoot)) return !bool(BlockHeader) && !bool(BlockHash);
        return false;
    }
    
    bool proofs_serialization_standard::valid(const json &j) {
        if (!j.is_object()) return false;
        
        // composite proofs not yet supported. 
        if (j.contains("composite") && (!j["composite"].is_boolean() || j["composite"] == true)) return false; 
        
        // trees not yet supported. 
        if (j.contains("proofType") && (!j["proofType"].is_string() || j["proofType"] != "branch")) return false; 
        
        if (!j.contains("index") || !j["index"].is_number_unsigned()) return false;
        
        if (!j.contains("txOrId") || 
            !j["txOrId"].is_string() || 
            string(j["txOrId"]).size() < 64 || 
            !encoding::hex::valid(string(j["txOrId"]))) return false;
        
        if (j.contains("targetType")) {
            json targetType = j["targetType"];
            if (!targetType.is_string() || (targetType != "hash" && targetType != "header" && targetType != "merkleRoot")) return false;
        } else if (!j.contains("target") || !j["target"].is_string() || !encoding::hex::valid(string(j["target"]))) return false;
        
        if (!j.contains("nodes")) return false;
        
        json nodes = j["nodes"];
        if (nodes.is_array()) {
            for (const json& node : nodes) if (!node.is_string() || 
                (node != "*" && !(encoding::hex::valid(string(node)) && string(node).size() == 64))) return false;
        } else return false;
        
        return true;
    }
    
    proofs_serialization_standard::operator json() const {
        if (!valid()) return nullptr;
        
        json j = json::object_t{};
        
        j["index"] = Path.Index;
        j["nodes"] = write_path(branch());
        
        if (bool(Txid)) {
            j["txOrId"] = write_digest(*Txid);
        } else {
            j["txOrId"] = encoding::hex::write(*Transaction);
        }
        
        if (bool(BlockHash)) {
            j["target"] = write_digest(*BlockHash);
        } else if (bool(BlockHeader)) {
            j["targetType"] = "header";
            j["target"] = encoding::hex::write(BlockHeader->write());
        } else if (bool(MerkleRoot)) {
            j["targetType"] = "merkleRoot";
            j["target"] = write_digest(*MerkleRoot);
        } else {
            return nullptr;
        }
        
        return j;
    }
    
    digest256 inline proofs_serialization_standard::txid(const json& j) {
        if (!valid(j)) return {};
        if (j["txOrId"].size() == 64) {
            return read_digest(j["txOrId"]);
        } else {
            return Bitcoin::transaction::read(*encoding::hex::read(string(j["txOrId"]))).id();
        }
    }
    
    proofs_serialization_standard proofs_serialization_standard::read_json(const json& j) {
        proofs_serialization_standard x;
        if (!proofs_serialization_standard::valid(j)) return {};
        
        if (string(j["txOrId"]).size() == 64) {
            x.Txid = read_digest(j["txOrId"]);
        } else {
            // we know this is ok because we checked valid earlier. 
            x.Transaction = *encoding::hex::read(string(j["txOrId"]));
        }
        
        x.Path.Index = j["index"];
        x.Path.Digests = read_path(j["nodes"], x.leaf());
        
        if (!j.contains("targetType")) {
            x.BlockHash = read_digest(j["target"]);
        } else {
            if (j["targetType"] == "hash") {
                x.BlockHash = read_digest(j["target"]);
            } else if (j["targetType"] == "header") {
                x.BlockHeader = read_header(j["target"]);
            } else if (j["targetType"] == "merkleRoot"){
                x.MerkleRoot = read_digest(j["target"]);
            } else return {};
        }
        
        return x;
    }
    
    bytes_reader read_transaction(bytes_reader r, bytes& b) {
        uint64 size;
        r = Bitcoin::reader::read_var_int(r, size);
        b.resize(size);
        return r >> b;
    }
    
    bytes_reader read_node(bytes_reader r, optional<digest256>& node) {
        byte type;
        r = r >> type;
        if (type == 1) {
            node = {};
        } else if (type == 0) {
            node = {digest256{}};
            r = r >> *node;
        } else throw std::logic_error{"unknown node type"};
        return r;
    }
    
    bytes_reader read_path(bytes_reader r, digest256 leaf, Merkle::path& p) {
        uint64 size;
        r = Bitcoin::reader::read_var_int(r, size);
        Merkle::digests d;
        Merkle::leaf l{leaf, p.Index};
        for (int i = 0; i < size; i++) {
            optional<digest256> Next;
            r = read_node(r, Next);
            digest256& next = bool(Next) ? *Next : l.Digest;
            d = d << next;
            l = l.next(next);
        }
        p.Digests = data::reverse(d);
        return r;
    }
    
    proofs_serialization_standard proofs_serialization_standard::read_binary(bytes_view b) {
        try {
            proofs_serialization_standard x;
            
            byte flags;
            uint64 index;
            bytes_reader r = Bitcoin::reader::read_var_int(bytes_reader{b.data(), b.data() + b.size()} >> flags, index);
            x.Path.Index = index;
            
            if (x.transaction_included(flags)) {
                bytes tx;
                r = read_transaction(r, tx);
            } else {
                Bitcoin::txid t;
                r = r >> t;
                x.Txid = t;
            }
            
            switch (target_type(flags)) {
                case target_type_block_hash: {
                    digest256 block_hash; 
                    r = r >> block_hash;
                    x.BlockHash = block_hash;
                    break;
                }
                case target_type_block_header: {
                    bytes header(80);
                    r = r >> header;
                    x.BlockHeader = Bitcoin::header::read(slice<80>(header.data()));
                    break;
                }
                case target_type_Merkle_root: {
                    digest256 root; 
                    r = r >> root;
                    x.MerkleRoot = root;
                    break;
                }
                case target_type_invalid: {
                    return {};
                }
            }
            
            read_path(r, x.txid(), x.Path);
            return x;
        } catch (...) {}
        return {};
    }
    
    bytes_writer write_duplicate(bytes_writer w) {
        return w << byte(1);
    }
    
    bytes_writer write_node(bytes_writer w, const digest256& d) {
        return w << byte(0) << d;
    }
    
    bytes_writer write_path(bytes_writer w, list<optional<digest256>> b) {
        w = Bitcoin::writer::write_var_int(w, b.size());
        for (const optional<digest256> &z : b) {
            if (bool(z)) w = write_node(w, *z);
            else w = write_duplicate(w);
            b = b.rest();
        }
        return w;
    }
    
    bytes_writer write_txid(bytes_writer w, const Bitcoin::txid& t) {
        return w << t;
    }
    
    bytes_writer write_transaction(bytes_writer w, const bytes& t) {
        return Bitcoin::writer::write_var_int(w, t.size()) << t;
    }
    
    proofs_serialization_standard::operator bytes() const {
        bool tx_included = transaction_included();
        auto tt = target_type();
        
        // we need to pre-generate some data for the path. 
        auto path = generate_path(branch());
        
        // figure out the serialized size. 
        size_t size = 1 + 
            Bitcoin::writer::var_int_size(Path.Index) + 
            Bitcoin::writer::var_int_size(Path.Digests.size()) + 
            (tx_included ? Bitcoin::writer::var_int_size(Transaction->size()) + Transaction->size() : 32);
        for (const optional<digest256>& d : path) size += (bool(d) ? 33 : 1);
        if (tt == target_type_block_hash || tt == target_type_Merkle_root) size += 32;
        else if (tt == target_type_block_header) size += 80;
        
        // allocate space 
        bytes b(size);
        
        // write flags and index. 
        bytes_writer w = Bitcoin::writer::write_var_int(bytes_writer{b.begin(), b.end()} << flags(), index());
        
        if (tx_included) w = write_transaction(w, *Transaction);
        else w = write_txid(w, *Txid);
        
        if (tt == target_type_block_hash) w = write_txid(w, *BlockHash);
        else if (tt == target_type_Merkle_root) w = write_txid(w, *MerkleRoot);
        else if (target_type_block_header) w = w << BlockHeader->write();
        else return {};
        
        w = write_path(w, path);
        return b;
    }
    
    proofs_serialization_standard::target_type_value proofs_serialization_standard::target_type(const json &j) {
        if (!j.contains("targetType")) return target_type_block_hash;
        if (j["targetType"] == "hash") return target_type_block_hash;
        if (j["targetType"] == "header") return target_type_block_header;
        return target_type_Merkle_root;
    }
    
    proofs_serialization_standard::target_type_value proofs_serialization_standard::target_type() const {
        if (bool(BlockHeader)) return target_type_block_header;
        if (bool(BlockHash)) return target_type_block_hash;
        if (bool(MerkleRoot)) return target_type_Merkle_root;
        return target_type_invalid;
    }
    
    proofs_serialization_standard::proofs_serialization_standard(
        const Bitcoin::transaction& t, const Merkle::path& p, const digest256& hash, target_type_value v) {
        if (v == target_type_block_hash) BlockHash = hash;
        else if (v == target_type_Merkle_root) MerkleRoot = hash;
        else return;
        Transaction = t.write();
        Path = p;
    }
    
    optional<digest256> inline proofs_serialization_standard::Merkle_root(const json& j) {
        target_type_value target = target_type(j);
        if (target == target_type_Merkle_root) return {read_digest(j["target"])};
        if (target == target_type_block_header) return block_header(j)->MerkleRoot;
        return {};
    }
    
    optional<Bitcoin::header> inline proofs_serialization_standard::block_header(const json& j) {
        if (j.contains("targetType") && j["targetType"] == "header") return {read_header(j["target"])};
        return {};
    }
    
}
