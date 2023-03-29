#include<gigamonkey/merkle/serialize.hpp>

namespace Gigamonkey::BitcoinAssociation {
    
    digest256 read_digest (const string &x) {
        return digest256 {string {"0x"} + x};
    }
    
    string write_digest (const digest256 &x) {
        std::stringstream ss;
        ss << x.Value;
        return ss.str ().substr (2);
    }
    
    Bitcoin::header read_header (const string &x) {
        maybe<bytes> b = encoding::hex::read (x);
        if (!bool (b) || b->size () != 80) return {};
        return Bitcoin::header {slice<80> {b->data ()}};
    }
    
    string write_header (const Bitcoin::header &h) {
        return encoding::hex::write (h.write ());
    }
    
    Merkle::digests read_path (const JSON::array_t &j, Merkle::leaf l) {
        Merkle::digests d;

        for (const JSON &n : j) {
            digest256 next = (n == "*" ? l.Digest : read_digest (n));
            d = d << next;
            l = l.next (next);
        }

        return data::reverse (d);
    }
    
    list<maybe<digest256>> generate_path (Merkle::branch b) {
        list<maybe<digest256>> l;

        while (b.Digests.size () > 0) {
            if (b.Leaf.Digest == b.Digests.first ()) l = l << maybe<digest256> {};
            else l = l << maybe<digest256> {b.Digests.first ()};
            b = b.rest ();
        }

        return l;
    }
    
    JSON write_path (Merkle::branch b) {
        JSON::array_t nodes (b.Digests.size ());

        for (JSON& j : nodes) {
            if (b.Leaf.Digest == b.Digests.first ()) j = "*";
            else j = write_digest (b.Digests.first ());
            b = b.rest();
        }

        return nodes;
    }
    
    bool proofs_serialization_standard::valid () const {
        if ((bool (Transaction) && bool (Txid)) || (!bool (Transaction) && !bool (Txid))) return false;
        if (bool (BlockHash)) return !bool (BlockHeader) && !bool (MerkleRoot);
        if (bool (BlockHeader)) return !bool (BlockHash) && !bool (MerkleRoot);
        if (bool (MerkleRoot)) return !bool (BlockHeader) && !bool (BlockHash);
        return false;
    }
    
    bool proofs_serialization_standard::valid (const JSON &j) {
        if (!j.is_object ()) return false;
        
        // composite proofs not yet supported. 
        if (j.contains ("composite") && (!j["composite"].is_boolean () || j["composite"] == true)) return false;
        
        // trees not yet supported. 
        if (j.contains ("proofType") && (!j["proofType"].is_string () || j["proofType"] != "branch")) return false;
        
        if (!j.contains ("index") || !j["index"].is_number_unsigned ()) return false;
        
        if (!j.contains ("txOrId") ||
            !j["txOrId"].is_string () ||
            string (j["txOrId"]).size () < 64 ||
            !encoding::hex::valid (string (j["txOrId"]))) return false;
        
        if (j.contains ("targetType")) {
            JSON targetType = j["targetType"];
            if (!targetType.is_string () || (targetType != "hash" && targetType != "header" && targetType != "merkleRoot")) return false;
        } else if (!j.contains ("target") || !j["target"].is_string () || !encoding::hex::valid (string (j["target"]))) return false;
        
        if (!j.contains ("nodes")) return false;
        
        JSON nodes = j["nodes"];
        if (nodes.is_array ()) {
            for (const JSON &node : nodes) if (!node.is_string () ||
                (node != "*" && !(encoding::hex::valid (string (node)) && string (node).size () == 64))) return false;
        } else return false;
        
        return true;
    }
    
    proofs_serialization_standard::operator JSON () const {
        if (!valid ()) return nullptr;
        
        JSON j = JSON::object_t {};
        
        j["index"] = Path.Index;
        j["nodes"] = write_path (branch ());
        
        if (bool (Txid)) {
            j["txOrId"] = write_digest (*Txid);
        } else {
            j["txOrId"] = encoding::hex::write (*Transaction);
        }
        
        if (bool (BlockHash)) {
            j["target"] = write_digest (*BlockHash);
        } else if (bool (BlockHeader)) {
            j["targetType"] = "header";
            j["target"] = encoding::hex::write (BlockHeader->write ());
        } else if (bool (MerkleRoot)) {
            j["targetType"] = "merkleRoot";
            j["target"] = write_digest (*MerkleRoot);
        } else {
            return nullptr;
        }
        
        return j;
    }
    
    digest256 inline proofs_serialization_standard::txid (const JSON &j) {
        if (!valid (j)) return {};
        if (j["txOrId"].size () == 64) {
            return read_digest (j["txOrId"]);
        } else {
            return Bitcoin::transaction::id(*encoding::hex::read (string (j["txOrId"])));
        }
    }
    
    proofs_serialization_standard proofs_serialization_standard::read_JSON (const JSON &j) {
        proofs_serialization_standard x;
        if (!proofs_serialization_standard::valid (j)) return {};
        
        if (string (j["txOrId"]).size () == 64) x.Txid = read_digest (j["txOrId"]);
        // we know this is ok because we checked valid earlier.
        else x.Transaction = *encoding::hex::read (string (j["txOrId"]));
        
        x.Path.Index = j["index"];
        x.Path.Digests = read_path (j["nodes"], x.leaf ());
        
        if (!j.contains ("targetType")) {
            x.BlockHash = read_digest (j["target"]);
        } else {
            if (j["targetType"] == "hash") {
                x.BlockHash = read_digest (j["target"]);
            } else if (j["targetType"] == "header") {
                x.BlockHeader = read_header (j["target"]);
            } else if (j["targetType"] == "merkleRoot"){
                x.MerkleRoot = read_digest (j["target"]);
            } else return {};
        }
        
        return x;
    }
    
    reader &read_transaction (reader &r, bytes &b) {
        return r >> Bitcoin::var_string {b};
    }
    
    reader &read_node (reader &r, maybe<digest256> &node) {
        byte type;
        r = r >> type;
        if (type == 1) {
            node = {};
        } else if (type == 0) {
            node = {digest256 {}};
            r = r >> *node;
        } else throw std::logic_error {"unknown node type"};
        return r;
    }
    
    reader &read_path (reader &r, digest256 leaf, Merkle::path &p) {
        Bitcoin::var_int size; 
        r >> size;
        Merkle::digests d;
        Merkle::leaf l {leaf, p.Index};
        for (int i = 0; i < size; i++) {
            maybe<digest256> Next;
            r = read_node (r, Next);
            digest256& next = bool (Next) ? *Next : l.Digest;
            d = d << next;
            l = l.next (next);
        }
        p.Digests = data::reverse (d);
        return r;
    }
    
    proofs_serialization_standard proofs_serialization_standard::read_binary (bytes_view b) {
        try {
            proofs_serialization_standard x;
            
            byte flags;
            bytes_reader r {b.data (), b.data () + b.size ()};
            Bitcoin::var_int index; 
            r >> flags >> index;
            x.Path.Index = index;
            
            if (x.transaction_included (flags)) {
                bytes tx;
                read_transaction (r, tx);
            } else {
                Bitcoin::txid t;
                r >> t;
                x.Txid = t;
            }

            switch (target_type (flags)) {
                case target_type_block_hash: {
                    digest256 block_hash; 
                    r >> block_hash;
                    x.BlockHash = block_hash;
                    break;
                }
                case target_type_block_header: {
                    bytes header (80);
                    r >> header;
                    x.BlockHeader = Bitcoin::header {slice<80> (header.data ())};
                    break;
                }
                case target_type_Merkle_root: {
                    digest256 root; 
                    r >> root;
                    x.MerkleRoot = root;
                    break;
                }
                case target_type_invalid: {
                    return {};
                }
            }
            
            read_path (r, x.txid (), x.Path);
            return x;
        } catch (...) {}
        return {};
    }
    
    writer &write_duplicate (writer &w) {
        return w << byte (1);
    }
    
    writer &write_node (writer &w, const digest256 &d) {
        return w << byte (0) << d;
    }
    
    writer &write_path (writer &w, list<maybe<digest256>> b) {
        w << Bitcoin::var_int {b.size ()};
        for (const maybe<digest256> &z : b) {
            if (bool (z)) w = write_node (w, *z);
            else w = write_duplicate (w);
        }
        return w;
    }
    
    writer &write_txid (writer &w, const Bitcoin::txid &t) {
        return w << t;
    }
    
    writer &write_transaction (writer &w, const bytes& t) {
        return w << Bitcoin::var_int {t.size ()} << t;
    }
    
    proofs_serialization_standard::operator bytes () const {
        bool tx_included = transaction_included ();
        auto tt = target_type ();
        
        // we need to pre-generate some data for the path. 
        auto path = generate_path (branch ());
        
        // figure out the serialized size. 
        size_t size = 1 + 
            Bitcoin::var_int::size (Path.Index) +
            Bitcoin::var_int::size (Path.Digests.size ()) +
            (tx_included ? Bitcoin::var_int::size (Transaction->size ()) + Transaction->size () : 32);
        for (const maybe<digest256>& d : path) size += (bool (d) ? 33 : 1);
        if (tt == target_type_block_hash || tt == target_type_Merkle_root) size += 32;
        else if (tt == target_type_block_header) size += 80;
        
        // allocate space 
        bytes b (size);
        
        // write flags and index. 
        bytes_writer w {b.begin (), b.end ()};
        w << flags() << Bitcoin::var_int {index ()};
        
        if (tx_included) write_transaction (w, *Transaction);
        else write_txid (w, *Txid);
        
        if (tt == target_type_block_hash) write_txid (w, *BlockHash);
        else if (tt == target_type_Merkle_root) write_txid (w, *MerkleRoot);
        else if (target_type_block_header) w << BlockHeader->write ();
        else return {};
        
        write_path (w, path);
        return b;
    }
    
    proofs_serialization_standard::target_type_value proofs_serialization_standard::target_type (const JSON &j) {
        if (!j.contains ("targetType")) return target_type_block_hash;
        if (j["targetType"] == "hash") return target_type_block_hash;
        if (j["targetType"] == "header") return target_type_block_header;
        return target_type_Merkle_root;
    }
    
    proofs_serialization_standard::target_type_value proofs_serialization_standard::target_type () const {
        if (bool (BlockHeader)) return target_type_block_header;
        if (bool (BlockHash)) return target_type_block_hash;
        if (bool (MerkleRoot)) return target_type_Merkle_root;
        return target_type_invalid;
    }
    
    proofs_serialization_standard::proofs_serialization_standard(
        const Bitcoin::transaction& t, const Merkle::path& p, const digest256& hash, target_type_value v) {
        if (v == target_type_block_hash) BlockHash = hash;
        else if (v == target_type_Merkle_root) MerkleRoot = hash;
        else return;
        Transaction = bytes(t);
        Path = p;
    }
    
    maybe<digest256> inline proofs_serialization_standard::Merkle_root(const JSON& j) {
        target_type_value target = target_type(j);
        if (target == target_type_Merkle_root) return {read_digest (j["target"])};
        if (target == target_type_block_header) return block_header (j)->MerkleRoot;
        return {};
    }
    
    maybe<Bitcoin::header> inline proofs_serialization_standard::block_header (const JSON &j) {
        if (j.contains ("targetType") && j["targetType"] == "header") return {read_header (j["target"])};
        return {};
    }
    
}
