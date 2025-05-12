// Copyright (c) 2019-2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/SPV.hpp>
#include <gigamonkey/script/interpreter.hpp>

namespace Gigamonkey::Bitcoin {
    
    block genesis () {
        static block Genesis = block {bytes (encoding::hex::string {std::string {} +
            "0100000000000000000000000000000000000000000000000000000000000000" +
            "000000003BA3EDFD7A7B12B27AC72C3E67768F617FC81BC3888A51323A9FB8AA" +
            "4B1E5E4A29AB5F49FFFF001D1DAC2B7C01010000000100000000000000000000" +
            "00000000000000000000000000000000000000000000FFFFFFFF4D04FFFF001D" +
            "0104455468652054696D65732030332F4A616E2F32303039204368616E63656C" +
            "6C6F72206F6E206272696E6B206F66207365636F6E64206261696C6F75742066" +
            "6F722062616E6B73FFFFFFFF0100F2052A01000000434104678AFDB0FE554827" +
            "1967F1A67130B7105CD6A828E03909A67962E0EA1F61DEB649F6BC3F4CEF38C4" +
            "F35504E51EC112DE5C384DF7BA0B8D578A4C702B6BF11D5FAC00000000"})};
        return Genesis;
    }
}

namespace Gigamonkey::SPV {

    ptr<const data::entry<N, Bitcoin::header>> database::memory::header (const N &n) {
        auto h = ByHeight.find (n);
        if (h == ByHeight.end ()) return {};
        return h->second->Header;
    }

    ptr<const data::entry<N, Bitcoin::header>> database::memory::header (const digest256 &n) {
        auto h = ByHash.find (n);

        if (h == ByHash.end ()) {
            h = ByRoot.find (n);
            if (h == ByRoot.end ()) return {};
        }

        return h->second->Header;
    }

    Merkle::dual database::memory::dual_tree (const digest256 &d) const {
        auto h = ByHash.find (d);

        if (h == ByHash.end ()) {
            h = ByRoot.find (d);
            if (h == ByRoot.end ()) return {};
        }

        return Merkle::dual {h->second->Paths, h->second->Header->Value.MerkleRoot};
    }

    ptr<const entry<N, Bitcoin::header>> database::memory::insert (const data::N &height, const Bitcoin::header &h) {

        if (!h.valid ()) return nullptr;

        auto old = ByHeight.find (height);
        if (old != ByHeight.end ()) {
            if (old->second->Header->Value == h) return old->second->Header;
            // if we replace one header with another, we assume this is a reorg and replace all subsequent blocks.

            auto o = old;
            do {
                for (const auto &[key, _] : o->second->Paths) {
                    // all txs in paths go into pending.
                    ByTXID.erase (key);
                    Pending = Pending.insert (key);
                }

                ByRoot.erase (o->second->Header->Value.MerkleRoot);
                ByHash.erase (o->second->Header->Value.hash ());

                ByHeight.erase (o++);

            } while (o != ByHeight.end ());

            // this block becomes latest.
            Latest = nullptr;
        }

        ptr<entry> new_entry {new entry {height, h}};
        ByHeight[height] = new_entry;

        ByHash[h.hash ()] = new_entry;
        ByRoot[h.MerkleRoot] = new_entry;

        if (height == 0 || Latest == nullptr || Latest->Header->Key < height)
            Latest = new_entry;

        if (height > 0) if (auto i = ByHeight.find (height - 1); i != ByHeight.end ())
            new_entry->Previous = i->second;

        if (auto i = ByHeight.find (height + 1); i != ByHeight.end ())
            i->second->Previous = new_entry;

        return new_entry->Header;
    }

    database::tx database::memory::transaction (const Bitcoin::TXID &t) {
        auto tx = Transactions.find (t);
        ptr<const Bitcoin::transaction> tt {tx == Transactions.end () ? ptr<const Bitcoin::transaction> {} : tx->second};
        auto h = ByTXID.find (t);
        return h == ByTXID.end () ? database::tx {tt} :
            database::tx {tt, confirmation {
                Merkle::path (Merkle::dual {h->second->Paths, h->second->Header->Value.MerkleRoot}[t].Branch),
                h->second->Header->Key,
                h->second->Header->Value}};
    }

    namespace {

        bool check_sub_proof (
            set<Bitcoin::TXID> &checked,
            const Bitcoin::transaction &tx,
            proof::map map,
            database &d,
            time_limit genesis_upgrade_time);

        bool proof_validate (const proof &u, database &d, time_limit genesis_upgrade_time = time_limit::negative_infinity ()) {

            //check that all txs are unique.
            auto pp = u.Payment;
            while (!data::empty (pp)) {
                auto x = pp.first ();
                pp = pp.rest ();
                for (const auto &p : pp) if (x == p) return false;
            }

            // keep track of transactions we have checked already.
            set<Bitcoin::TXID> checked;

            // we check each transaction in the payment, which involves
            // checking antecedents and their antecedents and so on.
            for (const Bitcoin::transaction &tx : u.Payment)
                if (!check_sub_proof (checked, tx, u.Proof, d, genesis_upgrade_time)) return false;

            return true;
        }

        bool check_sub_proof (
            set<Bitcoin::TXID> &checked,
            const Bitcoin::transaction &tx,
            proof::map map,
            database &d,
            time_limit genesis_upgrade_time) {

            uint32 input_index = 0;
            Bitcoin::satoshi spent = 0;

            // for checking scripts.
            Bitcoin::incomplete::transaction incomplete {tx};

            for (const Bitcoin::input &in : tx.Inputs) {
                const auto *v = map.contains (in.Reference.Digest);
                if (!bool (v)) return {};

                const proof::node &antecedent = **v;

                time_limit execution_time;

                if (!checked.contains (in.Reference.Digest)) {
                    if (antecedent.Proof.is<SPV::confirmation> ()) {
                        const confirmation &conf = antecedent.Proof.get<confirmation> ();
                        if (d.header (conf.Header.MerkleRoot) == nullptr) return false;

                        if (!proof::valid (antecedent.Transaction, conf.Path, conf.Header)) return false;

                        execution_time = time_limit {conf.Header.Timestamp};
                    } else {
                        if (!check_sub_proof (checked, antecedent.Transaction, antecedent.Proof.get<proof::map> (), d, genesis_upgrade_time))
                            return {};
                        checked = checked.insert (in.Reference.Digest);

                        // this ensures that we use the latest version of the interpreter.
                        execution_time = time_limit::infinity ();
                    }
                }

                // get prevout
                if (in.Reference.Index >= antecedent.Transaction.Outputs.size ()) return false;
                const Bitcoin::output &prevout = antecedent.Transaction.Outputs[in.Reference.Index];

                spent += prevout.Value;

                // check scripts
                if (!bool (
                    Bitcoin::evaluate (
                        in.Script, prevout.Script,
                        Bitcoin::redemption_document {incomplete, input_index, prevout.Value},
                        genesis_upgrade_time > execution_time ?
                            Bitcoin::script_config {Bitcoin::pre_genesis_profile ()}:
                            Bitcoin::script_config {Bitcoin::genesis_profile ()}
                        )
                    )
                ) return false;

                input_index++;
            }

            return spent >= tx.sent ();
        }
    }

    // check valid and check that all headers are in our database.
    bool proof::validate (SPV::database &d, time_limit genesis_upgrade_time) const {
        return proof_validate (*this, d, genesis_upgrade_time);
    }

    namespace {

        proof::accepted generate_proof_node (database &d, const Bitcoin::TXID &x) {

            database::tx n = d.transaction (x);
            // if we don't know about this tx then we can't construct a proof.
            if (!n.valid ()) return {};
            if (n.confirmed ()) return ptr<proof::node> {new proof::node {*n.Transaction, n.Confirmation}};

            database::tx tx = d.transaction (x);
            if (!tx.valid ()) return {};

            proof::map antecedents;

            for (const Bitcoin::input &in : tx.Transaction->Inputs) {
                proof::accepted u = generate_proof_node (d, in.Reference.Digest);
                if (u == nullptr) return {};
                antecedents = antecedents.insert (in.Reference.Digest, u);
            }

            return ptr<proof::node> {new proof::node {*n.Transaction, antecedents}};
        }
    }

    // attempt to generate a given SPV proof for an unconfirmed transaction.
    // this proof can be sent to a merchant who can use it to confirm that
    // the transaction is valid.
    maybe<proof> generate_proof (database &d, list<Bitcoin::transaction> payment) {
        proof p;

        for (const Bitcoin::transaction &b : payment) {

            Bitcoin::TXID x = b.id ();

            // the transaction should not have a proof already because
            // this is supposed to be a payment that is unconfirmed.
            database::tx n = d.transaction (x);
            if (n.confirmed ()) return {};

            p.Payment <<= b;

            for (const Bitcoin::input &in : b.Inputs)
                if (!p.Proof.contains (in.Reference.Digest)) {
                    if (ptr<proof::node> u = generate_proof_node (d, in.Reference.Digest); u == nullptr) return {};
                    else p.Proof = p.Proof.insert (in.Reference.Digest, u);
                }
        }

        return p;
    }

    maybe<extended::transaction> extend (database &d, const Bitcoin::transaction &tx) {
        list<extended::input> inputs;
        for (const auto &in : tx.Inputs) {
            auto c = d.transaction (in.Reference.Digest);
            if (!c.valid ()) return {};
            inputs <<= {c.Transaction->Outputs[in.Reference.Index], in};
        }

        return extended::transaction {tx.Version, inputs, tx.Outputs, tx.LockTime};
    }

    void database::memory::insert (const Bitcoin::transaction &t) {
        auto txid = t.id ();
        auto x = Transactions.find (txid);
        if (x != Transactions.end ()) return;
        Transactions[txid] = ptr<Bitcoin::transaction> {new Bitcoin::transaction {t}};
        // Do we have a merkle proof for this tx? If not put it in pending.

        if (auto e = ByTXID.find (txid); e == ByTXID.end ())
            Pending = Pending.insert (txid);
    }

    bool database::memory::insert (const Merkle::dual &p) {
        if (!p.valid ()) return false;

        auto h = ByRoot.find (p.Root);
        if (h == ByRoot.end ()) return false;

        auto d = Merkle::dual {h->second->Paths, h->second->Header->Value.MerkleRoot} + p;
        h->second->Paths = d.Paths;

        for (const auto &[txid, _]: p.Paths) {
            ByTXID[txid] = h->second;

            // do we have a tx for this proof? If we do, remove from pending.
            if (auto e = Transactions.find (txid); e != Transactions.end ())
                Pending = Pending.remove (txid);
        }

        return true;
    }

    bool database::memory::insert (const Bitcoin::transaction &t, const Merkle::path &path) {
        auto txid = t.id ();
        auto x = Transactions.find (txid);
        if (x != Transactions.end ()) return false;

        Merkle::branch branch {txid, path};

        digest256 root = branch.root ();

        auto h = ByRoot.find (root);
        if (h == ByRoot.end ()) return false;

        auto d = Merkle::dual {h->second->Paths, h->second->Header->Value.MerkleRoot} + Merkle::proof {branch, root};
        h->second->Paths = d.Paths;

        Transactions[txid] = ptr<Bitcoin::transaction> {new Bitcoin::transaction {t}};

        return true;
    }

    void database::memory::remove (const Bitcoin::TXID &txid) {
        if (!Pending.contains (txid)) return;
        Pending = Pending.remove (txid);
        Transactions.erase (txid);
    }

    void remove_latest (database::memory &m) {
        auto last = m.Latest;

        m.ByHeight.erase (last->Header->Key);
        m.ByHash.erase (last->Header->Value.hash ());
        m.ByRoot.erase (last->Header->Value.MerkleRoot);

        for (const auto &key: last->Paths.keys ()) m.Pending = m.Pending.insert (key);

        m.Latest = last->Previous;

    }

    void database::memory::remove_header (const data::N &n) {
        block_header last = latest ();
        if (last->Key != n) return;
        remove_latest (*this);
    }

    void database::memory::remove_header (const digest256 &d) {
        block_header last = latest ();
        if (last->Value.hash () != d) return;
        remove_latest (*this);
    }

    std::partial_ordering SPV::proof::ordering (const data::entry<Bitcoin::TXID, proof::tree> &a, const data::entry<Bitcoin::TXID, proof::tree> &b) {
        if (a.Key == b.Key) return std::partial_ordering::equivalent;

        if (a.Value.is<confirmation> ()) {
            return b.Value.is<confirmation> () ?
                a.Value.get<confirmation> () <=> b.Value.get<confirmation> ():
                std::partial_ordering::less;
        }

        if (b.Value.is<confirmation> ()) return std::partial_ordering::greater;

        if (b.Value.get<map> ().contains_branch (a.Key)) return std::partial_ordering::less;
        if (a.Value.get<map> ().contains_branch (b.Key)) return std::partial_ordering::greater;

        return std::partial_ordering::unordered;
    }

    bool proof::map::contains_branch (const Bitcoin::TXID &txid) {
        for (const auto &[k, v] : *this)
            if (k == txid ||
                v->Proof.is<map> () &&
                    v->Proof.get<map> ().contains_branch (txid)) return true;

        return false;
    }

}
