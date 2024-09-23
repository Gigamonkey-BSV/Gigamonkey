// Copyright (c) 2019-2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SPV
#define GIGAMONKEY_SPV

#include <gigamonkey/timechain.hpp>
#include <gigamonkey/pay/extended.hpp>
#include <gigamonkey/merkle/BUMP.hpp>
#include <data/either.hpp>

namespace Gigamonkey::Bitcoin {
    Bitcoin::block genesis ();
}

namespace Gigamonkey::SPV {

    struct confirmation {
        Merkle::path Path;
        N Height;
        Bitcoin::header Header;

        confirmation ();
        confirmation (Merkle::path p, const N &height, const Bitcoin::header &h);

        bool operator == (const confirmation &t) const;
        std::strong_ordering operator <=> (const confirmation &t) const;

        bool valid () const;
    };

    // database for storing headers, merkle proofs, and transactions.
    struct database;

    // a proof consists of a transaction + previous transactions that are being redeemed
    // with merkle proofs or previous transactions with merkle proofs, etc
    // this is what you would send to a peer when you wanted to make a payment.
    struct proof {

        static bool valid (const Bitcoin::transaction &tx, const Merkle::path &p, const Bitcoin::header &h);
        static bool valid (const Bitcoin::TXID &id, const Merkle::path &p, const digest256 &root);

        struct node;

        // a transaction that has been accepted by the network.
        struct accepted : ptr<node> {
            accepted ();
            accepted (ptr<node> &&n);
            accepted (const ptr<node> &n);

            bool valid () const;
            bool operator == (const accepted &tx) const;
        };

        struct map : tool::base_rb_map<Bitcoin::TXID, accepted, map> {
            using tool::base_rb_map<Bitcoin::TXID, accepted, map>::base_rb_map;
            bool operator == (const map &) const;
            bool contains_branch (const Bitcoin::TXID &);
        };

        // an spv proof is a tree whose nodes are txs and whose leaves are all Merkle proofs.
        struct tree : either<map, confirmation> {
            using either<map, confirmation>::either;
            bool valid () const;
        };

        // establish partial ordering of transactions.
        static std::partial_ordering ordering (const entry<Bitcoin::TXID, tree> &a, const entry<Bitcoin::TXID, tree> &b);

        struct node {
            Bitcoin::transaction Transaction;
            tree Proof;

            node (const Bitcoin::transaction &tx, const confirmation &c);
            node (const Bitcoin::transaction &tx, map m);

            bool operator == (const node &) const;
        };

        // the payment is in these transactions.
        // They do not yet have confirmations.
        list<Bitcoin::transaction> Payment;
        // map of txids referenced in the inputs of the transactions
        // to proofs, which may be further maps back to more transactions
        // or a merkle proof.
        map Proof;

        proof (): Payment {}, Proof {} {}

        bool valid () const;

        // check valid and check that all headers are in our database.
        // and check all scripts for txs that have no merkle proof.
        bool validate (database &) const;

        explicit operator list<extended::transaction> () const;

    };

    // convert proofs and proof parts to extended transactions.
    list<extended::transaction> inline extended_transactions (list<Bitcoin::transaction> payment, proof::map proof) {
        return for_each ([proof] (const Bitcoin::transaction &tx) -> extended::transaction {
            return extended::transaction {tx.Version, for_each ([proof] (const Bitcoin::input &in) -> extended::input {
                return extended::input {proof[in.Reference.Digest]->Transaction.Outputs[in.Reference.Index], in};
            }, tx.Inputs), tx.Outputs, tx.LockTime};
        }, payment);
    }

    extended::transaction inline extended_transaction (Bitcoin::transaction tx, proof::map proof) {
        return extended::transaction {tx.Version, for_each ([proof] (const Bitcoin::input &in) -> extended::input {
            return extended::input {proof[in.Reference.Digest]->Transaction.Outputs[in.Reference.Index], in};
        }, tx.Inputs), tx.Outputs, tx.LockTime};
    }

    // attempt to generate a given SPV proof for an unconfirmed transaction.
    // this proof can be sent to a merchant who can use it to confirm that
    // the transaction is valid.
    maybe<proof> generate_proof (database &d, list<Bitcoin::transaction> payment);
    maybe<extended::transaction> extend (database &d, Bitcoin::transaction);

    struct database {

        // get a block header by height.
        virtual const Bitcoin::header *header (const N &) = 0;

        virtual const entry<N, Bitcoin::header> *latest () = 0;

        // get by hash or merkle root
        virtual const entry<N, Bitcoin::header> *header (const digest256 &) = 0;

        // a transaction in the database, which may include a merkle proof if we have one.
        struct tx {

            ptr<const Bitcoin::transaction> Transaction;
            confirmation Confirmation;

            tx (ptr<const Bitcoin::transaction> t, const confirmation &x);
            tx (ptr<const Bitcoin::transaction> t);

            bool valid () const;
            // whether a proof is included.
            bool confirmed () const;
            // check the proof if it exists.
            bool validate () const;

        };

        // do we have a tx or merkle proof for a given tx?
        virtual tx transaction (const Bitcoin::TXID &) = 0;

        // get txids for transactions without Merkle proofs.
        virtual set<Bitcoin::TXID> unconfirmed () = 0;

        // an in-memory implementation of the database.
        class memory;

        virtual ~database () {}

    };

    // interface for database containing headers, transactions, and merkle path.
    struct writable {

        // it is allowed to insert a transaction without a merkle proof.
        // it goes into pending.
        virtual void insert (const Bitcoin::transaction &) = 0;

        // Txs cannot be removed unless they are in pending.
        virtual void remove (const Bitcoin::TXID &) = 0;
        
        // providing a merkle proof removes a tx from pending.
        virtual bool insert (const Merkle::proof &) = 0;
        virtual const data::entry<N, Bitcoin::header> *insert (const data::N &height, const Bitcoin::header &h) = 0;

        virtual ~writable () {}
    };
    
    struct database::memory : public virtual database, public virtual writable {
        struct entry {
            data::entry<data::N, Bitcoin::header> Header;
            Merkle::map Paths;
            ptr<entry> Last;

            entry (data::N n, Bitcoin::header h) : Header {n, h}, Paths {}, Last {nullptr} {}
            entry (data::N n, Bitcoin::header h, Merkle::map tree) : Header {n, h}, Paths {tree}, Last {nullptr} {}
            entry (Bitcoin::header h, const Merkle::BUMP &bump) : Header {bump.BlockHeight, h}, Paths {bump.paths ()}, Last {nullptr} {}

            Merkle::dual dual_tree () const;

            Merkle::BUMP BUMP () const;
        };

        ptr<entry> Latest;

        std::map<data::N, ptr<entry>> ByHeight;
        std::map<digest256, ptr<entry>> ByHash;
        std::map<digest256, ptr<entry>> ByRoot;
        std::map<Bitcoin::TXID, ptr<entry>> ByTXID;
        std::map<Bitcoin::TXID, ptr<const Bitcoin::transaction>> Transactions;
        set<Bitcoin::TXID> Pending;
        
        memory (const Bitcoin::header &h) {
            insert (0, h);
        }

        memory () : memory (Bitcoin::genesis ().Header) {}
        
        const data::entry<data::N, Bitcoin::header> *latest () final override {
            // always present because we always start with at least one header.
            return &Latest->Header;
        }
        
        const Bitcoin::header *header (const data::N &n) final override;
        const data::entry<data::N, Bitcoin::header> *header (const digest256 &n) override;

        tx transaction (const Bitcoin::TXID &t) final override;
        Merkle::dual dual_tree (const digest256 &d) const;

        const data::entry<N, Bitcoin::header> *insert (const data::N &height, const Bitcoin::header &h) final override;
        bool insert (const Merkle::proof &p) final override;
        void insert (const Bitcoin::transaction &) final override;

        // all unconfirmed txs in the database.
        set<Bitcoin::TXID> unconfirmed () final override;

        // only txs in unconfirmed can be removed.
        void remove (const Bitcoin::TXID &) final override;

    };

    inline confirmation::confirmation (): Path {}, Height {0}, Header {} {}
    inline confirmation::confirmation (Merkle::path p, const N &height, const Bitcoin::header &h): Path {p}, Height {height}, Header {h} {}

    bool inline confirmation::operator == (const confirmation &t) const {
        return Header == t.Header && t.Height == Height && Path.Index == t.Path.Index;
    }

    std::strong_ordering inline confirmation::operator <=> (const confirmation &t) const {
        auto cmp_block = Header <=> Header;
        return cmp_block == std::strong_ordering::equal ? cmp_block : Path.Index <=> t.Path.Index;
    }

    bool inline confirmation::valid () const {
        return Header.Timestamp != Bitcoin::timestamp {0};
    }

    bool inline proof::valid (const Bitcoin::transaction &tx, const Merkle::path &p, const Bitcoin::header &h) {
        return h.valid () && valid (tx.id (), p, h.MerkleRoot);
    }

    bool inline proof::valid (const Bitcoin::TXID &id, const Merkle::path &p, const digest256 &root) {
        return p.derive_root (id) == root;
    }

    set<Bitcoin::TXID> inline database::memory::unconfirmed () {
        return Pending;
    }

    inline proof::operator list<extended::transaction> () const {
        return extended_transactions (Payment, Proof);
    }

    inline proof::accepted::accepted (): ptr<node> {nullptr} {}
    inline proof::accepted::accepted (ptr<node> &&n): ptr<node> {n} {}
    inline proof::accepted::accepted (const ptr<node> &n): ptr<node> {n} {}

    bool inline proof::accepted::valid () const {
        return static_cast<ptr<node>> (*this) != nullptr;
    }

    bool inline proof::accepted::operator == (const accepted &tx) const {
        if (static_cast<ptr<node>> (*this) == static_cast<ptr<node>> (tx)) return true;
        return *(*this) == *tx;
    }

    inline proof::node::node (const Bitcoin::transaction &tx, const confirmation &c) : Transaction {tx}, Proof {c} {}

    inline proof::node::node (const Bitcoin::transaction &tx, map m) : Transaction {tx}, Proof {m} {}

    bool inline proof::tree::valid () const {
        return this->is<map> () && !data::empty (this->get<map> ()) ||
            this->is<confirmation> () && this->get<confirmation> ().valid ();
    }

    inline database::tx::tx (ptr<const Bitcoin::transaction> t, const confirmation &x) : Transaction {t}, Confirmation {x} {}
    inline database::tx::tx (ptr<const Bitcoin::transaction> t) : Transaction {t}, Confirmation {} {}

    bool inline database::tx::validate () const {
        if (!confirmed ()) return false;
        return proof::valid (*Transaction, Confirmation.Path, Confirmation.Header);
    }

    bool inline database::tx::confirmed () const {
        return Transaction != nullptr && Confirmation.valid ();
    }

    bool inline database::tx::valid () const {
        return Transaction != nullptr;
    }

    Merkle::dual inline database::memory::entry::dual_tree () const {
        return Merkle::dual {Paths, Header.Value.MerkleRoot};
    }

    Merkle::BUMP inline database::memory::entry::BUMP () const {
        return Merkle::BUMP {uint64 (Header.Key), Paths};
    }
}

#endif
