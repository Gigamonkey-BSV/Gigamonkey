// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_MINER
#define GIGAMONKEY_STRATUM_MINER

#include <gigamonkey/work/target.hpp>
#include <gigamonkey/stratum/mining_set_extranonce.hpp>
#include <gigamonkey/stratum/extensions.hpp>
#include <gigamonkey/stratum/client_session.hpp>
#include <shared_mutex>

namespace Gigamonkey::Stratum {
    
    class miner final : public client_session {
        using tcp = boost::asio::ip::tcp;
        
        difficulty *Difficulty;
        mining::set_extranonce::parameters *ExtraNonce;
        extensions::version_mask *VersionMask;
        mining::notify::parameters *Notify;
        
        bool ready_to_mine() {
            return ExtraNonce != nullptr && Difficulty != nullptr && Notify != nullptr;
        }
        
        struct job {
            work::job WorkJob;
            size_t ExtraNonce2Size;
            uint256 Target;
            bool VersionMaskEnabled;
        };
        
        static job make_job(const difficulty &d,
            const mining::set_extranonce::parameters &p,
            const mining::notify::parameters &n,
            const extensions::version_mask *mask) {
            
            job j{work::job{
                work::puzzle{n.Version, n.Digest, n.Target, Merkle::path{0, n.Path}, n.GenerationTx1, n.GenerationTx2}, p.ExtraNonce1}, 
                p.ExtraNonce2Size, uint256(work::difficulty(d)), false};
            
            if (mask != nullptr) {
                j.VersionMaskEnabled = true;
                j.WorkJob.Puzzle.Mask = *mask;
            };
            
            return j;
        }
        
        job *Job;
        
        std::shared_mutex Mutex;
        
        void work();
        
        uint32 Threads;
        std::thread** Mining;
        
        std::promise<void> WhenMiningStarts;
        std::future<void> WaitToStartMining;
        
        void start();
        
        void wait_to_start_mining();
        
        void make_puzzle() {
            if (!ready_to_mine()) return;
            if (Job != nullptr) *Job = make_job(*Difficulty, *ExtraNonce, *Notify, VersionMask);
            else {
                Job = new job{make_job(*Difficulty, *ExtraNonce, *Notify, VersionMask)};
                start();
            }
        }
        
        void notify(const mining::notify::parameters &n) final override {
            std::cout << "notification received: " << n << std::endl;
            std::lock_guard<std::shared_mutex> lock(Mutex);
            if (Notify == nullptr) Notify = new mining::notify::parameters{n};
            else *Notify = n;
            make_puzzle();
        }
        
        void set_difficulty(const difficulty &d) final override {
            std::cout << "difficulty received: " << d << std::endl;
            std::lock_guard<std::shared_mutex> lock(Mutex);
            if (Difficulty == nullptr) Difficulty = new difficulty{d};
            else *Difficulty = d;
            make_puzzle();
        }
        
        void set_extranonce(const mining::set_extranonce::parameters &p) final override {
            std::cout << "extra nonce received: " << p << std::endl;
            std::lock_guard<std::shared_mutex> lock(Mutex);
            if (ExtraNonce == nullptr) ExtraNonce = new mining::set_extranonce::parameters{p};
            else *ExtraNonce = p;
            make_puzzle();
        }
        
        void set_version_mask(const extensions::version_mask &m) final override {
            std::cout << "version mask received: " << m << std::endl;
            std::lock_guard<std::shared_mutex> lock(Mutex);
            if (VersionMask == nullptr) VersionMask = new extensions::version_mask{m};
            else *VersionMask = m;
            make_puzzle();
        }
        
        string version() final override {
            return Version;
        }
        
        void error(const io_error&) final override {
            shutdown();
            throw std::logic_error{""};
        }
        
        miner(tcp::socket &socket, uint32 threads) : 
            client_session{socket}, Threads{threads}, Mining{new std::thread*[threads]}, 
            WhenMiningStarts{}, WaitToStartMining{WhenMiningStarts.get_future()} {}
    public:
        
        // because we use shared_from_this, miner must be used as a shared_ptr. 
        static ptr<miner> make(tcp::socket &socket, uint32 threads) {
            return ptr<miner>(new miner{socket, threads});
        }
        
        static constexpr char Version[]{"Gigamonkey cpu miner/alpha"};
        
        void run(
            const optional<mining::configure_request::parameters> cp, 
            const mining::authorize_request::parameters& ap, 
            const mining::subscribe_request::parameters& sp) {
            try {
                if (!this->initialize(cp, ap, sp)) shutdown();
                
                WaitToStartMining.get();
                
                std::cout << "Begin mining!" << std::endl;
                
                for (int i = 0; i < Threads; i++) Mining[i]->join();
            } catch (...) {
                std::cout << "some kind of error happened" << std::endl;
                shutdown();
            }
        }
        
        void shutdown() {
            // TODO
        }
        
        ~miner() {
            shutdown();
        }
        
    };

}

#endif
