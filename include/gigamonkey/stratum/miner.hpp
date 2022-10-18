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
        
        // the notifications we will receive from the server that
        // define the mining job we are to perform. 
        difficulty *Difficulty;
        mining::set_extranonce::parameters *ExtraNonce;
        extensions::version_mask *VersionMask;
        mining::notify::parameters *Notify;
        
        bool ready_to_mine() {
            return ExtraNonce != nullptr && Difficulty != nullptr && Notify != nullptr;
        }
        
        struct job {
            job_id ID;
            work::job WorkJob;
            size_t ExtraNonce2Size;
            uint256 Target;
            bool VersionMaskEnabled;
        };
        
        static job make_job(const difficulty &d,
            const mining::set_extranonce::parameters &p,
            const mining::notify::parameters &n,
            const extensions::version_mask *mask);
        
        // the latest job we will be working on. 
        job *Job;
        
        // control access to the job. 
        std::shared_mutex ReadNewJobs;
        
        // how many mining threads we will have. 
        uint32 Threads;
        // pointers to them all. 
        std::thread** Mining;
        
        std::promise<void> WhenMiningStarts;
        std::shared_future<void> WaitToStartMining;
        
        byte random_byte();
        
        mutex GenerateRandomNumber;
        
        uint32_little random_uint32_little();
        
        bytes random_bytes(size_t size);
        
        void start();
        
        bool Finished;
        
        void make_puzzle();
        
        void notify(const mining::notify::parameters &n) final override;
        
        void set_difficulty(const difficulty &d) final override;
        
        void set_extranonce(const mining::set_extranonce::parameters &p) final override;
        
        void set_version_mask(const extensions::version_mask &m) final override;
        
        string version() final override {
            return Version;
        }
        
        void handle_error(const networking::io_error&) final override {
            shutdown();
            throw std::logic_error{""};
        }
        
        miner(networking::tcp::socket &socket, uint32 threads);
        
    public:
        
        // because we use shared_from_this, miner must be used as a shared_ptr. 
        static ptr<miner> make(networking::tcp::socket &socket, uint32 threads) {
            return ptr<client_session>(new client_session{socket, threads});
        }
        
        static constexpr char Version[]{"Gigamonkey cpu miner/alpha"};
        
        void run(
            const std::optional<extensions::requests> cp, 
            const mining::authorize_request::parameters& ap, 
            const mining::subscribe_request::parameters& sp);
        
        void shutdown();
        
        ~miner();
        
    };

}

#endif
