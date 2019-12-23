// Copyright (c) 2019 Katrina Swales
// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/work.hpp>
#include "gtest/gtest.h"

namespace gigamonkey::work {

    // can result in stack smashing
    TEST(WorkTest, DISABLED_TestWork) {
        
        const target MinimumTarget{31, 0xffffff};
        
        string message{"wake up!!!!!!"};
        
        work::content to_do{0};
        std::copy(message.begin(), message.end(), to_do.begin());
        
        const target target_half = SuccessHalf;
        const target target_quarter = SuccessQuarter;
        const target target_eighth = SuccessEighth;
        const target target_sixteenth = SuccessSixteenth;
        const target target_thirty_second = minimum_target;
        
        // Unknown exception thrown here.
        const order work_order_half = order{to_do, target_half};
        const order work_order_quarter = order{to_do, target_quarter};
        const order work_order_eighth = order{to_do, target_eighth};
        const order work_order_sixteenth = order{to_do, target_sixteenth};
        const order work_order_thirty_second = order{to_do, target_thirty_second};
        
        const nonce nonce_half = work(work_order_half);
        const nonce nonce_quarter = work(work_order_quarter);
        const nonce nonce_eighth = work(work_order_eighth);
        const nonce nonce_sixteenth = work(work_order_sixteenth);
        const nonce nonce_thirty_second = work(work_order_thirty_second);
        
        const candidate candidate_half = candidate{nonce_half, work_order_half};
        const candidate candidate_quarter = candidate{nonce_quarter, work_order_quarter};
        const candidate candidate_eighth = candidate{nonce_eighth, work_order_eighth};
        const candidate candidate_sixteenth = candidate{nonce_sixteenth, work_order_sixteenth};
        const candidate candidate_thirty_second = candidate{nonce_thirty_second, work_order_thirty_second};
        
        EXPECT_TRUE(candidate_half.valid());
        EXPECT_TRUE(candidate_quarter.valid());
        EXPECT_TRUE(candidate_eighth.valid());
        EXPECT_TRUE(candidate_sixteenth.valid());
        EXPECT_TRUE(candidate_thirty_second.valid());
        
        std::cout << "nonce half is " << nonce_half << std::endl;
        std::cout << "nonce quarter is " << nonce_quarter << std::endl;
        std::cout << "nonce eighth is " << nonce_eighth << std::endl;
        std::cout << "nonce sixteenth is " << nonce_sixteenth << std::endl;
        std::cout << "nonce thirty second is " << nonce_thirty_second << std::endl;
        
    }

}
