// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.



#ifndef GIGAMONKEY_HD_WALLET_FORMATS_H
#define GIGAMONKEY_HD_WALLET_FORMATS_H
#include <gigamonkey/schema/hd.hpp>
namespace Gigamonkey {
    namespace Bitcoin {
        namespace hd {
            namespace SimplyCash {
                class SimplyCash {
                private:
                    bip32::secret rootKey;
                    bip32::secret derive(int type,int index);
                public:
                    SimplyCash(std::string words);
                    inline bip32::secret change(int index) { return derive(1,index);};
                    inline bip32::secret receive(int index) { return derive(0,index);};
                };
            }
        }
    }
}
#endif //GIGAMONKEY_HD_WALLET_FORMATS_H
