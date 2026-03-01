#ifndef POWERCOIN_CONFIG_H
#define POWERCOIN_CONFIG_H

#include <string>

namespace PowerCoin {
    
    const std::string COIN_NAME = "Power Coin";
    const std::string COIN_SYMBOL = "PWR";
    const uint64_t TOTAL_SUPPLY = 21000000;
    const uint64_t INITIAL_BLOCK_REWARD = 50;
    const uint32_t INITIAL_DIFFICULTY = 4;
    const uint16_t P2P_PORT = 8333;
    
}

#endif // POWERCOIN_CONFIG_H