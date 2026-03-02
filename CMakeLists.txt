cmake_minimum_required(VERSION 3.10)
project(PowerCoin VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ============================================================================
# Build type configuration
# ============================================================================
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

# ============================================================================
# Compiler flags
# ============================================================================
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra)
endif()

# ============================================================================
# Find required packages
# ============================================================================
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(Boost 1.65 REQUIRED COMPONENTS system filesystem)

# LevelDB
find_path(LEVELDB_INCLUDE_DIR NAMES leveldb/db.h)
find_library(LEVELDB_LIBRARY NAMES leveldb)

if(NOT LEVELDB_INCLUDE_DIR OR NOT LEVELDB_LIBRARY)
    message(FATAL_ERROR "LevelDB not found")
endif()

# ============================================================================
# Include directories
# ============================================================================
include_directories(
    ${CMAKE_SOURCE_DIR}/src
    ${OPENSSL_INCLUDE_DIR}
    ${Boost_INCLUDE_DIRS}
    ${LEVELDB_INCLUDE_DIR}
)

# ============================================================================
# Source files
# ============================================================================

# Core Blockchain
set(CORE_SOURCES
    src/blockchain/block.cpp
    src/blockchain/blockchain.cpp
    src/blockchain/transaction.cpp
    src/blockchain/script.cpp
    src/blockchain/consensus.cpp
    src/blockchain/validation.cpp
)

# Cryptography
set(CRYPTO_SOURCES
    src/crypto/sha256.cpp
    src/crypto/ripemd160.cpp
    src/crypto/base58.cpp
    src/crypto/secp256k1.cpp
    src/crypto/aes.cpp
    src/crypto/random.cpp
)

# Networking
set(NETWORK_SOURCES
    src/network/p2p.cpp
    src/network/dht.cpp
    src/network/messages.cpp
    src/network/handshake.cpp
    src/network/sync.cpp
)

# Wallet
set(WALLET_SOURCES
    src/wallet/wallet.cpp
    src/wallet/address.cpp
    src/wallet/keystore.cpp
    src/wallet/mnemonic.cpp
    src/wallet/utxo.cpp
)

# Mining
set(MINING_SOURCES
    src/mining/pow.cpp
    src/mining/miner.cpp
    src/mining/stratum.cpp
    src/mining/difficulty.cpp
)

# Main and config
set(MAIN_SOURCES
    src/config.cpp
    src/main.cpp
)

# Combine all sources
set(ALL_SOURCES
    ${CORE_SOURCES}
    ${CRYPTO_SOURCES}
    ${NETWORK_SOURCES}
    ${WALLET_SOURCES}
    ${MINING_SOURCES}
    ${MAIN_SOURCES}
)

# ============================================================================
# Executable
# ============================================================================
add_executable(powercoin ${ALL_SOURCES})

# ============================================================================
# Link libraries
# ============================================================================
target_link_libraries(powercoin
    ${OPENSSL_LIBRARIES}
    ${Boost_LIBRARIES}
    ${LEVELDB_LIBRARY}
    Threads::Threads
    ${CMAKE_DL_LIBS}
)

# ============================================================================
# Install
# ============================================================================
install(TARGETS powercoin RUNTIME DESTINATION bin)

# ============================================================================
# Testing (optional)
# ============================================================================
option(BUILD_TESTS "Build tests" OFF)

if(BUILD_TESTS)
    enable_testing()
    add_executable(powercoin_test tests/test_main.cpp)
    target_link_libraries(powercoin_test powercoin)
    add_test(NAME powercoin_test COMMAND powercoin_test)
endif()

# ============================================================================
# Print build summary
# ============================================================================
message(STATUS "========================================")
message(STATUS "Power Coin Build Configuration")
message(STATUS "========================================")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "========================================")