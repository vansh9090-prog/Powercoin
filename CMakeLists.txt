cmake_minimum_required(VERSION 3.10)
project(PowerCoin)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/src)

# Source files
set(SOURCES
    src/main.cpp
    src/blockchain/block.cpp
    src/blockchain/transaction.cpp
    src/consensus/pow.cpp
    src/crypto/sha256.cpp
    src/wallet/wallet.cpp
    src/network/node.cpp
    src/network/p2p.cpp
)

# Header files
set(HEADERS
    src/config.h
    src/blockchain/block.h
    src/blockchain/transaction.h
    src/consensus/pow.h
    src/crypto/sha256.h
    src/wallet/wallet.h
    src/network/node.h
    src/network/p2p.h
)

# Executable
add_executable(powercoin ${SOURCES} ${HEADERS})

# Compiler flags
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(powercoin PRIVATE -Wall -Wextra -O2)
endif()

# Link libraries (if needed)
# target_link_libraries(powercoin pthread)