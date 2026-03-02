⚡ POWER COIN (PWR)

A **POWER COIN cryptocurrency** with advanced features - secure, decentralized, and feature-rich.


 📋 TABLE OF CONTENTS
- [Overview](#-overview)
- [Features](#-features)
- [Quick Start](#-quick-start)
- [Building from Source](#-building-from-source)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Configuration](#-configuration)
- [API Reference](#-api-reference)
- [Testing](#-testing)
- [Contributing](#-contributing)
- [License](#-license)
- [Contact](#-contact)

---

🌟 OVERVIEW

Power Coin (PWR) is a **complete blockchain implementation** written in C++17. It combines POWER proven security model with modern features like smart contracts, privacy, and governance.

✨ Why Power Coin?

- ✅ **Faster transactions** - Optimized for performance
- ✅ **Lower fees** - Efficient design
- ✅ **More features** - Smart contracts, privacy, governance
- ✅ **Pure C++** - No dependencies on other chains
- ✅ **Open source** - MIT licensed

---
 🚀 FEATURES

🔗 **Blockchain Core**
| Feature | Description |
|---------|-------------|
| **UTXO Model** | Bitcoin-style unspent transaction outputs |
| **Merkle Trees** | Efficient transaction verification |
| **Difficulty Adjustment** | Every 2016 blocks (Bitcoin-compatible) |
| **Halving Schedule** | Every 210,000 blocks |
| **Block Time** | 10 minutes |
| **Total Supply** | 21,000,000 PWR |

 🔐 **Cryptography**
| Feature | Description |
|---------|-------------|
| **SHA-256** | Double SHA-256 hashing |
| **RIPEMD-160** | Address generation |
| **Base58Check** | Human-readable addresses |
| **secp256k1** | Elliptic curve cryptography |
| **AES-256** | Wallet encryption |
| **BIP39** | Mnemonic seed phrases |
| **BIP32** | Hierarchical deterministic wallets |

 🌐 **Networking**
| Feature | Description |
|---------|-------------|
| **P2P Network** | Full peer-to-peer node |
| **Peer Discovery** | Automatic peer finding |
| **Block Propagation** | Gossip protocol |
| **Handshake** | Version/verack protocol |
| **Bloom Filters** | Light client support |
| **DHT** | Distributed hash table for peers |

👛 **Wallet**
| Feature | Description |
|---------|-------------|
| **HD Wallet** | BIP32/39/44 compatible |
| **Multiple Addresses** | Unlimited addresses per wallet |
| **Address Types** | P2PKH, P2SH, Bech32 |
| **Multi-signature** | M-of-N multisig |
| **Watch-only** | Import addresses without keys |
| **UTXO Management** | Coin selection, locking |
| **Transaction History** | Full history tracking |

⛏️ **Mining**
| Feature | Description |
|---------|-------------|
| **Proof of Work** | SHA-256d mining |
| **CPU Mining** | Multi-threaded CPU miner |
| **GPU Mining** | OpenCL/CUDA support |
| **Pool Mining** | Stratum protocol |
| **Solo Mining** | Mine alone |
| **Difficulty** | Automatic adjustment |

---

📖 USAGE
Command Line Interface

=== POWER COIN (PWR) ===
1. 👛 Create New Wallet
2. 🔑 Load Wallet
3. 💰 Check Balance
4. 📤 Send PWR
5. 📥 Receive Address
6. ⛏️  Start Mining
7. ⏹️  Stop Mining
8. 📊 Blockchain Info
9. 🔗 Network Info
10. 📝 Mining Stats
11. 💾 List Wallets
0. 🚪 Exit

Build from Source

# Clone the repository
git clone https://github.com/vansh9090-prog/Powercoin.git

cd powercoin

# Create build directory
mkdir build && cd build

# Configure
cmake ..

# Build
make -j4

# Run
./bin/powercoin

🔧 BUILDING FROM SOURCE
Detailed Build Instructions
Linux (Ubuntu/Debian)

# Install dependencies
sudo apt-get update
sudo apt-get install build-essential cmake git pkg-config
sudo apt-get install libssl-dev libboost-all-dev libleveldb-dev

# Clone and build
git clone https://github.com/vansh9090-prog/Powercoin.git
cd powercoin
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
sudo make install

macOS

# Install Homebrew if not installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install cmake boost openssl leveldb

# Clone and build
git clone https://github.com/vansh9090-prog/Powercoin.git
cd powercoin
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(sysctl -n hw.ncpu)

Windows (MSYS2/MinGW)

# Install MSYS2 from https://www.msys2.org/
# Open MSYS2 UCRT64 terminal

# Update packages
pacman -Syu

# Install dependencies
pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake
pacman -S mingw-w64-ucrt-x86_64-boost mingw-w64-ucrt-x86_64-openssl
pacman -S git make

# Clone and build
git clone https://github.com/vansh9090-prog/Powercoin.git
mkdir build && cd build
cmake -G "MSYS Makefiles" -DCMAKE_BUILD_TYPE=Release ..
make -j4

Built with ❤️ by the Power Coin 
