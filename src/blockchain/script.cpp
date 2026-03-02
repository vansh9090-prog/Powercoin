#include "script.h"
#include "../crypto/sha256.h"
#include "../crypto/ripemd160.h"
#include "../crypto/secp256k1.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cmath>
#include <cctype>

namespace powercoin {

    // ============== StackItem Implementation ==============

    StackItem::StackItem(uint64_t n) {
        data = castToBytes(n);
        isNumber = true;
    }

    int64_t StackItem::getNumber() const {
        if (data.empty()) return 0;
        if (!isNumber) return 0;
        
        int64_t n = 0;
        for (size_t i = 0; i < data.size(); i++) {
            n |= (static_cast<int64_t>(data[i]) << (i * 8));
        }
        return n;
    }

    std::string StackItem::toString() const {
        if (data.empty()) return "NULL";
        
        if (isNumber) {
            return std::to_string(getNumber());
        }
        
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (auto byte : data) {
            ss << std::setw(2) << (int)byte;
        }
        return ss.str();
    }

    StackItem StackItem::fromNumber(int64_t n) {
        return StackItem(static_cast<uint64_t>(n));
    }

    StackItem StackItem::fromBool(bool b) {
        std::vector<uint8_t> data;
        if (b) data.push_back(0x01);
        StackItem item(data);
        item.isNumber = true;
        return item;
    }

    // ============== ScriptContext Implementation ==============

    ScriptContext::ScriptContext() 
        : pc(0), opCount(0), valid(true), flags(SCRIPT_VERIFY_P2SH), version(0) {}

    void ScriptContext::reset() {
        stack.clear();
        altStack.clear();
        variables.clear();
        pc = 0;
        opCount = 0;
        valid = true;
        error.clear();
    }

    void ScriptContext::setError(const std::string& err) {
        valid = false;
        error = err;
    }

    // ============== Script Implementation ==============

    Script::Script() : parsed(true) {}

    Script::Script(const std::vector<uint8_t>& data) 
        : bytes(data), parsed(false) {}

    Script::Script(const std::string& hex) 
        : parsed(false) {
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteStr = hex.substr(i, 2);
            bytes.push_back(static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16)));
        }
    }

    Script::Script(const Script& other)
        : bytes(other.bytes), operations(other.operations),
          cachedString(other.cachedString), parsed(other.parsed) {}

    Script& Script::operator=(const Script& other) {
        if (this != &other) {
            bytes = other.bytes;
            operations = other.operations;
            cachedString = other.cachedString;
            parsed = other.parsed;
        }
        return *this;
    }

    Script::Script(Script&& other) noexcept
        : bytes(std::move(other.bytes)),
          operations(std::move(other.operations)),
          cachedString(std::move(other.cachedString)),
          parsed(other.parsed) {
        other.parsed = false;
    }

    Script& Script::operator=(Script&& other) noexcept {
        if (this != &other) {
            bytes = std::move(other.bytes);
            operations = std::move(other.operations);
            cachedString = std::move(other.cachedString);
            parsed = other.parsed;
            other.parsed = false;
        }
        return *this;
    }

    bool Script::operator==(const Script& other) const {
        return bytes == other.bytes;
    }

    bool Script::operator!=(const Script& other) const {
        return !(*this == other);
    }

    void Script::parse() const {
        if (parsed) return;
        
        operations.clear();
        size_t i = 0;
        
        while (i < bytes.size()) {
            OpCode op = static_cast<OpCode>(bytes[i]);
            operations.push_back(op);
            
            // Handle push operations with data
            if (op == OpCode::OP_PUSHDATA1) {
                if (i + 1 < bytes.size()) {
                    uint8_t len = bytes[i + 1];
                    i += len;
                }
            } else if (op == OpCode::OP_PUSHDATA2) {
                if (i + 2 < bytes.size()) {
                    uint16_t len = static_cast<uint16_t>(bytes[i + 1]) |
                                  (static_cast<uint16_t>(bytes[i + 2]) << 8);
                    i += len;
                }
            } else if (op == OpCode::OP_PUSHDATA4) {
                if (i + 4 < bytes.size()) {
                    uint32_t len = static_cast<uint32_t>(bytes[i + 1]) |
                                  (static_cast<uint32_t>(bytes[i + 2]) << 8) |
                                  (static_cast<uint32_t>(bytes[i + 3]) << 16) |
                                  (static_cast<uint32_t>(bytes[i + 4]) << 24);
                    i += len;
                }
            } else if (op >= OpCode::OP_1 && op <= OpCode::OP_16) {
                // Small numbers push themselves
            }
            
            i++;
        }
        
        parsed = true;
    }

    void Script::pushOp(OpCode op) {
        bytes.push_back(static_cast<uint8_t>(op));
        parsed = false;
    }

    void Script::pushData(const std::vector<uint8_t>& data) {
        if (data.size() < 0x4c) {
            bytes.push_back(static_cast<uint8_t>(data.size()));
        } else if (data.size() <= 0xff) {
            bytes.push_back(static_cast<uint8_t>(OpCode::OP_PUSHDATA1));
            bytes.push_back(static_cast<uint8_t>(data.size()));
        } else if (data.size() <= 0xffff) {
            bytes.push_back(static_cast<uint8_t>(OpCode::OP_PUSHDATA2));
            bytes.push_back(static_cast<uint8_t>(data.size() & 0xff));
            bytes.push_back(static_cast<uint8_t>((data.size() >> 8) & 0xff));
        } else {
            bytes.push_back(static_cast<uint8_t>(OpCode::OP_PUSHDATA4));
            bytes.push_back(static_cast<uint8_t>(data.size() & 0xff));
            bytes.push_back(static_cast<uint8_t>((data.size() >> 8) & 0xff));
            bytes.push_back(static_cast<uint8_t>((data.size() >> 16) & 0xff));
            bytes.push_back(static_cast<uint8_t>((data.size() >> 24) & 0xff));
        }
        
        bytes.insert(bytes.end(), data.begin(), data.end());
        parsed = false;
    }

    void Script::pushData(const std::string& data) {
        pushData(std::vector<uint8_t>(data.begin(), data.end()));
    }

    void Script::pushNumber(int64_t n) {
        if (n == -1) {
            pushOp(OpCode::OP_1NEGATE);
        } else if (n >= 1 && n <= 16) {
            pushOp(static_cast<OpCode>(static_cast<uint8_t>(OpCode::OP_1) + (n - 1)));
        } else {
            pushData(castToBytes(n));
        }
    }

    void Script::pushBool(bool b) {
        if (b) {
            pushOp(OpCode::OP_1);
        } else {
            pushOp(OpCode::OP_0);
        }
    }

    void Script::clear() {
        bytes.clear();
        operations.clear();
        cachedString.clear();
        parsed = true;
    }

    bool Script::execute(ScriptContext& context) const {
        parse();
        context.reset();
        
        for (size_t i = 0; i < operations.size(); i++) {
            OpCode op = operations[i];
            
            if (!executeOp(op, context)) {
                return false;
            }
            
            if (context.opCount++ > MAX_OP_COUNT) {
                context.setError("Too many operations");
                return false;
            }
        }
        
        return context.valid;
    }

    bool Script::executeOp(OpCode op, ScriptContext& context) const {
        // Constants
        if (op >= OpCode::OP_1 && op <= OpCode::OP_16) {
            uint8_t num = static_cast<uint8_t>(op) - static_cast<uint8_t>(OpCode::OP_1) + 1;
            context.stack.push_back(StackItem(num));
            return true;
        }
        
        switch (op) {
            // Stack operations
            case OpCode::OP_DUP: {
                if (context.stack.empty()) {
                    context.setError("Stack empty for DUP");
                    return false;
                }
                context.stack.push_back(context.stack.back());
                break;
            }
            
            case OpCode::OP_DROP: {
                if (context.stack.empty()) {
                    context.setError("Stack empty for DROP");
                    return false;
                }
                context.stack.pop_back();
                break;
            }
            
            case OpCode::OP_SWAP: {
                if (context.stack.size() < 2) {
                    context.setError("Stack too small for SWAP");
                    return false;
                }
                std::swap(context.stack[context.stack.size() - 2], 
                         context.stack.back());
                break;
            }
            
            case OpCode::OP_ROT: {
                if (context.stack.size() < 3) {
                    context.setError("Stack too small for ROT");
                    return false;
                }
                auto it = context.stack.end() - 3;
                std::rotate(it, it + 1, context.stack.end());
                break;
            }
            
            case OpCode::OP_2DUP: {
                if (context.stack.size() < 2) {
                    context.setError("Stack too small for 2DUP");
                    return false;
                }
                auto a = *(context.stack.end() - 2);
                auto b = context.stack.back();
                context.stack.push_back(a);
                context.stack.push_back(b);
                break;
            }
            
            case OpCode::OP_2DROP: {
                if (context.stack.size() < 2) {
                    context.setError("Stack too small for 2DROP");
                    return false;
                }
                context.stack.pop_back();
                context.stack.pop_back();
                break;
            }
            
            // Arithmetic operations
            case OpCode::OP_ADD: {
                if (context.stack.size() < 2) {
                    context.setError("Stack too small for ADD");
                    return false;
                }
                auto b = context.stack.back().getNumber();
                context.stack.pop_back();
                auto a = context.stack.back().getNumber();
                context.stack.pop_back();
                context.stack.push_back(StackItem(a + b));
                break;
            }
            
            case OpCode::OP_SUB: {
                if (context.stack.size() < 2) {
                    context.setError("Stack too small for SUB");
                    return false;
                }
                auto b = context.stack.back().getNumber();
                context.stack.pop_back();
                auto a = context.stack.back().getNumber();
                context.stack.pop_back();
                context.stack.push_back(StackItem(a - b));
                break;
            }
            
            case OpCode::OP_MUL: {
                if (context.stack.size() < 2) {
                    context.setError("Stack too small for MUL");
                    return false;
                }
                auto b = context.stack.back().getNumber();
                context.stack.pop_back();
                auto a = context.stack.back().getNumber();
                context.stack.pop_back();
                context.stack.push_back(StackItem(a * b));
                break;
            }
            
            case OpCode::OP_DIV: {
                if (context.stack.size() < 2) {
                    context.setError("Stack too small for DIV");
                    return false;
                }
                auto b = context.stack.back().getNumber();
                if (b == 0) {
                    context.setError("Division by zero");
                    return false;
                }
                context.stack.pop_back();
                auto a = context.stack.back().getNumber();
                context.stack.pop_back();
                context.stack.push_back(StackItem(a / b));
                break;
            }
            
            case OpCode::OP_MOD: {
                if (context.stack.size() < 2) {
                    context.setError("Stack too small for MOD");
                    return false;
                }
                auto b = context.stack.back().getNumber();
                if (b == 0) {
                    context.setError("Modulo by zero");
                    return false;
                }
                context.stack.pop_back();
                auto a = context.stack.back().getNumber();
                context.stack.pop_back();
                context.stack.push_back(StackItem(a % b));
                break;
            }
            
            case OpCode::OP_NEGATE: {
                if (context.stack.empty()) {
                    context.setError("Stack empty for NEGATE");
                    return false;
                }
                auto a = context.stack.back().getNumber();
                context.stack.pop_back();
                context.stack.push_back(StackItem(-a));
                break;
            }
            
            case OpCode::OP_ABS: {
                if (context.stack.empty()) {
                    context.setError("Stack empty for ABS");
                    return false;
                }
                auto a = context.stack.back().getNumber();
                context.stack.pop_back();
                context.stack.push_back(StackItem(std::abs(a)));
                break;
            }
            
            // Comparison operations
            case OpCode::OP_EQUAL:
            case OpCode::OP_EQUALVERIFY: {
                if (context.stack.size() < 2) {
                    context.setError("Stack too small for EQUAL");
                    return false;
                }
                auto a = context.stack.back();
                context.stack.pop_back();
                auto b = context.stack.back();
                context.stack.pop_back();
                
                bool equal = (a.data == b.data);
                context.stack.push_back(StackItem(equal ? 1 : 0));
                
                if (op == OpCode::OP_EQUALVERIFY) {
                    if (!equal) {
                        context.setError("EQUALVERIFY failed");
                        return false;
                    }
                    context.stack.pop_back();
                }
                break;
            }
            
            case OpCode::OP_LESSTHAN: {
                if (context.stack.size() < 2) {
                    context.setError("Stack too small for LESSTHAN");
                    return false;
                }
                auto b = context.stack.back().getNumber();
                context.stack.pop_back();
                auto a = context.stack.back().getNumber();
                context.stack.pop_back();
                context.stack.push_back(StackItem(a < b ? 1 : 0));
                break;
            }
            
            case OpCode::OP_GREATERTHAN: {
                if (context.stack.size() < 2) {
                    context.setError("Stack too small for GREATERTHAN");
                    return false;
                }
                auto b = context.stack.back().getNumber();
                context.stack.pop_back();
                auto a = context.stack.back().getNumber();
                context.stack.pop_back();
                context.stack.push_back(StackItem(a > b ? 1 : 0));
                break;
            }
            
            // Cryptographic operations
            case OpCode::OP_SHA256: {
                if (context.stack.empty()) {
                    context.setError("Stack empty for SHA256");
                    return false;
                }
                auto data = context.stack.back().data;
                context.stack.pop_back();
                
                std::string input(data.begin(), data.end());
                std::string hash = SHA256::hash(input);
                context.stack.push_back(StackItem(hash));
                break;
            }
            
            case OpCode::OP_HASH160: {
                if (context.stack.empty()) {
                    context.setError("Stack empty for HASH160");
                    return false;
                }
                auto data = context.stack.back().data;
                context.stack.pop_back();
                
                // SHA256 then RIPEMD160
                std::string input(data.begin(), data.end());
                std::string sha256 = SHA256::hash(input);
                std::string ripemd160 = RIPEMD160::hash(sha256);
                context.stack.push_back(StackItem(ripemd160));
                break;
            }
            
            case OpCode::OP_HASH256: {
                if (context.stack.empty()) {
                    context.setError("Stack empty for HASH256");
                    return false;
                }
                auto data = context.stack.back().data;
                context.stack.pop_back();
                
                std::string input(data.begin(), data.end());
                std::string hash = SHA256::doubleHash(input);
                context.stack.push_back(StackItem(hash));
                break;
            }
            
            case OpCode::OP_CHECKSIG:
            case OpCode::OP_CHECKSIGVERIFY: {
                if (context.stack.size() < 2) {
                    context.setError("Stack too small for CHECKSIG");
                    return false;
                }
                
                auto pubKey = context.stack.back().data;
                context.stack.pop_back();
                auto signature = context.stack.back().data;
                context.stack.pop_back();
                
                // Create signature hash from transaction
                std::string message = context.txHash + std::to_string(context.inputIndex);
                
                Secp256k1 secp256k1;
                bool valid = secp256k1.verify(message, signature, pubKey);
                
                context.stack.push_back(StackItem(valid ? 1 : 0));
                
                if (op == OpCode::OP_CHECKSIGVERIFY) {
                    if (!valid) {
                        context.setError("CHECKSIGVERIFY failed");
                        return false;
                    }
                    context.stack.pop_back();
                }
                break;
            }
            
            case OpCode::OP_CHECKMULTISIG:
            case OpCode::OP_CHECKMULTISIGVERIFY: {
                if (context.stack.size() < 3) {
                    context.setError("Stack too small for CHECKMULTISIG");
                    return false;
                }
                
                // Get number of public keys
                auto nKeysItem = context.stack.back();
                context.stack.pop_back();
                int nKeys = nKeysItem.getNumber();
                
                if (nKeys <= 0 || nKeys > MAX_MULTISIG_PUBKEYS) {
                    context.setError("Invalid number of public keys");
                    return false;
                }
                
                // Get public keys
                std::vector<std::vector<uint8_t>> pubKeys;
                for (int i = 0; i < nKeys; i++) {
                    if (context.stack.empty()) {
                        context.setError("Not enough public keys");
                        return false;
                    }
                    pubKeys.push_back(context.stack.back().data);
                    context.stack.pop_back();
                }
                
                // Get number of signatures
                auto nSigsItem = context.stack.back();
                context.stack.pop_back();
                int nSigs = nSigsItem.getNumber();
                
                if (nSigs <= 0 || nSigs > nKeys) {
                    context.setError("Invalid number of signatures");
                    return false;
                }
                
                // Get signatures
                std::vector<std::vector<uint8_t>> signatures;
                for (int i = 0; i < nSigs; i++) {
                    if (context.stack.empty()) {
                        context.setError("Not enough signatures");
                        return false;
                    }
                    signatures.push_back(context.stack.back().data);
                    context.stack.pop_back();
                }
                
                // Remove dummy element (required for Bitcoin compatibility)
                if (!context.stack.empty()) {
                    context.stack.pop_back();
                }
                
                // Verify signatures
                std::string message = context.txHash + std::to_string(context.inputIndex);
                Secp256k1 secp256k1;
                
                size_t sigIndex = 0;
                bool valid = true;
                
                for (size_t keyIndex = 0; keyIndex < pubKeys.size() && sigIndex < signatures.size(); keyIndex++) {
                    if (secp256k1.verify(message, signatures[sigIndex], pubKeys[keyIndex])) {
                        sigIndex++;
                    }
                }
                
                valid = (sigIndex >= static_cast<size_t>(nSigs));
                context.stack.push_back(StackItem(valid ? 1 : 0));
                
                if (op == OpCode::OP_CHECKMULTISIGVERIFY) {
                    if (!valid) {
                        context.setError("CHECKMULTISIGVERIFY failed");
                        return false;
                    }
                    context.stack.pop_back();
                }
                break;
            }
            
            // Flow control
            case OpCode::OP_IF:
            case OpCode::OP_NOTIF: {
                if (context.stack.empty()) {
                    context.setError("Stack empty for IF");
                    return false;
                }
                
                auto condition = context.stack.back().getNumber();
                context.stack.pop_back();
                
                bool execute = (condition != 0);
                if (op == OpCode::OP_NOTIF) {
                    execute = !execute;
                }
                
                // Skip if condition is false
                if (!execute) {
                    int depth = 1;
                    while (depth > 0 && context.pc < operations.size() - 1) {
                        context.pc++;
                        OpCode nextOp = operations[context.pc];
                        
                        if (nextOp == OpCode::OP_IF || nextOp == OpCode::OP_NOTIF) {
                            depth++;
                        } else if (nextOp == OpCode::OP_ENDIF) {
                            depth--;
                        }
                    }
                }
                break;
            }
            
            case OpCode::OP_ELSE: {
                // Skip to ENDIF
                int depth = 1;
                while (depth > 0 && context.pc < operations.size() - 1) {
                    context.pc++;
                    OpCode nextOp = operations[context.pc];
                    
                    if (nextOp == OpCode::OP_IF || nextOp == OpCode::OP_NOTIF) {
                        depth++;
                    } else if (nextOp == OpCode::OP_ENDIF) {
                        depth--;
                    }
                }
                break;
            }
            
            case OpCode::OP_ENDIF: {
                // Nothing to do
                break;
            }
            
            case OpCode::OP_VERIFY: {
                if (context.stack.empty()) {
                    context.setError("Stack empty for VERIFY");
                    return false;
                }
                
                auto value = context.stack.back().getNumber();
                context.stack.pop_back();
                
                if (value == 0) {
                    context.setError("VERIFY failed");
                    return false;
                }
                break;
            }
            
            case OpCode::OP_RETURN: {
                context.setError("RETURN encountered");
                return false;
            }
            
            // Lock time operations
            case OpCode::OP_CHECKLOCKTIMEVERIFY: {
                if (context.stack.empty()) {
                    context.setError("Stack empty for CHECKLOCKTIMEVERIFY");
                    return false;
                }
                
                auto lockTime = context.stack.back().getNumber();
                
                // Check against transaction lock time
                if (static_cast<uint32_t>(lockTime) > context.lockTime) {
                    context.setError("CHECKLOCKTIMEVERIFY failed");
                    return false;
                }
                break;
            }
            
            case OpCode::OP_CHECKSEQUENCEVERIFY: {
                if (context.stack.empty()) {
                    context.setError("Stack empty for CHECKSEQUENCEVERIFY");
                    return false;
                }
                
                // TODO: Implement sequence verification
                break;
            }
            
            // Power Coin advanced operations
            case OpCode::OP_SMARTCONTRACT: {
                // Smart contract execution stub
                if (context.stack.empty()) {
                    context.setError("Stack empty for SMARTCONTRACT");
                    return false;
                }
                // TODO: Implement smart contract execution
                break;
            }
            
            case OpCode::OP_STEALTHADDRESS: {
                // Stealth address handling
                if (context.stack.size() < 2) {
                    context.setError("Stack too small for STEALTHADDRESS");
                    return false;
                }
                // TODO: Implement stealth address verification
                break;
            }
            
            case OpCode::OP_ZKSNARK: {
                // Zero-knowledge proof verification
                if (context.stack.size() < 2) {
                    context.setError("Stack too small for ZKSNARK");
                    return false;
                }
                // TODO: Implement zk-SNARK verification
                break;
            }
            
            case OpCode::OP_CROSSCHAIN: {
                // Cross-chain verification
                if (context.stack.empty()) {
                    context.setError("Stack empty for CROSSCHAIN");
                    return false;
                }
                // TODO: Implement cross-chain verification
                break;
            }
            
            case OpCode::OP_GOVERNANCE: {
                // Governance voting verification
                if (context.stack.size() < 2) {
                    context.setError("Stack too small for GOVERNANCE");
                    return false;
                }
                // TODO: Implement governance verification
                break;
            }
            
            default:
                // Unsupported opcode
                context.setError("Unsupported opcode: " + std::to_string(static_cast<uint8_t>(op)));
                return false;
        }
        
        return true;
    }

    std::vector<uint8_t> Script::castToBytes(int64_t n) const {
        if (n == 0) return {};
        
        std::vector<uint8_t> bytes;
        uint64_t absN = std::abs(n);
        
        while (absN > 0) {
            bytes.push_back(absN & 0xff);
            absN >>= 8;
        }
        
        // Add sign bit if negative
        if (n < 0) {
            if (!bytes.empty()) {
                bytes.back() |= 0x80;
            }
        }
        
        return bytes;
    }

    int64_t Script::castToNumber(const std::vector<uint8_t>& data) const {
        if (data.empty()) return 0;
        
        int64_t n = 0;
        for (size_t i = 0; i < data.size(); i++) {
            n |= (static_cast<int64_t>(data[i] & 0x7f) << (i * 8));
        }
        
        // Check sign bit
        if (!data.empty() && (data.back() & 0x80)) {
            n = -n;
        }
        
        return n;
    }

    bool Script::checkMinimalEncoding(const std::vector<uint8_t>& data) const {
        // Check for minimal number encoding
        if (data.empty()) return true;
        
        if (data.size() > 4) return false;
        
        if ((data.back() & 0x7f) == 0) {
            if (data.size() == 1 || (data[data.size() - 2] & 0x80) == 0) {
                return false;
            }
        }
        
        return true;
    }

    std::string Script::getHex() const {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (auto byte : bytes) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }

    std::string Script::toString() const {
        if (!cachedString.empty()) return cachedString;
        
        parse();
        std::stringstream ss;
        
        for (size_t i = 0; i < operations.size(); i++) {
            if (i > 0) ss << " ";
            ss << getOpName(operations[i]);
        }
        
        cachedString = ss.str();
        return cachedString;
    }

    void Script::print() const {
        std::cout << toString() << std::endl;
    }

    std::string Script::getOpName(OpCode op) const {
        switch (op) {
            case OpCode::OP_0: return "OP_0";
            case OpCode::OP_PUSHDATA1: return "OP_PUSHDATA1";
            case OpCode::OP_PUSHDATA2: return "OP_PUSHDATA2";
            case OpCode::OP_PUSHDATA4: return "OP_PUSHDATA4";
            case OpCode::OP_1NEGATE: return "OP_1NEGATE";
            case OpCode::OP_1: return "OP_1";
            case OpCode::OP_2: return "OP_2";
            case OpCode::OP_3: return "OP_3";
            case OpCode::OP_4: return "OP_4";
            case OpCode::OP_5: return "OP_5";
            case OpCode::OP_6: return "OP_6";
            case OpCode::OP_7: return "OP_7";
            case OpCode::OP_8: return "OP_8";
            case OpCode::OP_9: return "OP_9";
            case OpCode::OP_10: return "OP_10";
            case OpCode::OP_11: return "OP_11";
            case OpCode::OP_12: return "OP_12";
            case OpCode::OP_13: return "OP_13";
            case OpCode::OP_14: return "OP_14";
            case OpCode::OP_15: return "OP_15";
            case OpCode::OP_16: return "OP_16";
            case OpCode::OP_NOP: return "OP_NOP";
            case OpCode::OP_IF: return "OP_IF";
            case OpCode::OP_NOTIF: return "OP_NOTIF";
            case OpCode::OP_ELSE: return "OP_ELSE";
            case OpCode::OP_ENDIF: return "OP_ENDIF";
            case OpCode::OP_VERIFY: return "OP_VERIFY";
            case OpCode::OP_RETURN: return "OP_RETURN";
            case OpCode::OP_TOALTSTACK: return "OP_TOALTSTACK";
            case OpCode::OP_FROMALTSTACK: return "OP_FROMALTSTACK";
            case OpCode::OP_IFDUP: return "OP_IFDUP";
            case OpCode::OP_DEPTH: return "OP_DEPTH";
            case OpCode::OP_DROP: return "OP_DROP";
            case OpCode::OP_DUP: return "OP_DUP";
            case OpCode::OP_NIP: return "OP_NIP";
            case OpCode::OP_OVER: return "OP_OVER";
            case OpCode::OP_PICK: return "OP_PICK";
            case OpCode::OP_ROLL: return "OP_ROLL";
            case OpCode::OP_ROT: return "OP_ROT";
            case OpCode::OP_SWAP: return "OP_SWAP";
            case OpCode::OP_TUCK: return "OP_TUCK";
            case OpCode::OP_2DROP: return "OP_2DROP";
            case OpCode::OP_2DUP: return "OP_2DUP";
            case OpCode::OP_3DUP: return "OP_3DUP";
            case OpCode::OP_2OVER: return "OP_2OVER";
            case OpCode::OP_2ROT: return "OP_2ROT";
            case OpCode::OP_2SWAP: return "OP_2SWAP";
            case OpCode::OP_CAT: return "OP_CAT";
            case OpCode::OP_SUBSTR: return "OP_SUBSTR";
            case OpCode::OP_LEFT: return "OP_LEFT";
            case OpCode::OP_RIGHT: return "OP_RIGHT";
            case OpCode::OP_SIZE: return "OP_SIZE";
            case OpCode::OP_INVERT: return "OP_INVERT";
            case OpCode::OP_AND: return "OP_AND";
            case OpCode::OP_OR: return "OP_OR";
            case OpCode::OP_XOR: return "OP_XOR";
            case OpCode::OP_EQUAL: return "OP_EQUAL";
            case OpCode::OP_EQUALVERIFY: return "OP_EQUALVERIFY";
            case OpCode::OP_1ADD: return "OP_1ADD";
            case OpCode::OP_1SUB: return "OP_1SUB";
            case OpCode::OP_2MUL: return "OP_2MUL";
            case OpCode::OP_2DIV: return "OP_2DIV";
            case OpCode::OP_NEGATE: return "OP_NEGATE";
            case OpCode::OP_ABS: return "OP_ABS";
            case OpCode::OP_NOT: return "OP_NOT";
            case OpCode::OP_0NOTEQUAL: return "OP_0NOTEQUAL";
            case OpCode::OP_ADD: return "OP_ADD";
            case OpCode::OP_SUB: return "OP_SUB";
            case OpCode::OP_MUL: return "OP_MUL";
            case OpCode::OP_DIV: return "OP_DIV";
            case OpCode::OP_MOD: return "OP_MOD";
            case OpCode::OP_LSHIFT: return "OP_LSHIFT";
            case OpCode::OP_RSHIFT: return "OP_RSHIFT";
            case OpCode::OP_BOOLAND: return "OP_BOOLAND";
            case OpCode::OP_BOOLOR: return "OP_BOOLOR";
            case OpCode::OP_NUMEQUAL: return "OP_NUMEQUAL";
            case OpCode::OP_NUMEQUALVERIFY: return "OP_NUMEQUALVERIFY";
            case OpCode::OP_NUMNOTEQUAL: return "OP_NUMNOTEQUAL";
            case OpCode::OP_LESSTHAN: return "OP_LESSTHAN";
            case OpCode::OP_GREATERTHAN: return "OP_GREATERTHAN";
            case OpCode::OP_LESSTHANOREQUAL: return "OP_LESSTHANOREQUAL";
            case OpCode::OP_GREATERTHANOREQUAL: return "OP_GREATERTHANOREQUAL";
            case OpCode::OP_MIN: return "OP_MIN";
            case OpCode::OP_MAX: return "OP_MAX";
            case OpCode::OP_WITHIN: return "OP_WITHIN";
            case OpCode::OP_RIPEMD160: return "OP_RIPEMD160";
            case OpCode::OP_SHA1: return "OP_SHA1";
            case OpCode::OP_SHA256: return "OP_SHA256";
            case OpCode::OP_HASH160: return "OP_HASH160";
            case OpCode::OP_HASH256: return "OP_HASH256";
            case OpCode::OP_CODESEPARATOR: return "OP_CODESEPARATOR";
            case OpCode::OP_CHECKSIG: return "OP_CHECKSIG";
            case OpCode::OP_CHECKSIGVERIFY: return "OP_CHECKSIGVERIFY";
            case OpCode::OP_CHECKMULTISIG: return "OP_CHECKMULTISIG";
            case OpCode::OP_CHECKMULTISIGVERIFY: return "OP_CHECKMULTISIGVERIFY";
            case OpCode::OP_CHECKLOCKTIMEVERIFY: return "OP_CHECKLOCKTIMEVERIFY";
            case OpCode::OP_CHECKSEQUENCEVERIFY: return "OP_CHECKSEQUENCEVERIFY";
            case OpCode::OP_SMARTCONTRACT: return "OP_SMARTCONTRACT";
            case OpCode::OP_STEALTHADDRESS: return "OP_STEALTHADDRESS";
            case OpCode::OP_RINGCT: return "OP_RINGCT";
            case OpCode::OP_BULLETPROOF: return "OP_BULLETPROOF";
            case OpCode::OP_ZKSNARK: return "OP_ZKSNARK";
            case OpCode::OP_MERKLEPROOF: return "OP_MERKLEPROOF";
            case OpCode::OP_CROSSCHAIN: return "OP_CROSSCHAIN";
            case OpCode::OP_GOVERNANCE: return "OP_GOVERNANCE";
            case OpCode::OP_STAKE: return "OP_STAKE";
            default: return "OP_UNKNOWN";
        }
    }

    Script Script::createPayToPubKey(const std::vector<uint8_t>& pubKey) {
        Script script;
        script.pushData(pubKey);
        script.pushOp(OpCode::OP_CHECKSIG);
        return script;
    }

    Script Script::createPayToPubKeyHash(const std::string& address) {
        auto hash160 = decodeAddress(address);
        Script script;
        script.pushOp(OpCode::OP_DUP);
        script.pushOp(OpCode::OP_HASH160);
        script.pushData(hash160);
        script.pushOp(OpCode::OP_EQUALVERIFY);
        script.pushOp(OpCode::OP_CHECKSIG);
        return script;
    }

    Script Script::createPayToScriptHash(const std::string& scriptHash) {
        Script script;
        script.pushOp(OpCode::OP_HASH160);
        script.pushData(scriptHash);
        script.pushOp(OpCode::OP_EQUAL);
        return script;
    }

    Script Script::createMultiSig(uint32_t required, const std::vector<std::vector<uint8_t>>& pubKeys) {
        if (required > pubKeys.size() || pubKeys.size() > MAX_MULTISIG_PUBKEYS) {
            return Script();
        }
        
        Script script;
        script.pushNumber(required);
        
        for (const auto& key : pubKeys) {
            script.pushData(key);
        }
        
        script.pushNumber(pubKeys.size());
        script.pushOp(OpCode::OP_CHECKMULTISIG);
        return script;
    }

    Script Script::createNullData(const std::string& data) {
        Script script;
        script.pushOp(OpCode::OP_RETURN);
        script.pushData(data);
        return script;
    }

    Script Script::createSmartContract(const std::string& bytecode) {
        Script script;
        script.pushOp(OpCode::OP_SMARTCONTRACT);
        script.pushData(bytecode);
        return script;
    }

    Script Script::createStealthAddress(const std::string& stealthAddress) {
        Script script;
        script.pushOp(OpCode::OP_STEALTHADDRESS);
        script.pushData(stealthAddress);
        return script;
    }

    Script Script::createGovernanceVote(const std::string& proposal, bool support) {
        Script script;
        script.pushOp(OpCode::OP_GOVERNANCE);
        script.pushData(proposal);
        script.pushBool(support);
        return script;
    }

    Script Script::createCrossChainLock(const std::string& chain, const std::string& txid) {
        Script script;
        script.pushOp(OpCode::OP_CROSSCHAIN);
        script.pushData(chain);
        script.pushData(txid);
        return script;
    }

    bool Script::isPushOnly(const std::vector<uint8_t>& script) {
        size_t i = 0;
        while (i < script.size()) {
            uint8_t op = script[i];
            
            if (op > static_cast<uint8_t>(OpCode::OP_16)) {
                return false;
            }
            
            if (op <= static_cast<uint8_t>(OpCode::OP_PUSHDATA4)) {
                // Handle push operations
                if (op == static_cast<uint8_t>(OpCode::OP_PUSHDATA1)) {
                    if (i + 1 >= script.size()) return false;
                    i += 1 + script[i + 1];
                } else if (op == static_cast<uint8_t>(OpCode::OP_PUSHDATA2)) {
                    if (i + 2 >= script.size()) return false;
                    uint16_t len = static_cast<uint16_t>(script[i + 1]) |
                                  (static_cast<uint16_t>(script[i + 2]) << 8);
                    i += 2 + len;
                } else if (op == static_cast<uint8_t>(OpCode::OP_PUSHDATA4)) {
                    if (i + 4 >= script.size()) return false;
                    uint32_t len = static_cast<uint32_t>(script[i + 1]) |
                                  (static_cast<uint32_t>(script[i + 2]) << 8) |
                                  (static_cast<uint32_t>(script[i + 3]) << 16) |
                                  (static_cast<uint32_t>(script[i + 4]) << 24);
                    i += 4 + len;
                } else if (op <= 0x4b) {
                    i += 1 + op;
                }
            } else {
                i++;
            }
        }
        
        return true;
    }

    std::string Script::encodeAddress(const std::vector<uint8_t>& hash160) {
        std::vector<uint8_t> data;
        data.push_back(0x00); // Mainnet version
        data.insert(data.end(), hash160.begin(), hash160.end());
        
        // Add checksum (first 4 bytes of double SHA256)
        std::string dataStr(data.begin(), data.end());
        std::string checksum = SHA256::doubleHash(dataStr);
        
        for (int i = 0; i < 4; i++) {
            data.push_back(static_cast<uint8_t>(checksum[i]));
        }
        
        // TODO: Base58 encode
        return "PWR" + std::string(data.begin(), data.end());
    }

    std::vector<uint8_t> Script::decodeAddress(const std::string& address) {
        // TODO: Implement Base58 decoding
        std::vector<uint8_t> result(20, 0);
        return result;
    }

    uint32_t Script::getSigOpCount(const std::vector<uint8_t>& script) {
        uint32_t count = 0;
        size_t i = 0;
        
        while (i < script.size()) {
            OpCode op = static_cast<OpCode>(script[i]);
            
            if (op == OpCode::OP_CHECKSIG || op == OpCode::OP_CHECKSIGVERIFY) {
                count++;
            } else if (op == OpCode::OP_CHECKMULTISIG || op == OpCode::OP_CHECKMULTISIGVERIFY) {
                count += 20; // Maximum possible
            }
            
            i++;
        }
        
        return count;
    }

    // ============== ScriptMachine Implementation ==============

    ScriptMachine::ScriptMachine() : initialized(false) {}

    ScriptMachine::ScriptMachine(const Script& s) 
        : script(std::make_unique<Script>(s)), initialized(true) {}

    ScriptMachine::~ScriptMachine() = default;

    bool ScriptMachine::initialize(const Script& s) {
        script = std::make_unique<Script>(s);
        initialized = true;
        return true;
    }

    bool ScriptMachine::execute() {
        if (!initialized || !script) {
            return false;
        }
        
        return script->execute(context);
    }

    bool ScriptMachine::step() {
        if (!initialized || !script) {
            return false;
        }
        
        // Single step execution
        return false;
    }

    void ScriptMachine::reset() {
        context.reset();
    }

} // namespace powercoin