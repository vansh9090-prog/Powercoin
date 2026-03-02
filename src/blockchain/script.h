#ifndef POWERCOIN_SCRIPT_H
#define POWERCOIN_SCRIPT_H

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <map>

namespace powercoin {

    /**
     * Script opcodes (Bitcoin-compatible)
     */
    enum class OpCode : uint8_t {
        // Constants
        OP_0 = 0x00,
        OP_FALSE = 0x00,
        OP_PUSHDATA1 = 0x4c,
        OP_PUSHDATA2 = 0x4d,
        OP_PUSHDATA4 = 0x4e,
        OP_1NEGATE = 0x4f,
        OP_RESERVED = 0x50,
        OP_1 = 0x51,
        OP_TRUE = 0x51,
        OP_2 = 0x52,
        OP_3 = 0x53,
        OP_4 = 0x54,
        OP_5 = 0x55,
        OP_6 = 0x56,
        OP_7 = 0x57,
        OP_8 = 0x58,
        OP_9 = 0x59,
        OP_10 = 0x5a,
        OP_11 = 0x5b,
        OP_12 = 0x5c,
        OP_13 = 0x5d,
        OP_14 = 0x5e,
        OP_15 = 0x5f,
        OP_16 = 0x60,

        // Flow control
        OP_NOP = 0x61,
        OP_IF = 0x63,
        OP_NOTIF = 0x64,
        OP_ELSE = 0x67,
        OP_ENDIF = 0x68,
        OP_VERIFY = 0x69,
        OP_RETURN = 0x6a,

        // Stack operations
        OP_TOALTSTACK = 0x6b,
        OP_FROMALTSTACK = 0x6c,
        OP_IFDUP = 0x73,
        OP_DEPTH = 0x74,
        OP_DROP = 0x75,
        OP_DUP = 0x76,
        OP_NIP = 0x77,
        OP_OVER = 0x78,
        OP_PICK = 0x79,
        OP_ROLL = 0x7a,
        OP_ROT = 0x7b,
        OP_SWAP = 0x7c,
        OP_TUCK = 0x7d,
        OP_2DROP = 0x6d,
        OP_2DUP = 0x6e,
        OP_3DUP = 0x6f,
        OP_2OVER = 0x70,
        OP_2ROT = 0x71,
        OP_2SWAP = 0x72,

        // Splice operations
        OP_CAT = 0x7e,
        OP_SUBSTR = 0x7f,
        OP_LEFT = 0x80,
        OP_RIGHT = 0x81,
        OP_SIZE = 0x82,

        // Bitwise logic
        OP_INVERT = 0x83,
        OP_AND = 0x84,
        OP_OR = 0x85,
        OP_XOR = 0x86,
        OP_EQUAL = 0x87,
        OP_EQUALVERIFY = 0x88,

        // Arithmetic
        OP_1ADD = 0x8b,
        OP_1SUB = 0x8c,
        OP_2MUL = 0x8d,
        OP_2DIV = 0x8e,
        OP_NEGATE = 0x8f,
        OP_ABS = 0x90,
        OP_NOT = 0x91,
        OP_0NOTEQUAL = 0x92,
        OP_ADD = 0x93,
        OP_SUB = 0x94,
        OP_MUL = 0x95,
        OP_DIV = 0x96,
        OP_MOD = 0x97,
        OP_LSHIFT = 0x98,
        OP_RSHIFT = 0x99,
        OP_BOOLAND = 0x9a,
        OP_BOOLOR = 0x9b,
        OP_NUMEQUAL = 0x9c,
        OP_NUMEQUALVERIFY = 0x9d,
        OP_NUMNOTEQUAL = 0x9e,
        OP_LESSTHAN = 0x9f,
        OP_GREATERTHAN = 0xa0,
        OP_LESSTHANOREQUAL = 0xa1,
        OP_GREATERTHANOREQUAL = 0xa2,
        OP_MIN = 0xa3,
        OP_MAX = 0xa4,
        OP_WITHIN = 0xa5,

        // Crypto
        OP_RIPEMD160 = 0xa6,
        OP_SHA1 = 0xa7,
        OP_SHA256 = 0xa8,
        OP_HASH160 = 0xa9,
        OP_HASH256 = 0xaa,
        OP_CODESEPARATOR = 0xab,
        OP_CHECKSIG = 0xac,
        OP_CHECKSIGVERIFY = 0xad,
        OP_CHECKMULTISIG = 0xae,
        OP_CHECKMULTISIGVERIFY = 0xaf,

        // Reserved
        OP_CHECKLOCKTIMEVERIFY = 0xb1,
        OP_CHECKSEQUENCEVERIFY = 0xb2,

        // Advanced Power Coin operations
        OP_SMARTCONTRACT = 0xc0,
        OP_STEALTHADDRESS = 0xc1,
        OP_RINGCT = 0xc2,
        OP_BULLETPROOF = 0xc3,
        OP_ZKSNARK = 0xc4,
        OP_MERKLEPROOF = 0xc5,
        OP_CROSSCHAIN = 0xc6,
        OP_GOVERNANCE = 0xc7,
        OP_STAKE = 0xc8
    };

    /**
     * Script execution flags
     */
    enum ScriptFlags : uint32_t {
        SCRIPT_VERIFY_NONE = 0,
        SCRIPT_VERIFY_P2SH = (1U << 0),
        SCRIPT_VERIFY_STRICTENC = (1U << 1),
        SCRIPT_VERIFY_DERSIG = (1U << 2),
        SCRIPT_VERIFY_LOW_S = (1U << 3),
        SCRIPT_VERIFY_NULLDUMMY = (1U << 4),
        SCRIPT_VERIFY_SIGPUSHONLY = (1U << 5),
        SCRIPT_VERIFY_MINIMALDATA = (1U << 6),
        SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = (1U << 7),
        SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 8),
        SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1U << 9),
        SCRIPT_VERIFY_WITNESS = (1U << 10),
        SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = (1U << 11),
        SCRIPT_VERIFY_MINIMALIF = (1U << 12),
        SCRIPT_VERIFY_NULLFAIL = (1U << 13),
        SCRIPT_VERIFY_WITNESS_PUBKEYTYPE = (1U << 14),
        SCRIPT_VERIFY_CONST_SCRIPTCODE = (1U << 15),
        SCRIPT_VERIFY_TAPROOT = (1U << 16),
        
        // Power Coin specific
        SCRIPT_VERIFY_SMARTCONTRACT = (1U << 20),
        SCRIPT_VERIFY_PRIVACY = (1U << 21),
        SCRIPT_VERIFY_GOVERNANCE = (1U << 22)
    };

    /**
     * Script execution stack item
     */
    struct StackItem {
        std::vector<uint8_t> data;
        bool isNumber;
        
        StackItem() : isNumber(false) {}
        explicit StackItem(const std::vector<uint8_t>& d) : data(d), isNumber(false) {}
        explicit StackItem(const std::string& d) : data(d.begin(), d.end()), isNumber(false) {}
        explicit StackItem(uint64_t n);
        
        int64_t getNumber() const;
        std::string toString() const;
        size_t size() const { return data.size(); }
        bool empty() const { return data.empty(); }
        
        static StackItem fromNumber(int64_t n);
        static StackItem fromBool(bool b);
    };

    /**
     * Script execution context
     */
    struct ScriptContext {
        std::vector<StackItem> stack;
        std::vector<StackItem> altStack;
        std::map<uint32_t, StackItem> variables;
        uint32_t pc;  // Program counter
        uint32_t opCount;
        bool valid;
        std::string error;
        
        // Transaction context
        std::string txHash;
        uint32_t inputIndex;
        uint64_t amount;
        
        // Flags
        uint32_t flags;
        uint32_t version;
        
        ScriptContext();
        void reset();
        void setError(const std::string& err);
    };

    /**
     * Script types
     */
    enum class ScriptType {
        NONSTANDARD,
        PUBKEY,
        PUBKEYHASH,
        SCRIPTHASH,
        MULTISIG,
        NULLDATA,
        WITNESS_V0_KEYHASH,
        WITNESS_V0_SCRIPTHASH,
        WITNESS_V1_TAPROOT,
        
        // Power Coin specific
        SMART_CONTRACT,
        STEALTH_ADDRESS,
        GOVERNANCE_VOTE,
        CROSS_CHAIN_LOCK
    };

    /**
     * Main script class
     * Implements Bitcoin-compatible scripting system
     */
    class Script {
    private:
        std::vector<uint8_t> bytes;
        std::vector<OpCode> operations;
        mutable std::string cachedString;
        mutable bool parsed;
        
        void parse() const;
        bool executeOp(OpCode op, ScriptContext& context) const;
        
        // Stack operations
        bool stackPush(ScriptContext& context, const StackItem& item) const;
        bool stackPop(ScriptContext& context, StackItem& item) const;
        bool stackTop(ScriptContext& context, StackItem& item, size_t depth = 0) const;
        
        // Arithmetic helpers
        bool checkMinimalEncoding(const std::vector<uint8_t>& data) const;
        int64_t castToNumber(const std::vector<uint8_t>& data) const;
        std::vector<uint8_t> castToBytes(int64_t n) const;
        
        // Crypto helpers
        bool checkSignature(const std::vector<uint8_t>& signature,
                           const std::vector<uint8_t>& pubKey,
                           const std::string& message) const;
        bool checkMultiSignature(const std::vector<StackItem>& sigs,
                                const std::vector<StackItem>& keys,
                                const std::string& message) const;
        
    public:
        Script();
        explicit Script(const std::vector<uint8_t>& data);
        explicit Script(const std::string& hex);
        Script(const Script& other);
        Script& operator=(const Script& other);
        Script(Script&& other) noexcept;
        Script& operator=(Script&& other) noexcept;
        
        // Comparison
        bool operator==(const Script& other) const;
        bool operator!=(const Script& other) const;
        
        // Building
        void pushOp(OpCode op);
        void pushData(const std::vector<uint8_t>& data);
        void pushData(const std::string& data);
        void pushNumber(int64_t n);
        void pushBool(bool b);
        void clear();
        
        // Standard scripts
        static Script createPayToPubKey(const std::vector<uint8_t>& pubKey);
        static Script createPayToPubKeyHash(const std::string& address);
        static Script createPayToScriptHash(const std::string& scriptHash);
        static Script createMultiSig(uint32_t required, const std::vector<std::vector<uint8_t>>& pubKeys);
        static Script createNullData(const std::string& data);
        
        // Power Coin advanced scripts
        static Script createSmartContract(const std::string& bytecode);
        static Script createStealthAddress(const std::string& stealthAddress);
        static Script createGovernanceVote(const std::string& proposal, bool support);
        static Script createCrossChainLock(const std::string& chain, const std::string& txid);
        
        // Execution
        bool execute(ScriptContext& context) const;
        bool verify(const std::vector<uint8_t>& signature,
                   const std::vector<uint8_t>& pubKey,
                   const std::string& message) const;
        
        // Analysis
        ScriptType getType() const;
        bool isPayToPubKey() const;
        bool isPayToPubKeyHash() const;
        bool isPayToScriptHash() const;
        bool isMultiSig() const;
        bool isNullData() const;
        bool isWitness() const;
        
        // Getters
        const std::vector<uint8_t>& getBytes() const { return bytes; }
        std::string getHex() const;
        size_t size() const { return bytes.size(); }
        bool empty() const { return bytes.empty(); }
        
        // Utility
        std::string toString() const;
        void print() const;
        std::string getOpName(OpCode op) const;
        
        // Static helpers
        static bool isPushOnly(const std::vector<uint8_t>& script);
        static std::string encodeAddress(const std::vector<uint8_t>& hash160);
        static std::vector<uint8_t> decodeAddress(const std::string& address);
        static uint32_t getSigOpCount(const std::vector<uint8_t>& script);
        
        // Constants
        static constexpr uint32_t MAX_SCRIPT_SIZE = 10000;
        static constexpr uint32_t MAX_STACK_SIZE = 1000;
        static constexpr uint32_t MAX_OP_COUNT = 201;
        static constexpr uint32_t MAX_MULTISIG_PUBKEYS = 20;
    };

    /**
     * Script machine for advanced execution
     */
    class ScriptMachine {
    private:
        std::unique_ptr<Script> script;
        ScriptContext context;
        bool initialized;
        
    public:
        ScriptMachine();
        explicit ScriptMachine(const Script& s);
        ~ScriptMachine();
        
        bool initialize(const Script& s);
        bool execute();
        bool step();
        
        // Stack access
        std::vector<StackItem> getStack() const { return context.stack; }
        std::vector<StackItem> getAltStack() const { return context.altStack; }
        
        // Results
        bool success() const { return context.valid; }
        std::string getError() const { return context.error; }
        
        // Reset
        void reset();
    };

} // namespace powercoin

#endif // POWERCOIN_SCRIPT_H