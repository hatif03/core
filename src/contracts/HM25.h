using namespace QPI;

struct BridgeOrder {
    uint32 orderId;
    id sender;
    string destChain;
    string destAddress;
    int64 amount;
    bool completed;
    string ethTxHash;
};

static const uint32 MAX_ORDERS = 1000;
static const uint32 MAX_VALIDATORS = 10;
static const uint32 MAX_EVENTS = 1000;
static const uint32 MAX_MESSAGES = 100;

struct BridgeContract : public ContractBase {
public:
    // Input/Output structures for contract calls
    struct CreateOrder_input {
        string destChain;
        string destAddress;
        int64 amount;
    };
    struct CreateOrder_output {
        uint32 orderId;
    };

    struct SendMessage_input {
        string destChain;
        string destAddress;
        string payload;
    };
    struct SendMessage_output {
        uint64 messageId;
    };

    struct CompleteOrder_input {
        uint32 orderId;
        string ethTxHash;
        uint8 sigCount;
        // Each signature consists of (r, s, v) components (e.g. ECDSA signature parts)
        struct Signature { uint256 r; uint256 s; uint8 v; };
        Signature signatures[MAX_VALIDATORS];
    };
    struct CompleteOrder_output {};  // no output needed

    struct ReleaseTokens_input {
        string srcChain;
        string ethTxHash;
        id recipient;
        int64 amount;
        uint8 sigCount;
        struct Signature { uint256 r; uint256 s; uint8 v; };
        Signature signatures[MAX_VALIDATORS];
    };
    struct ReleaseTokens_output {};

    struct ExecuteMessage_input {
        string srcChain;
        string srcTxHash;
        id dest;
        string payload;
        uint8 sigCount;
        struct Signature { uint256 r; uint256 s; uint8 v; };
        Signature signatures[MAX_VALIDATORS];
    };
    struct ExecuteMessage_output {};

private:
    // State variables
    uint32 nextOrderId;
    uint64 nextMessageId;
    int64 lockedSupply;                       // total QU locked in this contract
    BridgeOrder orders[MAX_ORDERS];
    uint32 orderCount;
    string validators[MAX_VALIDATORS];
    uint8 validatorsCount;
    uint8 threshold;
    string processedEvents[MAX_EVENTS];       // record of processed event IDs (to prevent replays)
    uint32 processedEventCount;
    struct DeliveredMessage {                // record for delivered incoming messages
        string srcChain;
        id dest;
        string payload;
    };
    DeliveredMessage deliveredMessages[MAX_MESSAGES];
    uint32 deliveredCount;

    PUBLIC_PROCEDURE(CreateOrder)
        // User initiates a bridge order by sending QU to this contract
        // Require a positive amount and that the attached QU equals the specified amount
        if (input.amount <= 0 || qpi.invocationReward() < input.amount) {
            return;  // invalid amount or insufficient attached funds
        }
        if (qpi.invocationReward() > input.amount) {
            // Burn any excess tokens sent beyond the specified amount (no extra tokens should be sent)
            qpi.burn(qpi.invocationReward() - input.amount);
        }
        if (state.orderCount >= MAX_ORDERS) {
            return;  // storage full (should not happen in normal use)
        }
        // Create and store the new bridge order
        BridgeOrder &order = state.orders[state.orderCount];
        order.orderId      = state.nextOrderId;
        order.sender       = qpi.originator();          // Qubic address of the user
        order.destChain    = input.destChain;
        order.destAddress  = input.destAddress;
        order.amount       = input.amount;
        order.completed    = false;
        order.ethTxHash    = "";                        // no Ethereum tx yet
        // Update order counters and locked token balance
        state.orderCount++;
        state.nextOrderId++;
        state.lockedSupply += input.amount;             // keep track of locked QU
        // Return the new Order ID to the caller
        output.orderId = order.orderId;
    _

    PUBLIC_PROCEDURE(SendMessage)
        // User sends a generic cross-chain message. No QU should be attached for messages.
        if (qpi.invocationReward() > 0) {
            qpi.burn(qpi.invocationReward());  // burn any tokens mistakenly sent with the message
        }
        if (state.deliveredCount >= MAX_MESSAGES) {
            return;  // message buffer full (for simplicity, we drop if capacity exceeded)
        }
        // Assign a new message ID (for reference) and return it
        uint64 msgId = state.nextMessageId;
        state.nextMessageId++;
        output.messageId = msgId;
        // (Relayers will pick up this payload and deliver it to destChain:destAddress off-chain)
    _

    PUBLIC_PROCEDURE(CompleteOrder)
        // Finalize an outgoing token bridge after Ethereum mint. Called by relayers with attestation.
        if (qpi.invocationReward() > 0) {
            qpi.burn(qpi.invocationReward());  // no tokens should accompany this call
        }
        // Validate order existence and status
        if (input.orderId >= state.nextOrderId) {
            return;  // invalid order ID
        }
        BridgeOrder &order = state.orders[input.orderId - 1];
        if (order.completed) {
            return;  // order already completed
        }
        // Prepare the hash of the event that was signed by relayers (e.g. hash(orderId + ethTxHash))
        // id messageHash = qpi.K12(<orderId, ethTxHash data>);  // Pseudocode for computing a hash
        // Verify the relayer signatures (M-of-N multisig check)
        if (input.sigCount < state.threshold || input.sigCount > state.validatorsCount) {
            return;  // not enough signatures provided
        }
        uint8 validCount = 0;
        bool usedValidator[MAX_VALIDATORS] = {false};
        for (uint8 i = 0; i < input.sigCount; ++i) {
            // Recover the signer's address from the signature (pseudo-code, using ECDSA recovery)
            // string signer = ecrecover(messageHash, input.signatures[i].v, input.signatures[i].r, input.signatures[i].s);
            string signer = "0x0";  // placeholder for recovered signer address
            // Check if signer is an authorized validator and not already counted
            for (uint8 j = 0; j < state.validatorsCount; ++j) {
                if (!usedValidator[j] && signer == state.validators[j]) {
                    usedValidator[j] = true;
                    validCount++;
                    break;
                }
            }
        }
        if (validCount < state.threshold) {
            return;  // signatures did not meet the threshold
        }
        // Mark the order as completed and record the Ethereum transaction hash
        order.completed = true;
        order.ethTxHash = input.ethTxHash;
        // (The QU remains locked in this contract until a corresponding burn on Ethereum triggers release)
    _

    PUBLIC_PROCEDURE(ReleaseTokens)
        // Release locked QU to a user on Qubic after a burn on the source chain (Ethereum).
        if (qpi.invocationReward() > 0) {
            qpi.burn(qpi.invocationReward());
        }
        // Prevent replay: ensure this Ethereum event (ethTxHash) hasn’t been processed before
        for (uint32 i = 0; i < state.processedEventCount; ++i) {
            if (state.processedEvents[i] == input.ethTxHash) {
                return;  // event already processed
            }
        }
        // Verify relayer signatures on the burn event (e.g. hash(srcChain + recipient + amount + ethTxHash))
        // id messageHash = qpi.K12(<srcChain, recipient, amount, txHash>);  // Pseudocode for hash
        if (input.sigCount < state.threshold || input.sigCount > state.validatorsCount) {
            return;
        }
        uint8 validCount2 = 0;
        bool usedVal[MAX_VALIDATORS] = {false};
        for (uint8 i = 0; i < input.sigCount; ++i) {
            string signer = "0x0";  // placeholder for recovered signer address
            for (uint8 j = 0; j < state.validatorsCount; ++j) {
                if (!usedVal[j] && signer == state.validators[j]) {
                    usedVal[j] = true;
                    validCount2++;
                    break;
                }
            }
        }
        if (validCount2 < state.threshold) {
            return;  // not enough valid signatures
        }
        // All good – transfer the tokens to the recipient on Qubic
        if (input.amount > state.lockedSupply) {
            return;  // safety check, should not happen (insufficient reserve)
        }
        state.lockedSupply -= input.amount;
        qpi.transfer(input.recipient, input.amount);
        // Record this event as processed to avoid double-release
        if (state.processedEventCount < MAX_EVENTS) {
            state.processedEvents[state.processedEventCount++] = input.ethTxHash;
        }
    _

    PUBLIC_PROCEDURE(ExecuteMessage)
        // Deliver an incoming cross-chain message to a Qubic address (contract or user).
        if (qpi.invocationReward() > 0) {
            qpi.burn(qpi.invocationReward());
        }
        // Prevent replay of the same message event
        for (uint32 i = 0; i < state.processedEventCount; ++i) {
            if (state.processedEvents[i] == input.srcTxHash) {
                return;
            }
        }
        // Verify the signatures on the message payload (e.g. hash(srcChain + srcTxHash + dest + payload))
        if (input.sigCount < state.threshold || input.sigCount > state.validatorsCount) {
            return;
        }
        uint8 validCount3 = 0;
        bool usedVal2[MAX_VALIDATORS] = {false};
        for (uint8 i = 0; i < input.sigCount; ++i) {
            string signer = "0x0";  // placeholder for recovered signer
            for (uint8 j = 0; j < state.validatorsCount; ++j) {
                if (!usedVal2[j] && signer == state.validators[j]) {
                    usedVal2[j] = true;
                    validCount3++;
                    break;
                }
            }
        }
        if (validCount3 < state.threshold) {
            return;
        }
        // Store the message for the destination address
        if (state.deliveredCount < MAX_MESSAGES) {
            DeliveredMessage &msg = state.deliveredMessages[state.deliveredCount];
            msg.srcChain = input.srcChain;
            msg.dest     = input.dest;
            msg.payload  = input.payload;
            state.deliveredCount++;
        }
        // Mark this message event as processed
        if (state.processedEventCount < MAX_EVENTS) {
            state.processedEvents[state.processedEventCount++] = input.srcTxHash;
        }
        // (The target address can now retrieve or handle the payload as needed)
    _

    // Function registration
    REGISTER_USER_FUNCTIONS_AND_PROCEDURES
        REGISTER_USER_PROCEDURE(CreateOrder,    1);
        REGISTER_USER_PROCEDURE(SendMessage,    2);
        REGISTER_USER_PROCEDURE(CompleteOrder,  3);
        REGISTER_USER_PROCEDURE(ReleaseTokens,  4);
        REGISTER_USER_PROCEDURE(ExecuteMessage, 5);
    _

    INITIALIZE
        // Initialize state
        state.nextOrderId        = 1;
        state.nextMessageId      = 1;
        state.lockedSupply       = 0;
        state.orderCount         = 0;
        state.processedEventCount= 0;
        state.deliveredCount     = 0;
        // Setup validator set (N) and threshold (M)
        state.validatorsCount = 3;
        state.threshold       = 2;
        // Example validator addresses (to be replaced with actual relayer addresses)
        state.validators[0] = "0xAAAABBBBCCCCDDDDEEEEFFFF0000111122223333";
        state.validators[1] = "0x1111222233334444555566667777888899990000";
        state.validators[2] = "0xABCDEABCDEABCDEABCDEABCDEABCDEABCDE0000";
    _
};
