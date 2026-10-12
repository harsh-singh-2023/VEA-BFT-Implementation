// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title VEABFTLedger
 * @notice On-chain ledger for VEA-BFT: Verifiable Encrypted Aggregation with a
 *         permissioned BFT validator set for privacy-preserving federated learning.
 *
 * What lives on-chain (and what does not)
 * ---------------------------------------
 *  - Ciphertexts and ZK proofs are LARGE, so they live in a content-addressed
 *    off-chain store (IPFS-style). The chain keeps their 32-byte keccak256 content
 *    ids, which makes every round replayable by an auditor.
 *  - PBFT (pre-prepare / prepare / commit / view-change) runs OFF-chain between the
 *    validators. The result is anchored here as a *quorum certificate* (QC): 2f+1
 *    distinct validator ECDSA signatures over the proposal digest. The contract
 *    re-derives everything it can cheaply check (inclusion set, sample count n_S,
 *    k_min, noise budget rule) and refuses a QC for a wrong proposal.
 *  - Per-hospital zero-knowledge proofs and the homomorphic re-computation are
 *    verified by the validators off-chain; the contract trusts the 2f+1 quorum
 *    (at least f+1 honest validators verified them, paper Section VI, P2/P3).
 *
 * Security goals mapped to code
 *  - P2 correctness / P3 robustness : finalizeRound (QC over inputsHash + aggHash)
 *  - P4 dynamic cohort              : beginRotation / ackReshare / CommitteeRotated
 *  - P5 noise integrity             : expectedBeta, finalizeRound budget checks, bootstrap
 */
contract VEABFTLedger {
    // ------------------------------------------------------------------ types
    enum RoundStatus { None, Open, Closed, Finalized, Aborted, Decrypted }

    struct Params {
        bytes32 pkHash;        // keccak256 of the Paillier modulus N (public key)
        bytes32 sharingRoot;   // hash of the genesis secret-sharing commitments
        uint256 normBound;     // B: L2 bound on a (quantized) update, in scaled integer units
        uint256 scale;         // s: quantization scale
        uint256 beta0;         // initial noise budget
        uint256 tau;           // noise-budget floor
        uint256 kMin;          // minimum participation count
        uint256 costScalarMul; // noise cost of one scalar multiplication n_i (.) ct_i
        uint256 costAdd;       // noise cost of one homomorphic addition
        bool excludePolicy;    // true = exclude-and-continue, false = abort
        bool carryBudget;      // true = budget is chained across rounds (deep computation mode)
    }

    struct Hospital {
        bool registered;
        bool active;
        uint256 nSamples;
    }

    struct Submission {
        bool exists;
        bytes32 ctHash;     // content id of the encrypted update blob
        bytes32 proofHash;  // content id of the proof blob
        uint64 time;
    }

    struct Round {
        RoundStatus status;
        uint256 viewNo;
        uint256 epoch;          // committee epoch used to decrypt
        uint256 nS;             // sum of n_i over the inclusion set
        uint256 beta;           // noise budget recorded for the round
        bytes32 inputsHash;
        bytes32 aggHash;        // content id of ct_Sigma blob
        bytes32 modelHash;      // content id of the published global model
        uint256 sharesPosted;
        uint64 openedAt;
    }

    struct Epoch {
        address[] members;
        uint256 threshold;
        bytes32 root;           // hash of verifiable resharing commitments
        uint256 acks;
        bool active;
    }

    struct FinalizeArgs {
        uint256 roundId;
        uint256 viewNo;
        address[] included;     // strictly ascending addresses
        bytes32 aggHash;
        uint256 betaNew;
    }

    // ------------------------------------------------------------------ constants
    bytes32 public constant DOMAIN_COMMIT = keccak256("VEABFT/COMMIT/v1");
    bytes32 public constant DOMAIN_ABORT = keccak256("VEABFT/ABORT/v1");
    bytes32 public constant DOMAIN_BOOTSTRAP = keccak256("VEABFT/BOOTSTRAP/v1");

    // ------------------------------------------------------------------ storage
    address public owner;
    bool public genesisDone;
    bool public committeeInstalled;
    Params public params;

    address[] public validators;
    mapping(address => uint256) private validatorIndex1; // 1-based
    uint256 public f;       // tolerated Byzantine validators
    uint256 public quorum;  // 2f + 1

    mapping(address => Hospital) public hospitals;
    address[] private hospitalList;
    bool public cohortChanged;

    uint256 public roundCounter;
    mapping(uint256 => Round) public rounds;
    mapping(uint256 => mapping(address => Submission)) private submissions;
    mapping(uint256 => address[]) private submitters;
    mapping(uint256 => mapping(address => bool)) private sharePosted;

    mapping(uint256 => Epoch) private epochs;
    mapping(uint256 => mapping(address => bool)) private acked;
    uint256 public currentEpoch;
    uint256 public pendingEpoch; // 0 = none

    uint256 public noiseBudget;
    uint256 public bootstrapNonce;

    // ------------------------------------------------------------------ events
    event GenesisInitialized(bytes32 pkHash, bytes32 sharingRoot, uint256 normBound, uint256 scale, uint256 beta0, uint256 tau, uint256 kMin, bool excludePolicy, uint256 validatorCount, uint256 f);
    event HospitalRegistered(address indexed hospital, uint256 nSamples);
    event HospitalRemoved(address indexed hospital);
    event CommitteeInstalled(uint256 indexed epoch, address[] members, uint256 threshold, bytes32 root);
    event RoundOpened(uint256 indexed roundId, uint256 epoch);
    event UpdateSubmitted(uint256 indexed roundId, address indexed hospital, bytes32 ctHash, bytes32 proofHash);
    event SubmissionsClosed(uint256 indexed roundId, uint256 submissionCount);
    event RoundFinalized(uint256 indexed roundId, uint256 viewNo, bytes32 inputsHash, bytes32 aggHash, uint256 nS, uint256 beta, uint256 included, uint256 signers);
    event RoundAborted(uint256 indexed roundId, uint256 viewNo, bytes32 reason, uint256 signers);
    event DecryptionSharePosted(uint256 indexed roundId, address indexed member, bytes32 shareHash);
    event ModelPublished(uint256 indexed roundId, bytes32 modelHash, uint256 epoch);
    event RotationStarted(uint256 indexed epoch, address[] members, uint256 threshold, bytes32 root);
    event ReshareAcked(uint256 indexed epoch, address indexed member);
    event CommitteeRotated(uint256 indexed epoch, address[] members, uint256 threshold, bytes32 root);
    event NoiseBudgetBootstrapped(uint256 nonce, uint256 newBudget, uint256 signers);

    // ------------------------------------------------------------------ modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }
    modifier onlyValidator() {
        require(validatorIndex1[msg.sender] != 0, "not validator");
        _;
    }
    modifier onlyActiveHospital() {
        require(hospitals[msg.sender].active, "not an active hospital");
        _;
    }
    modifier whenIdle() {
        RoundStatus s = rounds[roundCounter].status;
        require(
            roundCounter == 0 || s == RoundStatus.Decrypted || s == RoundStatus.Aborted,
            "round in progress"
        );
        _;
    }
    modifier inStatus(uint256 roundId, RoundStatus s) {
        require(rounds[roundId].status == s, "wrong round status");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // ------------------------------------------------------------------ genesis
    /// @notice One-shot genesis block: public key hash, norm bound B, scale s, budgets,
    ///         k_min, policy and the fixed validator set (n = 3f+1).
    function initGenesis(Params calldata p, address[] calldata vals) external onlyOwner {
        require(!genesisDone, "genesis done");
        uint256 n = vals.length;
        require(n >= 4 && (n - 1) % 3 == 0 && n <= 255, "validators must be 3f+1");
        require(p.kMin >= 1 && p.beta0 > p.tau && p.tau > 0, "bad params");
        for (uint256 i = 0; i < n; i++) {
            require(vals[i] != address(0) && validatorIndex1[vals[i]] == 0, "bad validator");
            validators.push(vals[i]);
            validatorIndex1[vals[i]] = i + 1;
        }
        f = (n - 1) / 3;
        quorum = 2 * f + 1;
        params = p;
        noiseBudget = p.beta0;
        genesisDone = true;
        emit GenesisInitialized(p.pkHash, p.sharingRoot, p.normBound, p.scale, p.beta0, p.tau, p.kMin, p.excludePolicy, n, f);
    }

    /// @notice Enrollment: sample counts n_i are registered up front (trusted, see paper VI).
    function registerHospital(address h, uint256 nSamples) external onlyOwner {
        require(genesisDone, "no genesis");
        require(h != address(0) && nSamples > 0, "bad hospital");
        require(!hospitals[h].active, "already active");
        if (committeeInstalled) {
            _requireIdle();
            cohortChanged = true;
        }
        if (!hospitals[h].registered) hospitalList.push(h);
        hospitals[h] = Hospital(true, true, nSamples);
        emit HospitalRegistered(h, nSamples);
    }

    /// @notice A hospital leaves. The committee must be rotated before the next round.
    function removeHospital(address h) external onlyOwner {
        require(hospitals[h].active, "not active");
        _requireIdle();
        hospitals[h].active = false;
        cohortChanged = true;
        emit HospitalRemoved(h);
    }

    /// @notice Install the genesis decryption committee (epoch 1), threshold t > m/2.
    function installCommittee(address[] calldata members, uint256 threshold, bytes32 root) external onlyOwner {
        require(genesisDone && !committeeInstalled, "bad state");
        _checkMembers(members, threshold);
        currentEpoch = 1;
        Epoch storage e = epochs[1];
        e.members = members;
        e.threshold = threshold;
        e.root = root;
        e.active = true;
        committeeInstalled = true;
        emit CommitteeInstalled(1, members, threshold, root);
    }

    // ------------------------------------------------------------------ round lifecycle
    function openRound() external onlyOwner whenIdle returns (uint256 roundId) {
        require(committeeInstalled, "no committee");
        require(!cohortChanged && pendingEpoch == 0, "rotate committee first");
        roundId = ++roundCounter;
        Round storage r = rounds[roundId];
        r.status = RoundStatus.Open;
        r.epoch = currentEpoch;
        r.openedAt = uint64(block.timestamp);
        emit RoundOpened(roundId, currentEpoch);
    }

    /// @notice A hospital commits (ct_i, pi_i) by content id. One submission per round.
    function submitUpdate(uint256 roundId, bytes32 ctHash, bytes32 proofHash)
        external
        onlyActiveHospital
        inStatus(roundId, RoundStatus.Open)
    {
        require(ctHash != bytes32(0) && proofHash != bytes32(0), "empty hash");
        Submission storage s = submissions[roundId][msg.sender];
        require(!s.exists, "already submitted");
        s.exists = true;
        s.ctHash = ctHash;
        s.proofHash = proofHash;
        s.time = uint64(block.timestamp);
        submitters[roundId].push(msg.sender);
        emit UpdateSubmitted(roundId, msg.sender, ctHash, proofHash);
    }

    /// @notice Any validator can close the submission window (no owner dependency).
    function closeSubmissions(uint256 roundId) external onlyValidator inStatus(roundId, RoundStatus.Open) {
        rounds[roundId].status = RoundStatus.Closed;
        emit SubmissionsClosed(roundId, submitters[roundId].length);
    }

    /// @notice Anchor the BFT decision for a round: 2f+1 validator signatures over the proposal.
    function finalizeRound(FinalizeArgs calldata a, bytes[] calldata sigs)
        external
        inStatus(a.roundId, RoundStatus.Closed)
    {
        (bytes32 inputsHash, uint256 nS) = _checkInclusion(a.roundId, a.included);
        _checkBudget(a.included.length, a.betaNew);

        bytes32 digest = proposalDigest(a.roundId, a.viewNo, inputsHash, a.aggHash, nS, a.betaNew);
        uint256 signers = _verifyQuorum(digest, sigs, a.viewNo);

        Round storage r = rounds[a.roundId];
        r.status = RoundStatus.Finalized;
        r.viewNo = a.viewNo;
        r.nS = nS;
        r.beta = a.betaNew;
        r.inputsHash = inputsHash;
        r.aggHash = a.aggHash;
        if (params.carryBudget) noiseBudget = a.betaNew;
        emit RoundFinalized(a.roundId, a.viewNo, inputsHash, a.aggHash, nS, a.betaNew, a.included.length, signers);
    }

    /// @dev Inclusion set rules: >= k_min, strictly ascending, every member submitted and is active.
    ///      Under the abort policy the primary may not censor, so every submission must be included.
    function _checkInclusion(uint256 roundId, address[] calldata included)
        internal
        view
        returns (bytes32 inputsHash, uint256 nS)
    {
        uint256 k = included.length;
        require(k >= params.kMin, "below k_min");
        bytes memory packed;
        for (uint256 i = 0; i < k; i++) {
            address h = included[i];
            if (i > 0) require(included[i - 1] < h, "included not ascending");
            Submission storage s = submissions[roundId][h];
            require(s.exists && hospitals[h].active, "included without submission");
            packed = abi.encodePacked(packed, h, s.ctHash, s.proofHash);
            nS += hospitals[h].nSamples;
        }
        if (!params.excludePolicy) require(k == submitters[roundId].length, "abort policy: must include all");
        inputsHash = keccak256(packed);
    }

    /// @dev P5: the proposed noise budget must equal the budget derived from ledger state
    ///      and must not fall below the floor tau.
    function _checkBudget(uint256 k, uint256 betaNew) internal view {
        uint256 base = params.carryBudget ? noiseBudget : params.beta0;
        uint256 cost = k * params.costScalarMul + (k - 1) * params.costAdd;
        require(base >= cost && base - cost >= params.tau, "noise budget below floor");
        require(betaNew == base - cost, "wrong noise budget");
    }

    /// @notice Abort policy / failed consensus: 2f+1 validators certify the round is aborted
    ///         and the global model w is left unchanged.
    function abortRound(uint256 roundId, uint256 viewNo, bytes32 reason, bytes[] calldata sigs) external {
        RoundStatus s = rounds[roundId].status;
        require(s == RoundStatus.Open || s == RoundStatus.Closed, "cannot abort");
        bytes32 digest = keccak256(abi.encode(DOMAIN_ABORT, block.chainid, address(this), roundId, viewNo, reason));
        uint256 signers = _verifyQuorum(digest, sigs, type(uint256).max);
        rounds[roundId].status = RoundStatus.Aborted;
        rounds[roundId].viewNo = viewNo;
        emit RoundAborted(roundId, viewNo, reason, signers);
    }

    // ------------------------------------------------------------------ decryption
    /// @notice A committee member of the round's epoch posts the hash of its (verifiable)
    ///         decryption share for ct_Sigma. Only ct_Sigma is ever decrypted.
    function postDecryptionShare(uint256 roundId, bytes32 shareHash) external inStatus(roundId, RoundStatus.Finalized) {
        require(_isMember(rounds[roundId].epoch, msg.sender), "not committee member");
        require(!sharePosted[roundId][msg.sender], "share already posted");
        sharePosted[roundId][msg.sender] = true;
        rounds[roundId].sharesPosted += 1;
        emit DecryptionSharePosted(roundId, msg.sender, shareHash);
    }

    /// @notice After t shares, a member publishes the content id of the updated global model.
    function publishModel(uint256 roundId, bytes32 modelHash) external inStatus(roundId, RoundStatus.Finalized) {
        Round storage r = rounds[roundId];
        require(_isMember(r.epoch, msg.sender), "not committee member");
        require(r.sharesPosted >= epochs[r.epoch].threshold, "threshold not reached");
        r.modelHash = modelHash;
        r.status = RoundStatus.Decrypted;
        emit ModelPublished(roundId, modelHash, r.epoch);
    }

    // ------------------------------------------------------------------ committee rotation (P4)
    /// @notice Start a rotation after the hospital cohort changed. The public key is unchanged;
    ///         old members reshare to the new committee off-chain with verifiable commitments
    ///         whose hash is `root`.
    function beginRotation(address[] calldata members, uint256 threshold, bytes32 root) external onlyOwner whenIdle {
        require(committeeInstalled && cohortChanged, "no cohort change");
        require(pendingEpoch == 0, "rotation pending");
        _checkMembers(members, threshold);
        uint256 id = currentEpoch + 1;
        Epoch storage e = epochs[id];
        e.members = members;
        e.threshold = threshold;
        e.root = root;
        pendingEpoch = id;
        emit RotationStarted(id, members, threshold, root);
    }

    /// @notice A new member confirms it received and verified its share. Once all new members
    ///         confirmed, the new epoch becomes active and the round gate re-opens.
    function ackReshare(uint256 epochId) external {
        require(epochId == pendingEpoch && epochId != 0, "no such pending epoch");
        require(_isMember(epochId, msg.sender), "not new member");
        require(!acked[epochId][msg.sender], "already acked");
        acked[epochId][msg.sender] = true;
        Epoch storage e = epochs[epochId];
        e.acks += 1;
        emit ReshareAcked(epochId, msg.sender);
        if (e.acks == e.members.length) {
            e.active = true;
            epochs[currentEpoch].active = false;
            currentEpoch = epochId;
            pendingEpoch = 0;
            cohortChanged = false;
            emit CommitteeRotated(epochId, e.members, e.threshold, e.root);
        }
    }

    // ------------------------------------------------------------------ noise budget (P5)
    /// @notice Bootstrapping as a validated action: 2f+1 validators certify a budget reset.
    function bootstrap(bytes[] calldata sigs) external whenIdle {
        bytes32 digest = keccak256(abi.encode(DOMAIN_BOOTSTRAP, block.chainid, address(this), bootstrapNonce));
        uint256 signers = _verifyQuorum(digest, sigs, type(uint256).max);
        bootstrapNonce += 1;
        noiseBudget = params.beta0;
        emit NoiseBudgetBootstrapped(bootstrapNonce - 1, params.beta0, signers);
    }

    // ------------------------------------------------------------------ views
    function proposalDigest(uint256 roundId, uint256 viewNo, bytes32 inputsHash, bytes32 aggHash, uint256 nS, uint256 betaNew)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(DOMAIN_COMMIT, block.chainid, address(this), roundId, viewNo, inputsHash, aggHash, nS, betaNew));
    }

    function abortDigest(uint256 roundId, uint256 viewNo, bytes32 reason) external view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_ABORT, block.chainid, address(this), roundId, viewNo, reason));
    }

    function bootstrapDigest() external view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_BOOTSTRAP, block.chainid, address(this), bootstrapNonce));
    }

    function primaryOf(uint256 viewNo) public view returns (address) {
        return validators[viewNo % validators.length];
    }

    /// @notice Noise budget a proposal over k inputs must carry, derived from ledger state.
    function expectedBeta(uint256 k) external view returns (uint256) {
        Params memory p = params;
        uint256 base = p.carryBudget ? noiseBudget : p.beta0;
        uint256 cost = k * p.costScalarMul + (k > 0 ? (k - 1) * p.costAdd : 0);
        return base >= cost ? base - cost : 0;
    }

    function getValidators() external view returns (address[] memory) {
        return validators;
    }

    function getHospitals() external view returns (address[] memory) {
        return hospitalList;
    }

    function getSubmitters(uint256 roundId) external view returns (address[] memory) {
        return submitters[roundId];
    }

    function getSubmission(uint256 roundId, address h) external view returns (Submission memory) {
        return submissions[roundId][h];
    }

    function getEpoch(uint256 epochId) external view returns (address[] memory members, uint256 threshold, bytes32 root, uint256 acks, bool active) {
        Epoch storage e = epochs[epochId];
        return (e.members, e.threshold, e.root, e.acks, e.active);
    }

    // ------------------------------------------------------------------ internals
    function _requireIdle() internal view {
        RoundStatus s = rounds[roundCounter].status;
        require(roundCounter == 0 || s == RoundStatus.Decrypted || s == RoundStatus.Aborted, "round in progress");
    }

    function _checkMembers(address[] calldata members, uint256 threshold) internal view {
        uint256 m = members.length;
        require(m >= 1 && threshold * 2 > m && threshold <= m, "need t > m/2");
        for (uint256 i = 0; i < m; i++) {
            require(hospitals[members[i]].active, "member not an active hospital");
            for (uint256 j = 0; j < i; j++) require(members[i] != members[j], "duplicate member");
        }
    }

    function _isMember(uint256 epochId, address who) internal view returns (bool) {
        address[] storage ms = epochs[epochId].members;
        for (uint256 i = 0; i < ms.length; i++) if (ms[i] == who) return true;
        return false;
    }

    /// @dev Count distinct validator signatures over `digest`. If `viewNo` is a real view, the
    ///      primary of that view must be among the signers (its pre-prepare is its vote).
    function _verifyQuorum(bytes32 digest, bytes[] calldata sigs, uint256 viewNo) internal view returns (uint256 count) {
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        uint256 seen;
        for (uint256 i = 0; i < sigs.length; i++) {
            address signer = _recover(ethHash, sigs[i]);
            uint256 idx = validatorIndex1[signer];
            require(idx != 0, "signer not validator");
            uint256 bit = 1 << (idx - 1);
            require(seen & bit == 0, "duplicate signer");
            seen |= bit;
            count++;
        }
        require(count >= quorum, "quorum not reached");
        if (viewNo != type(uint256).max) {
            uint256 pIdx = (viewNo % validators.length) + 1;
            require(seen & (1 << (pIdx - 1)) != 0, "primary of view did not sign");
        }
    }

    function _recover(bytes32 h, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig length");
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        if (v < 27) v += 27;
        require(
            uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
            "malleable signature"
        );
        address a = ecrecover(h, v, r, s);
        require(a != address(0), "bad signature");
        return a;
    }
}
