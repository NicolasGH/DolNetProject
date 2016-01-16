package com.blockparser.Testtt;

/**
 * Created by Nicolas on 16/01/16.
 */

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;


public class Block {
    private static final Logger log = LoggerFactory.getLogger(Block.class);
    private static final long serialVersionUID = 2738848929966035281L;

    /** How many bytes are required to represent a block header WITHOUT the trailing 00 length byte. */
    public static final int HEADER_SIZE = 80;

    static final long ALLOWED_TIME_DRIFT = 2 * 60 * 60; // Same value as official client.

    /**
     * A constant shared by the entire network: how large in bytes a block is allowed to be. One day we may have to
     * upgrade everyone to change this, so Bitcoin can continue to grow. For now it exists as an anti-DoS measure to
     * avoid somebody creating a titanically huge but valid block and forcing everyone to download/store it forever.
     */
    public static final int MAX_BLOCK_SIZE = 1 * 1000 * 1000;
    /**
     * A "sigop" is a signature verification operation. Because they're expensive we also impose a separate limit on
     * the number in a block to prevent somebody mining a huge block that has way more sigops than normal, so is very
     * expensive/slow to verify.
     */
    public static final int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE / 50;

    /** A value for difficultyTarget (nBits) that allows half of all possible hash solutions. Used in unit testing. */
    public static final long EASIEST_DIFFICULTY_TARGET = 0x207fFFFFL;

    // Fields defined as part of the protocol format.
    private long magicID;
    private long blockSize;
    private long version;
    private Sha256Hash prevBlockHash;
    private Sha256Hash merkleRoot;
    private long time;
    private long difficultyTarget; // "nBits"
    private long nonce;
    private BigInteger maxTarget;

    // TODO: Get rid of all the direct accesses to this field. It's a long-since unnecessary holdover from the Dalvik days.
    /** If null, it means this object holds only the headers. */
    @Nullable List<Transaction> transactions;

    /** Stores the hash of the block. If null, getHash() will recalculate it. */
    private transient Sha256Hash hash;

    private transient boolean headerParsed;
    private transient boolean transactionsParsed;

    private transient boolean headerBytesValid;
    private transient boolean transactionBytesValid;

    // Blocks can be encoded in a way that will use more bytes than is optimal (due to VarInts having multiple encodings)
    // MAX_BLOCK_SIZE must be compared to the optimal encoding, not the actual encoding, so when parsing, we keep track
    // of the size of the ideal encoding in addition to the actual message size (which Message needs)
    private transient int optimalEncodingMessageSize;




    /**
     * Construct a block initialized with all the given fields.
     * @param params Which network the block is for.
     * @param version This should usually be set to 1 or 2, depending on if the height is in the coinbase input.
     * @param prevBlockHash Reference to previous block in the chain or {@link Sha256Hash#ZERO_HASH} if genesis.
     * @param merkleRoot The root of the merkle tree formed by the transactions.
     * @param time UNIX time when the block was mined.
     * @param difficultyTarget Number which this block hashes lower than.
     * @param nonce Arbitrary number to make the block hash lower than the target.
     * @param transactions List of transactions including the coinbase.
     */
    public Block(long magicID, byte[] byteRawArray) {
        this.maxTarget = Utils.decodeCompactBits(0x1d00ffffL);
        this.magicID = magicID;
        this.blockSize = blockSize;
        this.version = version;
        this.prevBlockHash = prevBlockHash;
        this.merkleRoot = merkleRoot;
        this.time = time;
        this.difficultyTarget = difficultyTarget;
        this.nonce = nonce;
        this.transactions = new LinkedList<Transaction>();
        this.transactions.addAll(transactions);
    }




    private void readObject(ObjectInputStream ois) throws ClassNotFoundException, IOException {
        ois.defaultReadObject();
        // This code is not actually necessary, as transient fields are initialized to the default value which is in
        // this case null. However it clears out a FindBugs warning and makes it explicit what we're doing.
        hash = null;
    }

    protected void parseHeader() {
        if (headerParsed)
            return;

        //cursor = offset;
        version = readUint32();
        prevBlockHash = Sha256Hash.wrapReversed(readBytes(32));
        merkleRoot = Sha256Hash.wrapReversed(readBytes(32));
        time = readUint32();
        difficultyTarget = readUint32();
        nonce = readUint32();

        hash = Sha256Hash.wrapReversed(Sha256Hash.hashTwice(payload, offset, cursor));

        headerParsed = true;
        headerBytesValid = parseRetain;
    }

    long readUint32() {
        long u = Utils.readUint32(payload, cursor);
            cursor += 4;
            return u;
    }

    long readInt64() {
            long u = Utils.readInt64(payload, cursor);
            cursor += 8;
            return u;
    }

    BigInteger readUint64() {
        // Java does not have an unsigned 64 bit type. So scrape it off the wire then flip.
        return new BigInteger(Utils.reverseBytes(readBytes(8)));
    }

    long readVarInt(){
        return readVarInt(0);
    }

    long readVarInt(int offset)   {
            VarInt varint = new VarInt(payload, cursor + offset);
            cursor += offset + varint.getOriginalSizeInBytes();
            return varint.value;
    }

    byte[] readBytes(int length) {
        if (length > MAX_SIZE) {
             new Exception("Claimed value length too large: " + length);
        }

            byte[] b = new byte[length];
            System.arraycopy(payload, cursor, b, 0, length);
            cursor += length;
            return b;

    }

    byte[] readByteArray() {
        long len = readVarInt();
        return readBytes((int)len);
    }

    String readStr()  {
        long length = readVarInt();
        return length == 0 ? "" : Utils.toString(readBytes((int) length), "UTF-8"); // optimization for empty strings
    }

    org.bitcoinj.core.Sha256Hash readHash()  {
        // We have to flip it around, as it's been read off the wire in little endian.
        // Not the most efficient way to do this but the clearest.
        return Sha256Hash.wrapReversed(readBytes(32));
    }

    protected void parseTransactions() {
        if (transactionsParsed)
            return;

        cursor = offset + HEADER_SIZE;
        optimalEncodingMessageSize = HEADER_SIZE;
        if (payload.length == cursor) {
            // This message is just a header, it has no transactions.
            transactionsParsed = true;
            transactionBytesValid = false;
            return;
        }

        int numTransactions = (int) readVarInt();
        optimalEncodingMessageSize += VarInt.sizeOf(numTransactions);
        transactions = new ArrayList<Transaction>(numTransactions);
        for (int i = 0; i < numTransactions; i++) {
            Transaction tx = new Transaction(params, payload, cursor, this, parseLazy, parseRetain, UNKNOWN_LENGTH);
            // Label the transaction as coming from the P2P network, so code that cares where we first saw it knows.
            tx.getConfidence().setSource(TransactionConfidence.Source.NETWORK);
            transactions.add(tx);
            cursor += tx.getMessageSize();
            optimalEncodingMessageSize += tx.getOptimalEncodingMessageSize();
        }
        // No need to set length here. If length was not provided then it should be set at the end of parseLight().
        // If this is a genuine lazy parse then length must have been provided to the constructor.
        transactionsParsed = true;
        transactionBytesValid = parseRetain;
    }

    @Override
    void parse() {
        parseHeader();
        parseTransactions();
        length = cursor - offset;
    }

    public int getOptimalEncodingMessageSize() {
        if (optimalEncodingMessageSize != 0)
            return optimalEncodingMessageSize;
        maybeParseTransactions();
        if (optimalEncodingMessageSize != 0)
            return optimalEncodingMessageSize;
        optimalEncodingMessageSize = bitcoinSerialize().length;
        return optimalEncodingMessageSize;
    }

    @Override
    protected void parseLite() {
        // Ignore the header since it has fixed length. If length is not provided we will have to
        // invoke a light parse of transactions to calculate the length.
        if (length == UNKNOWN_LENGTH) {
            Preconditions.checkState(parseLazy,
                    "Performing lite parse of block transaction as block was initialised from byte array " +
                            "without providing length.  This should never need to happen.");
            parseTransactions();
            length = cursor - offset;
        } else {
            transactionBytesValid = !transactionsParsed || parseRetain && length > HEADER_SIZE;
        }
        headerBytesValid = !headerParsed || parseRetain && length >= HEADER_SIZE;
    }

    /*
     * Block uses some special handling for lazy parsing and retention of cached bytes. Parsing and serializing the
     * block header and the transaction list are both non-trivial so there are good efficiency gains to be had by
     * separating them. There are many cases where a user may need to access or change one or the other but not both.
     *
     * With this in mind we ignore the inherited checkParse() and unCache() methods and implement a separate version
     * of them for both header and transactions.
     *
     * Serializing methods are also handled in their own way. Whilst they deal with separate parts of the block structure
     * there are some interdependencies. For example altering a tx requires invalidating the Merkle root and therefore
     * the cached header bytes.
     */
    private void maybeParseHeader() {
        if (headerParsed || payload == null)
            return;
        try {
            parseHeader();
            if (!(headerBytesValid || transactionBytesValid))
                payload = null;
        } catch (ProtocolException e) {
            throw new LazyParseException(
                    "ProtocolException caught during lazy parse.  For safe access to fields call ensureParsed before attempting read or write access",
                    e);
        }
    }

    private void maybeParseTransactions() {
        if (transactionsParsed || payload == null)
            return;
        try {
            parseTransactions();
            if (!parseRetain) {
                transactionBytesValid = false;
                if (headerParsed)
                    payload = null;
            }
        } catch (ProtocolException e) {
            throw new LazyParseException(
                    "ProtocolException caught during lazy parse.  For safe access to fields call ensureParsed before attempting read or write access",
                    e);
        }
    }

    /**
     * Ensure the object is parsed if needed. This should be called in every getter before returning a value. If the
     * lazy parse flag is not set this is a method returns immediately.
     */
    @Override
    protected void maybeParse() {
        throw new LazyParseException(
                "checkParse() should never be called on a Block.  Instead use checkParseHeader() and checkParseTransactions()");
    }



    // default for testing
    void writeHeader(OutputStream stream) throws IOException {
        // try for cached write first
        if (headerBytesValid && payload != null && payload.length >= offset + HEADER_SIZE) {
            stream.write(payload, offset, HEADER_SIZE);
            return;
        }
        // fall back to manual write
        maybeParseHeader();
        org.bitcoinj.core.Utils.uint32ToByteStreamLE(version, stream);
        stream.write(prevBlockHash.getReversedBytes());
        stream.write(getMerkleRoot().getReversedBytes());
        org.bitcoinj.core.Utils.uint32ToByteStreamLE(time, stream);
        org.bitcoinj.core.Utils.uint32ToByteStreamLE(difficultyTarget, stream);
        org.bitcoinj.core.Utils.uint32ToByteStreamLE(nonce, stream);
    }

    private void writeTransactions(OutputStream stream) throws IOException {
        // check for no transaction conditions first
        // must be a more efficient way to do this but I'm tired atm.
        if (transactions == null && transactionsParsed) {
            return;
        }

        // confirmed we must have transactions either cached or as objects.
        if (transactionBytesValid && payload != null && payload.length >= offset + length) {
            stream.write(payload, offset + HEADER_SIZE, length - HEADER_SIZE);
            return;
        }

        if (transactions != null) {
            stream.write(new VarInt(transactions.size()).encode());
            for (Transaction tx : transactions) {
                tx.bitcoinSerialize(stream);
            }
        }
    }

    /**
     * Special handling to check if we have a valid byte array for both header
     * and transactions
     *
     * @throws IOException
     */
    @Override
    public byte[] bitcoinSerialize() {
        // we have completely cached byte array.
        if (headerBytesValid && transactionBytesValid) {
            Preconditions.checkNotNull(payload, "Bytes should never be null if headerBytesValid && transactionBytesValid");
            if (length == payload.length) {
                return payload;
            } else {
                // byte array is offset so copy out the correct range.
                byte[] buf = new byte[length];
                System.arraycopy(payload, offset, buf, 0, length);
                return buf;
            }
        }

        // At least one of the two cacheable components is invalid
        // so fall back to stream write since we can't be sure of the length.
        ByteArrayOutputStream stream = new UnsafeByteArrayOutputStream(length == UNKNOWN_LENGTH ? HEADER_SIZE + guessTransactionsLength() : length);
        try {
            writeHeader(stream);
            writeTransactions(stream);
        } catch (IOException e) {
            // Cannot happen, we are serializing to a memory stream.
        }
        return stream.toByteArray();
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        writeHeader(stream);
        // We may only have enough data to write the header.
        writeTransactions(stream);
    }

    /**
     * Provides a reasonable guess at the byte length of the transactions part of the block.
     * The returned value will be accurate in 99% of cases and in those cases where not will probably slightly
     * oversize.
     *
     * This is used to preallocate the underlying byte array for a ByteArrayOutputStream.  If the size is under the
     * real value the only penalty is resizing of the underlying byte array.
     */
    private int guessTransactionsLength() {
        if (transactionBytesValid)
            return payload.length - HEADER_SIZE;
        if (transactions == null)
            return 0;
        int len = VarInt.sizeOf(transactions.size());
        for (Transaction tx : transactions) {
            // 255 is just a guess at an average tx length
            len += tx.length == UNKNOWN_LENGTH ? 255 : tx.length;
        }
        return len;
    }

    @Override
    protected void unCache() {
        // Since we have alternate uncache methods to use internally this will only ever be called by a child
        // transaction so we only need to invalidate that part of the cache.
        unCacheTransactions();
    }

    private void unCacheHeader() {
        maybeParseHeader();
        headerBytesValid = false;
        if (!transactionBytesValid)
            payload = null;
        hash = null;
        checksum = null;
    }

    private void unCacheTransactions() {
        maybeParseTransactions();
        transactionBytesValid = false;
        if (!headerBytesValid)
            payload = null;
        // Current implementation has to uncache headers as well as any change to a tx will alter the merkle root. In
        // future we can go more granular and cache merkle root separately so rest of the header does not need to be
        // rewritten.
        unCacheHeader();
        // Clear merkleRoot last as it may end up being parsed during unCacheHeader().
        merkleRoot = null;
    }

    /**
     * Calculates the block hash by serializing the block and hashing the
     * resulting bytes.
     */
    private Sha256Hash calculateHash() {
        try {
            ByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(HEADER_SIZE);
            writeHeader(bos);
            return Sha256Hash.wrapReversed(Sha256Hash.hashTwice(bos.toByteArray()));
        } catch (IOException e) {
            throw new RuntimeException(e); // Cannot happen.
        }
    }

    /**
     * Returns the hash of the block (which for a valid, solved block should be below the target) in the form seen on
     * the block explorer. If you call this on block 1 in the mainnet chain
     * you will get "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048".
     */
    public String getHashAsString() {
        return getHash().toString();
    }

    /**
     * Returns the hash of the block (which for a valid, solved block should be
     * below the target). Big endian.
     */
    @Override
    public Sha256Hash getHash() {
        if (hash == null)
            hash = calculateHash();
        return hash;
    }

    /**
     * The number that is one greater than the largest representable SHA-256
     * hash.
     */
    private static BigInteger LARGEST_HASH = BigInteger.ONE.shiftLeft(256);

    /**
     * Returns the work represented by this block.<p>
     *
     * Work is defined as the number of tries needed to solve a block in the
     * average case. Consider a difficulty target that covers 5% of all possible
     * hash values. Then the work of the block will be 20. As the target gets
     * lower, the amount of work goes up.
     */
    public BigInteger getWork() {
        BigInteger target = getDifficultyTargetAsInteger();
        return LARGEST_HASH.divide(target.add(BigInteger.ONE));
    }

    /** Returns a copy of the block, but without any transactions. */
    public Block cloneAsHeader() {
        maybeParseHeader();
        Block block = new Block(params);
        copyBitcoinHeaderTo(block);
        return block;
    }

    /** Copy the block without transactions into the provided empty block. */
    protected final void copyBitcoinHeaderTo(final Block block) {
        block.nonce = nonce;
        block.prevBlockHash = prevBlockHash;
        block.merkleRoot = getMerkleRoot();
        block.version = version;
        block.time = time;
        block.difficultyTarget = difficultyTarget;
        block.transactions = null;
        block.hash = getHash();
    }

    /**
     * Returns a multi-line string containing a description of the contents of
     * the block. Use for debugging purposes only.
     */
    @Override
    public String toString() {
        StringBuilder s = new StringBuilder("v");
        s.append(version);
        s.append(" block: \n");
        s.append("   previous block: ").append(getPrevBlockHash()).append("\n");
        s.append("   merkle root: ").append(getMerkleRoot()).append("\n");
        s.append("   time: [").append(time).append("] ").append(org.bitcoinj.core.Utils.dateTimeFormat(time * 1000)).append("\n");
        s.append("   difficulty target (nBits): ").append(difficultyTarget).append("\n");
        s.append("   nonce: ").append(nonce).append("\n");
        if (transactions != null && transactions.size() > 0) {
            s.append("   with ").append(transactions.size()).append(" transaction(s):\n");
            for (Transaction tx : transactions) {
                s.append(tx);
            }
        }
        return s.toString();
    }

    /**
     * <p>Finds a value of nonce that makes the blocks hash lower than the difficulty target. This is called mining, but
     * solve() is far too slow to do real mining with. It exists only for unit testing purposes.
     *
     * <p>This can loop forever if a solution cannot be found solely by incrementing nonce. It doesn't change
     * extraNonce.</p>
     */
    public void solve() {
        maybeParseHeader();
        while (true) {
            try {
                // Is our proof of work valid yet?
                if (checkProofOfWork(false))
                    return;
                // No, so increment the nonce and try again.
                setNonce(getNonce() + 1);
            } catch (Exception e) {
                throw new RuntimeException(e); // Cannot happen.
            }
        }
    }

    /**
     * Returns the difficulty target as a 256 bit value that can be compared to a SHA-256 hash. Inside a block the
     * target is represented using a compact form. If this form decodes to a value that is out of bounds, an exception
     * is thrown.
     */
    public BigInteger getDifficultyTargetAsInteger() {
        maybeParseHeader();
        BigInteger target = org.bitcoinj.core.Utils.decodeCompactBits(difficultyTarget);
        if (target.signum() <= 0 || target.compareTo(params.maxTarget) > 0)
            new RuntimeException("Difficulty target is bad: " + target.toString());
        return target;
    }

    /** Returns true if the hash of the block is OK (lower than difficulty target). */
    protected boolean checkProofOfWork(boolean throwException)  {
        // This part is key - it is what proves the block was as difficult to make as it claims
        // to be. Note however that in the context of this function, the block can claim to be
        // as difficult as it wants to be .... if somebody was able to take control of our network
        // connection and fork us onto a different chain, they could send us valid blocks with
        // ridiculously easy difficulty and this function would accept them.
        //
        // To prevent this attack from being possible, elsewhere we check that the difficultyTarget
        // field is of the right value. This requires us to have the preceeding blocks.
        BigInteger target = getDifficultyTargetAsInteger();

        BigInteger h = getHash().toBigInteger();
        if (h.compareTo(target) > 0) {
            // Proof of work check failed!
            if (throwException)
                throw new VerificationException("Hash is higher than target: " + getHashAsString() + " vs "
                        + target.toString(16));
            else
                return false;
        }
        return true;
    }

    private void checkTimestamp() throws Exception {
        maybeParseHeader();
        // Allow injection of a fake clock to allow unit testing.
        long currentTime = org.bitcoinj.core.Utils.currentTimeSeconds();
        if (time > currentTime + ALLOWED_TIME_DRIFT)
            throw new Exception(String.format("Block too far in future: %d vs %d", time, currentTime + ALLOWED_TIME_DRIFT));
    }

    private void checkSigOps() throws Exception {
        // Check there aren't too many signature verifications in the block. This is an anti-DoS measure, see the
        // comments for MAX_BLOCK_SIGOPS.
        int sigOps = 0;
        for (Transaction tx : transactions) {
            sigOps += tx.getSigOpCount();
        }
        if (sigOps > MAX_BLOCK_SIGOPS)
            throw new Exception("Block had too many Signature Operations");
    }

    private void checkMerkleRoot() throws Exception {
        Sha256Hash calculatedRoot = calculateMerkleRoot();
        if (!calculatedRoot.equals(merkleRoot)) {
            log.error("Merkle tree did not verify");
            throw new Exception("Merkle hashes do not match: " + calculatedRoot + " vs " + merkleRoot);
        }
    }

    private Sha256Hash calculateMerkleRoot() {
        List<byte[]> tree = buildMerkleTree();
        return Sha256Hash.wrap(tree.get(tree.size() - 1));
    }

    private List<byte[]> buildMerkleTree() {
        maybeParseTransactions();
        ArrayList<byte[]> tree = new ArrayList<byte[]>();
        // Start by adding all the hashes of the transactions as leaves of the tree.
        for (Transaction t : transactions) {
            tree.add(t.getHash().getBytes());
        }
        int levelOffset = 0; // Offset in the list where the currently processed level starts.
        // Step through each level, stopping when we reach the root (levelSize == 1).
        for (int levelSize = transactions.size(); levelSize > 1; levelSize = (levelSize + 1) / 2) {
            // For each pair of nodes on that level:
            for (int left = 0; left < levelSize; left += 2) {
                // The right hand node can be the same as the left hand, in the case where we don't have enough
                // transactions.
                int right = Math.min(left + 1, levelSize - 1);
                byte[] leftBytes = Utils.reverseBytes(tree.get(levelOffset + left));
                byte[] rightBytes = Utils.reverseBytes(tree.get(levelOffset + right));
                tree.add(Utils.reverseBytes(Sha256Hash.hashTwice(leftBytes, 0, 32, rightBytes, 0, 32)));
            }
            // Move to the next level.
            levelOffset += levelSize;
        }
        return tree;
    }

    private void checkTransactions() throws Exception {
        // The first transaction in a block must always be a coinbase transaction.
        if (!transactions.get(0).isCoinBase())
            throw new Exception("First tx is not coinbase");
        // The rest must not be.
        for (int i = 1; i < transactions.size(); i++) {
            if (transactions.get(i).isCoinBase())
                throw new Exception("TX " + i + " is coinbase when it should not be.");
        }
    }

    /**
     * Checks the block data to ensure it follows the rules laid out in the network parameters. Specifically,
     * throws an exception if the proof of work is invalid, or if the timestamp is too far from what it should be.
     * This is <b>not</b> everything that is required for a block to be valid, only what is checkable independent
     * of the chain and without a transaction index.
     *
     * @throws VerificationException
     */
    public void verifyHeader() throws Exception {
        // Prove that this block is OK. It might seem that we can just ignore most of these checks given that the
        // network is also verifying the blocks, but we cannot as it'd open us to a variety of obscure attacks.
        //
        // Firstly we need to ensure this block does in fact represent real work done. If the difficulty is high
        // enough, it's probably been done by the network.
        maybeParseHeader();
        checkProofOfWork(true);
        checkTimestamp();
    }


    public void verifyTransactions() throws Exception {
        // Now we need to check that the body of the block actually matches the headers. The network won't generate
        // an invalid block, but if we didn't validate this then an untrusted man-in-the-middle could obtain the next
        // valid block from the network and simply replace the transactions in it with their own fictional
        // transactions that reference spent or non-existant inputs.
        if (transactions.isEmpty())
            throw new Exception("Block had no transactions");
        maybeParseTransactions();
        if (this.getOptimalEncodingMessageSize() > MAX_BLOCK_SIZE)
            throw new Exception("Block larger than MAX_BLOCK_SIZE");
        checkTransactions();
        checkMerkleRoot();
        checkSigOps();
        for (Transaction transaction : transactions)
            transaction.verify();
    }

    /**
     * Verifies both the header and that the transactions hash to the merkle root.
     */
    public void verify() throws Exception {
        verifyHeader();
        verifyTransactions();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Block other = (Block) o;
        return getHash().equals(other.getHash());
    }

    @Override
    public int hashCode() {
        return getHash().hashCode();
    }

    /**
     * Returns the merkle root in big endian form, calculating it from transactions if necessary.
     */
    public Sha256Hash getMerkleRoot() {
        maybeParseHeader();
        if (merkleRoot == null) {
            //TODO check if this is really necessary.
            unCacheHeader();
            merkleRoot = calculateMerkleRoot();
        }
        return merkleRoot;
    }

    /** Exists only for unit testing. */
    void setMerkleRoot(Sha256Hash value) {
        unCacheHeader();
        merkleRoot = value;
        hash = null;
    }

    /** Adds a transaction to this block. The nonce and merkle root are invalid after this. */

    /** Adds a transaction to this block, with or without checking the sanity of doing so */
    public void addTransaction(Transaction t) {
        unCacheTransactions();
        if (transactions == null) {
            transactions = new ArrayList<Transaction>();
        }
        transactions.add(t);
        // Force a recalculation next time the values are needed.
        merkleRoot = null;
        hash = null;
    }

    /** Returns the version of the block data structure as defined by the Bitcoin protocol. */
    public long getVersion() {
        maybeParseHeader();
        return version;
    }

    /**
     * Returns the hash of the previous block in the chain, as defined by the block header.
     */
    public Sha256Hash getPrevBlockHash() {
        maybeParseHeader();
        return prevBlockHash;
    }

    void setPrevBlockHash(Sha256Hash prevBlockHash) {
        unCacheHeader();
        this.prevBlockHash = prevBlockHash;
        this.hash = null;
    }

    /**
     * Returns the time at which the block was solved and broadcast, according to the clock of the solving node. This
     * is measured in seconds since the UNIX epoch (midnight Jan 1st 1970).
     */
    public long getTimeSeconds() {
        maybeParseHeader();
        return time;
    }

    /**
     * Returns the time at which the block was solved and broadcast, according to the clock of the solving node.
     */
    public Date getTime() {
        return new Date(getTimeSeconds()*1000);
    }

    public void setTime(long time) {
        unCacheHeader();
        this.time = time;
        this.hash = null;
    }

    /**
     * Returns the difficulty of the proof of work that this block should meet encoded <b>in compact form</b>. The {@link
     * BlockChain} verifies that this is not too easy by looking at the length of the chain when the block is added.
     * To find the actual value the hash should be compared against, use
     * {@link org.bitcoinj.core.Block#getDifficultyTargetAsInteger()}. Note that this is <b>not</b> the same as
     * the difficulty value reported by the Bitcoin "getdifficulty" RPC that you may see on various block explorers.
     * That number is the result of applying a formula to the underlying difficulty to normalize the minimum to 1.
     * Calculating the difficulty that way is currently unsupported.
     */
    public long getDifficultyTarget() {
        maybeParseHeader();
        return difficultyTarget;
    }

    /** Sets the difficulty target in compact form. */
    public void setDifficultyTarget(long compactForm) {
        unCacheHeader();
        this.difficultyTarget = compactForm;
        this.hash = null;
    }

    /**
     * Returns the nonce, an arbitrary value that exists only to make the hash of the block header fall below the
     * difficulty target.
     */
    public long getNonce() {
        maybeParseHeader();
        return nonce;
    }

    /** Sets the nonce and clears any cached data. */
    public void setNonce(long nonce) {
        unCacheHeader();
        this.nonce = nonce;
        this.hash = null;
    }

    /** Returns an immutable list of transactions held in this block, or null if this object represents just a header. */
    @Nullable
    public List<Transaction> getTransactions() {
        maybeParseTransactions();
        return transactions == null ? null : ImmutableList.copyOf(transactions);
    }




}
