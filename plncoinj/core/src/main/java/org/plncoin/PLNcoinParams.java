package org.plncoin;

import com.google.bitcoin.core.*;
import com.google.bitcoin.script.Script;
import com.google.bitcoin.script.ScriptOpCodes;
import com.lambdaworks.crypto.SCrypt;
import org.spongycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;

import static com.google.common.base.Preconditions.checkState;

/**
 * Parameters for the testnet, a separate public instance of Bitcoin that has relaxed rules suitable for development
 * and testing of applications and new Bitcoin versions.
 */
public class PLNcoinParams extends NetworkParameters {
    public PLNcoinParams() {
        super();
        id = "org.plncoin.production";
        proofOfWorkLimit = Utils.decodeCompactBits(0x1e0ffff0);
        addressHeader = 22;
        acceptableAddressCodes = new int[] { 22 };
        port = 9334;
        packetMagic = 0xfbc0b6db;
        dumpedPrivateKeyHeader = 128 + addressHeader;

        targetTimespan = 4 * 60 * 60;
        interval = 1 * 60;

        genesisBlock.setDifficultyTarget(0x1e0ffff0L);
        genesisBlock.setTime(1394716143);
        genesisBlock.setNonce(949591);
        genesisBlock.removeTransaction(0);
        Transaction t = new Transaction(this);
        try {
            // A script containing the difficulty bits and the following
            // message:
            //
            //   "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
            byte[] bytes = Hex.decode
                    ("04ffff001d01042d30362f30352f32303134204e415343415220447269766572204a6f73682057697365206f6e20446f6765636172");
            t.addInput(new TransactionInput(this, t, bytes));
            ByteArrayOutputStream scriptPubKeyBytes = new ByteArrayOutputStream();
            Script.writeBytes(scriptPubKeyBytes, Hex.decode
                    ("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9"));
            scriptPubKeyBytes.write(ScriptOpCodes.OP_CHECKSIG);
            t.addOutput(new TransactionOutput(this, t, Utils.toNanoCoins(44, 0), scriptPubKeyBytes.toByteArray()));
        } catch (Exception e) {
            // Cannot happen.
            throw new RuntimeException(e);
        }
        genesisBlock.addTransaction(t);
        String genesisHash = genesisBlock.getHashAsString();
        checkState(genesisHash.equals("2ffbf36d8fe734317177ece5e985a7fc651735ff6a9e7503d86a28d31376db9c"),
                genesisBlock);

        subsidyDecreaseBlockCount = 100000000;

        dnsSeeds = new String[] {
                "seed.plncoin.org"
        };
    }

    private static BigInteger MAX_MONEY = Utils.COIN.multiply(BigInteger.valueOf(100000000));
    @Override
    public BigInteger getMaxMoney() { return MAX_MONEY; }

    private static PLNcoinParams instance;
    public static synchronized PLNcoinParams get() {
        if (instance == null) {
            instance = new PLNcoinParams();
        }
        return instance;
    }

    /** The number of previous blocks to look at when calculating the next Block's difficulty */
    @Override
    public int getRetargetBlockCount(StoredBlock cursor) {
        if (cursor.getHeight() + 1 != getInterval()) {
            //Logger.getLogger("wallet_ltc").info("Normal LTC retarget");
            return getInterval();
        } else {
            //Logger.getLogger("wallet_ltc").info("Genesis LTC retarget");
            return getInterval() - 1;
        }
    }

    @Override public String getURIScheme() { return "plncoin:"; }

    /** Gets the hash of the given block for the purpose of checking its PoW */
    public Sha256Hash calculateBlockPoWHash(Block b) {
        byte[] blockHeader = b.cloneAsHeader().bitcoinSerialize();
        try {
            return new Sha256Hash(Utils.reverseBytes(SCrypt.scrypt(blockHeader, blockHeader, 1024, 1, 1, 32)));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    static {
        NetworkParameters.registerParams(get());
        NetworkParameters.PROTOCOL_VERSION = 70002;
    }
}
