/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record.crypto;

import static de.rub.nds.tlsattacker.core.util.LoggerPrintConverter.bytesToHexWithSpaces;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.RecordNullCipher;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordEncryptor extends Encryptor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsContext tlsContext;

    private final RecordNullCipher nullCipher;

    public RecordEncryptor(RecordCipher recordCipher, TlsContext tlsContext) {
        super(recordCipher);
        this.tlsContext = tlsContext;
        nullCipher = RecordCipherFactory.getNullCipher(tlsContext);
    }

    @Override
    public void encrypt(Record record) {
        LOGGER.debug("Encrypting Record:");
        RecordCipher recordCipher;
        if (tlsContext.getChooser().getSelectedProtocolVersion().isDTLS()) {
            recordCipher = getRecordCipher(record.getEpoch().getValue());
        } else {
            recordCipher = getRecordMostRecentCipher();
        }
        try {
            record.setSequenceNumber(
                    BigInteger.valueOf(recordCipher.getState().getWriteSequenceNumber()));
            recordCipher.encrypt(record);
            if (record.getUnifiedHeaderBitmask() != null) {
                // DTLS 1.3 with Unified Header
                encryptSequenceNumber(record);
            }
        } catch (CryptoException ex) {
            LOGGER.warn("Could not encrypt BlobRecord. Using NullCipher", ex);
            try {
                nullCipher.encrypt(record);
            } catch (CryptoException ex1) {
                LOGGER.error("Could not encrypt with NullCipher", ex1);
            }
        }
        recordCipher.getState().increaseWriteSequenceNumber();
        if (tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
            record.getComputations().setUsedTls13KeySetType(tlsContext.getActiveKeySetTypeWrite());
        }
    }

    private void encryptSequenceNumber(Record record) throws CryptoException {
        byte[] ciphertext = record.getProtocolMessageBytes().getValue();
        if (ciphertext.length < 16) {
            LOGGER.warn(
                    "Ciphertext too short for sequence number encryption (less than 16 bytes). Skipping.");
            return;
        }

        LOGGER.debug(
                "[DEBUG] Encrypting sequence number for record with epoch: {}",
                record.getEpoch().getValue());

        RecordCipher recordCipher = getRecordCipher(record.getEpoch().getValue());
        CipherSuite cipherSuite = recordCipher.getState().getCipherSuite();
        LOGGER.debug("[DEBUG] Using cipher suite: {}", cipherSuite.name());

        KeySet keySet = recordCipher.getState().getKeySet();
        ConnectionEndType localEndType = tlsContext.getConnection().getLocalConnectionEndType();
        byte[] snKey = keySet.getWriteSnKey(localEndType);

        if (snKey == null) {
            LOGGER.warn("[DEBUG] snKey is null! Sequence number will not be encrypted.");
            return;
        }

        LOGGER.debug("[DEBUG] snKey length: {}", snKey.length);
        LOGGER.debug("[DEBUG] snKey: {}", bytesToHexWithSpaces(snKey));

        byte[] firstBlock = Arrays.copyOfRange(ciphertext, 0, 16);
        LOGGER.debug("[DEBUG] First 16 bytes of ciphertext: {}", bytesToHexWithSpaces(firstBlock));

        byte[] mask;
        try {
            mask = generateAESMask(snKey, firstBlock);
            LOGGER.debug("[DEBUG] Generated mask: {}", bytesToHexWithSpaces(mask));

            int plainSeqNum = record.getSequenceNumberSuffix().getValue();
            LOGGER.debug("[DEBUG] Plain sequence number: {}", plainSeqNum);

            int encryptedSeqNum = plainSeqNum ^ (((mask[0] & 0xFF) << 8) | (mask[1] & 0xFF));
            LOGGER.debug("[DEBUG] Encrypted sequence number: {}", encryptedSeqNum);

            record.setSequenceNumberSuffix(encryptedSeqNum);
        } catch (Exception e) {
            LOGGER.error("[DEBUG] Failed to encrypt sequence number: ", e);
        }
    }

    private byte[] generateAESMask(byte[] key, byte[] data) throws CryptoException {
        try {
            LOGGER.debug("[DEBUG] Generating AES mask with key length: {}", key.length);
            LOGGER.debug("[DEBUG] Data length: {}", data.length);

            if (key.length != 16 && key.length != 24 && key.length != 32) {
                LOGGER.warn("Invalid AES key length: {}", key.length);
                byte[] adjustedKey = new byte[16];
                System.arraycopy(key, 0, adjustedKey, 0, Math.min(key.length, 16));
                key = adjustedKey;
            }

            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CryptoException("Failed to generate AES mask", e);
        }
    }
}
