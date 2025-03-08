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

import de.rub.nds.protocol.exception.EndOfStreamException;
import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordNullCipher;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordDecryptor extends Decryptor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsContext tlsContext;

    public RecordDecryptor(RecordCipher recordCipher, TlsContext tlsContext) {
        super(recordCipher);
        this.tlsContext = tlsContext;
    }

    @Override
    public void decrypt(Record record) throws ParserException {
        LOGGER.debug("Decrypting Record");
        RecordCipher recordCipher;
        if (tlsContext.getChooser().getSelectedProtocolVersion().isDTLS()
                && record.getEpoch() != null
                && record.getEpoch().getValue() != null) {
            recordCipher = getRecordCipher(record.getEpoch().getValue());
        } else {
            recordCipher = getRecordMostRecentCipher();
        }
        record.prepareComputations();
        if (tlsContext.getChooser().getHighestProtocolVersion().isDTLS13()
                && record.getUnifiedHeaderBitmask() != null) {
            try {
                decryptSequenceNumber(record, record.getProtocolMessageBytes().getValue());
                recordCipher.decrypt(record);
                recordCipher.getState().increaseReadSequenceNumber();
            } catch (CryptoException ex) {
                throw new ParserException(ex);
            }
        } else {
            ProtocolVersion version =
                    ProtocolVersion.getProtocolVersion(record.getProtocolVersion().getValue());
            if (version == null || !version.isDTLS()) {
                record.setSequenceNumber(
                        BigInteger.valueOf(recordCipher.getState().getReadSequenceNumber()));
            }

            try {
                if (!tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()
                        || record.getContentMessageType()
                                != ProtocolMessageType.CHANGE_CIPHER_SPEC) {
                    try {
                        recordCipher.decrypt(record);
                    } catch (ParserException | CryptoException | EndOfStreamException ex) {
                        if (recordCipherList.indexOf(recordCipher) > 0) {
                            LOGGER.warn(
                                    "Failed to decrypt record, will try to process with previous cipher");
                            recordCipherList
                                    .get(recordCipherList.indexOf(recordCipher) - 1)
                                    .decrypt(record);
                        }
                    }
                    recordCipher.getState().increaseReadSequenceNumber();
                } else {
                    LOGGER.debug("Skipping decryption for legacy CCS");
                    new RecordNullCipher(tlsContext, recordCipher.getState()).decrypt(record);
                }
            } catch (CryptoException ex) {
                throw new ParserException(ex);
            }
        }
    }

    private void decryptSequenceNumber(Record record, byte[] ciphertext) throws CryptoException {
        if (ciphertext.length < 16) {
            throw new CryptoException("Ciphertext too short for sequence number decryption");
        }

        RecordCipher recordCipher = getRecordCipher(record.getEpoch().getValue());
        CipherSuite cipherSuite = recordCipher.getState().getCipherSuite();
        LOGGER.debug(
                "[DEBUG] Decrypting sequence number for record with epoch: {}",
                record.getEpoch().getValue());
        LOGGER.debug("[DEBUG] Using cipher suite: {}", cipherSuite.name());

        byte[] mask;
        KeySet keySet = recordCipher.getState().getKeySet();
        ConnectionEndType localEndType = tlsContext.getConnection().getLocalConnectionEndType();
        LOGGER.debug("[DEBUG] Local connection end type: {}", localEndType);

        byte[] snKey = keySet.getReadSnKey(localEndType);
        if (snKey == null) {
            LOGGER.warn("[DEBUG] snKey is null! Sequence number key not set.");
            return;
        }

        LOGGER.debug("[DEBUG] snKey length: {}", snKey.length);
        LOGGER.debug("[DEBUG] snKey : {}", bytesToHexWithSpaces(snKey));

        if (cipherSuite.isAEAD()) {
            if (cipherSuite.getCipherAlgorithm().name().contains("CHACHA")) {
                byte[] counter = Arrays.copyOfRange(ciphertext, 0, 4);
                byte[] nonce = Arrays.copyOfRange(ciphertext, 4, 16);
                mask = generateChaCha20Mask(snKey, counter, nonce);
            } else {
                try {
                    mask = generateAESMask(snKey, Arrays.copyOfRange(ciphertext, 0, 16));
                } catch (Exception e) {
                    LOGGER.error("[DEBUG] Failed to generate AES mask: ", e);
                    return;
                }
            }
            LOGGER.debug("[DEBUG] mask: {}", bytesToHexWithSpaces(mask));

            int encryptedSeqNum = record.getSequenceNumberSuffix().getValue();
            LOGGER.debug("[DEBUG] encryptedSeqNum: {}", encryptedSeqNum);
            int decryptedSeqNum = encryptedSeqNum ^ (((mask[0] & 0xFF) << 8) | (mask[1] & 0xFF));
            LOGGER.debug("[DEBUG] decryptedSeqNum: {}", decryptedSeqNum);
            record.setSequenceNumberSuffix(decryptedSeqNum);
            // TODO: we may need to use another way to record the sequence number, since
            // SequenceNumberSuffix is only 2 bytes
            record.setSequenceNumber(BigInteger.valueOf(decryptedSeqNum));
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

    private byte[] generateChaCha20Mask(byte[] key, byte[] counter, byte[] nonce)
            throws CryptoException {
        throw new UnsupportedOperationException("ChaCha20 mask generation not implemented yet");
    }
}
