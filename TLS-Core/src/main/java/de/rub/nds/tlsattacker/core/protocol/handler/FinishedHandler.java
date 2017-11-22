/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import static de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler.LOGGER;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.FinishedMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.FinishedMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.FinishedMessageSerializer;
import de.rub.nds.tlsattacker.core.record.cipher.RecordAEADCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;

public class FinishedHandler extends HandshakeMessageHandler<FinishedMessage> {

    public FinishedHandler(TlsContext context) {
        super(context);
    }

    @Override
    public FinishedMessageParser getParser(byte[] message, int pointer) {
        return new FinishedMessageParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public FinishedMessagePreparator getPreparator(FinishedMessage message) {
        return new FinishedMessagePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public FinishedMessageSerializer getSerializer(FinishedMessage message) {
        return new FinishedMessageSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(FinishedMessage message) {
        if (tlsContext.getConnectionEnd().getConnectionEndType() == ConnectionEndType.CLIENT
                && tlsContext.isExtensionProposed(ExtensionType.EARLY_DATA)) {
            adjustRecordCipherForClientFin();
        }
        if (tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
            if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.SERVER) {
                adjustApplicationTrafficSecrets();
            }
        }
        if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
            tlsContext.setLastClientVerifyData(message.getVerifyData().getValue());
        } else {
            tlsContext.setLastServerVerifyData(message.getVerifyData().getValue());
        }
    }

    private void adjustApplicationTrafficSecrets() {
        HKDFAlgorithm hkdfAlgortihm = AlgorithmResolver.getHKDFAlgorithm(tlsContext.getChooser()
                .getSelectedCipherSuite());
        DigestAlgorithm digestAlgo = AlgorithmResolver.getDigestAlgorithm(tlsContext.getChooser()
                .getSelectedProtocolVersion(), tlsContext.getChooser().getSelectedCipherSuite());
        try {
            int macLength = Mac.getInstance(hkdfAlgortihm.getMacAlgorithm().getJavaName()).getMacLength();
            byte[] saltMasterSecret = HKDFunction.deriveSecret(hkdfAlgortihm, digestAlgo.getJavaName(),
                    tlsContext.getHandshakeSecret(), HKDFunction.DERIVED, ArrayConverter.hexStringToByteArray(""));
            byte[] masterSecret = HKDFunction.extract(hkdfAlgortihm, saltMasterSecret, new byte[macLength]);
            byte[] clientApplicationTrafficSecret = HKDFunction.deriveSecret(hkdfAlgortihm, digestAlgo.getJavaName(),
                    masterSecret, HKDFunction.CLIENT_APPLICATION_TRAFFIC_SECRET, tlsContext.getDigest().getRawBytes());
            tlsContext.setClientApplicationTrafficSecret(clientApplicationTrafficSecret);
            LOGGER.debug("Set clientApplicationTrafficSecret in Context to "
                    + ArrayConverter.bytesToHexString(clientApplicationTrafficSecret));
            byte[] serverApplicationTrafficSecret = HKDFunction.deriveSecret(hkdfAlgortihm, digestAlgo.getJavaName(),
                    masterSecret, HKDFunction.SERVER_APPLICATION_TRAFFIC_SECRET, tlsContext.getDigest().getRawBytes());
            tlsContext.setServerApplicationTrafficSecret(serverApplicationTrafficSecret);
            LOGGER.debug("Set serverApplicationTrafficSecret in Context to "
                    + ArrayConverter.bytesToHexString(serverApplicationTrafficSecret));
            tlsContext.setMasterSecret(masterSecret);
            LOGGER.debug("Set masterSecret in Context to " + ArrayConverter.bytesToHexString(masterSecret));
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoException(ex);
        }
    }

    private void adjustRecordCipherForClientFin() {
        try {
            LOGGER.debug("Adjusting recordCipher after encrypting EOED using different key");

            tlsContext.setActiveKeySetType(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);
            KeySet keySet = KeySetGenerator.generateKeySet(tlsContext);
            RecordCipher recordCipher = RecordCipherFactory.getRecordCipher(tlsContext, keySet,
                    tlsContext.getSelectedCipherSuite());
            tlsContext.getRecordLayer().setRecordCipher(recordCipher);
            tlsContext.getRecordLayer().updateDecryptionCipher();
            tlsContext.getRecordLayer().updateEncryptionCipher();

            // Set the correct SequenceNumbers
            tlsContext.setWriteSequenceNumber(0);
            tlsContext.setReadSequenceNumber(2);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(FinishedHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    public void adjustTlsContextAfterSerialize(FinishedMessage message) {
        if (tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
            adjustRecordCipherForApplicationData();
        }
    }

    private void adjustRecordCipherForApplicationData() {
        tlsContext.setActiveKeySetType(Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);
        KeySet keySet = getKeySet(tlsContext);
        LOGGER.debug("Setting new Cipher in RecordLayer");
        RecordCipher recordCipher = RecordCipherFactory.getRecordCipher(tlsContext, keySet);
        tlsContext.getRecordLayer().setRecordCipher(recordCipher);
        tlsContext.getRecordLayer().updateDecryptionCipher();
        tlsContext.getRecordLayer().updateEncryptionCipher();
        tlsContext.setWriteSequenceNumber(0);
        tlsContext.setReadSequenceNumber(0);
    }

    private KeySet getKeySet(TlsContext context) {
        try {
            LOGGER.debug("Generating new KeySet");
            KeySet keySet = KeySetGenerator.generateKeySet(context);
            return keySet;
        } catch (NoSuchAlgorithmException ex) {
            throw new UnsupportedOperationException("The specified Algorithm is not supported", ex);
        }
    }
}
