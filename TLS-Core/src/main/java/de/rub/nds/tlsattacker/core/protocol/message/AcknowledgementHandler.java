package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeyDerivator;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.NoSuchAlgorithmException;

public class AcknowledgementHandler extends ProtocolMessageHandler<AcknowledgementMessage> {
    public AcknowledgementHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(AcknowledgementMessage container) {
        if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.SERVER) {
            if (tlsContext.getWriteEpoch() == 3) {
                // according to section 6.1 from
                // https://www.rfc-editor.org/rfc/inline-errata/rfc9147.html
                // I think the maximum epoch after receive ACK should be 3, and cannot be 4, 5 , and
                // so on
                LOGGER.warn("We only allow epoch=3 as the maximum value right now");
                return;
            }
            // Only update cipher when we receive a valid Ack
            if (container.getRecordNumbers().getValue().length > 0) {
                setClientRecordCipher(Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);
            }
        }
    }

    private void setClientRecordCipher(Tls13KeySetType keySetType) {
        tlsContext.setActiveClientKeySetType(keySetType);
        LOGGER.debug("Setting cipher for client to use {}", keySetType);

        KeySet keySet;

        switch (keySetType) {
            case APPLICATION_TRAFFIC_SECRETS:
                keySet = getKeySet(tlsContext, tlsContext.getActiveClientKeySetType());
                break;
            case HANDSHAKE_TRAFFIC_SECRETS:
                keySet = tlsContext.getkeySetHandshake();
                break;
            default:
                throw new IllegalArgumentException(
                        "In this state, only APPLICATION_TRAFFIC_SECRETS and HANDSHAKE_TRAFFIC_SECRETS are valid.");
        }

        if (tlsContext.getRecordLayer() != null) {
            if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.SERVER) {
                tlsContext
                        .getRecordLayer()
                        .updateDecryptionCipher(
                                RecordCipherFactory.getRecordCipher(tlsContext, keySet, false));
            } else {
                tlsContext
                        .getRecordLayer()
                        .updateEncryptionCipher(
                                RecordCipherFactory.getRecordCipher(tlsContext, keySet, true));
            }
        }
    }

    private KeySet getKeySet(TlsContext tlsContext, Tls13KeySetType keySetType) {
        try {
            LOGGER.debug("Generating new KeySet");
            KeySet keySet =
                    KeyDerivator.generateKeySet(
                            tlsContext,
                            tlsContext.getChooser().getSelectedProtocolVersion(),
                            keySetType);
            return keySet;
        } catch (NoSuchAlgorithmException | CryptoException ex) {
            throw new UnsupportedOperationException("The specified Algorithm is not supported", ex);
        }
    }
}
