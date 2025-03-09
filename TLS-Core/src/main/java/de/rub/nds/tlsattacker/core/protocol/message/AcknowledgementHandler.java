/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
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
            setClientRecordCipher(Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);
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
