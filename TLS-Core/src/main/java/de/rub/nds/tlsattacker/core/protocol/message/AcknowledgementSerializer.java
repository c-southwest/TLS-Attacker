/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageSerializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AcknowledgementSerializer extends ProtocolMessageSerializer<AcknowledgementMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AcknowledgementSerializer(AcknowledgementMessage message) {
        super(message);
    }

    @Override
    protected byte[] serializeBytes() {
        LOGGER.error("Not implemented yet");
        return getAlreadySerialized();
    }
}
