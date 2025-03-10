/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.serializer.packet;

import de.rub.nds.tlsattacker.core.quic.packet.LongHeaderPacket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class LongHeaderPacketSerializer<T extends LongHeaderPacket>
        extends QuicPacketSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public LongHeaderPacketSerializer(T packet) {
        super(packet);
    }

    protected void writeSourceConnectionIdLength(T packet) {
        appendByte(packet.getSourceConnectionIdLength().getValue());
        LOGGER.debug(
                "Source Connection ID Length: {}", packet.getSourceConnectionIdLength().getValue());
    }

    protected void writeSourceConnectionId(T packet) {
        appendBytes(packet.getSourceConnectionId().getValue());
        LOGGER.debug("Source Connection ID: {}", packet.getSourceConnectionId().getValue());
    }

    protected void writeQuicVersion(T packet) {
        appendBytes(packet.getQuicVersion().getValue());
        LOGGER.debug("Quic Version: {}", packet.getSourceConnectionId().getValue());
    }
}
