/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HeartbeatByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;

public class HeartbeatMessageParser extends ProtocolMessageParser<HeartbeatMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param version
     *                Version of the Protocol
     * @param config
     */
    public HeartbeatMessageParser(InputStream stream, ProtocolVersion version, Config config) {
        super(stream, config);
    }

    @Override
    protected void parseMessageContent(HeartbeatMessage message) {
        LOGGER.debug("Parsing HeartbeatMessage");
        parseHeartbeatMessageType(message);
        parsePayloadLength(message);
        parsePayload(message);
        parsePadding(message);
    }

    /**
     * Reads the next bytes as the HeartbeatMessageType and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseHeartbeatMessageType(HeartbeatMessage msg) {
        msg.setHeartbeatMessageType(parseByteField(HeartbeatByteLength.TYPE));
        LOGGER.debug("HeartbeatMessageType: " + msg.getHeartbeatMessageType().getValue());
    }

    /**
     * Reads the next bytes as the PayloadLength and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePayloadLength(HeartbeatMessage msg) {
        msg.setPayloadLength(parseIntField(HeartbeatByteLength.PAYLOAD_LENGTH));
        LOGGER.debug("PayloadLength: " + msg.getPayloadLength().getValue());
    }

    /**
     * Reads the next bytes as the Payload and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePayload(HeartbeatMessage msg) {
        msg.setPayload(parseByteArrayField(msg.getPayloadLength().getValue()));
        LOGGER.debug("Payload: " + ArrayConverter.bytesToHexString(msg.getPayload().getValue()));
    }

    /**
     * Reads the next bytes as the Padding and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePadding(HeartbeatMessage msg) {
        msg.setPadding(parseByteArrayField(getBytesLeft()));
        LOGGER.debug("Padding: " + ArrayConverter.bytesToHexString(msg.getPadding().getValue()));
    }

}
