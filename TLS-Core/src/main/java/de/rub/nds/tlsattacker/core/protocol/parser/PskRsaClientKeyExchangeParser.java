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
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.PskRsaClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;

public class PskRsaClientKeyExchangeParser extends RSAClientKeyExchangeParser<PskRsaClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param version
     *                   Version of the Protocol
     * @param tlsContext
     */
    public PskRsaClientKeyExchangeParser(InputStream stream, ProtocolVersion version, TlsContext tlsContext) {
        super(stream, version, tlsContext);
    }

    @Override
    protected void parseHandshakeMessageContent(PskRsaClientKeyExchangeMessage msg) {
        LOGGER.debug("Parsing PSKRSAClientKeyExchangeMessage");
        parsePskIdentityLength(msg);
        parsePskIdentity(msg);
        super.parseRsaParams(msg);
    }

    /**
     * Reads the next bytes as the PSKIdentityLength and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePskIdentityLength(PskRsaClientKeyExchangeMessage msg) {
        msg.setIdentityLength(parseIntField(HandshakeByteLength.PSK_IDENTITY_LENGTH));
        LOGGER.debug("PSK-IdentityLength: " + msg.getIdentityLength().getValue());
    }

    /**
     * Reads the next bytes as the PSKIdentity and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePskIdentity(PskRsaClientKeyExchangeMessage msg) {
        msg.setIdentity(parseByteArrayField(msg.getIdentityLength().getValue()));
        LOGGER.debug("PSK-Identity: " + ArrayConverter.bytesToHexString(msg.getIdentity().getValue()));
    }
}
