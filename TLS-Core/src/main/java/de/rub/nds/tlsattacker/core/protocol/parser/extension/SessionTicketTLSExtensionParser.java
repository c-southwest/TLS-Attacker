/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.state.parser.SessionTicketParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;

import static de.rub.nds.modifiablevariable.util.ArrayConverter.bytesToHexString;

public class SessionTicketTLSExtensionParser extends ExtensionParser<SessionTicketTLSExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final byte[] configTicketKeyName;
    private final CipherAlgorithm configCipherAlgorithm;
    private final MacAlgorithm configMacAlgorithm;

    /**
     * Constructor
     *
     * @param stream
     * @param config
     */
    public SessionTicketTLSExtensionParser(InputStream stream, Config config) {
        super(stream, config);
        configTicketKeyName = config.getSessionTicketKeyName();
        configCipherAlgorithm = config.getSessionTicketCipherAlgorithm();
        configMacAlgorithm = config.getSessionTicketMacAlgorithm();
    }

    /**
     * Parses the content of the given byte array to a SessionTicketTLSExtensionMessage
     *
     * @param msg
     *            Message, which will hold the parsed extension
     */
    @Override
    public void parseExtensionMessageContent(SessionTicketTLSExtensionMessage msg) {
        if (msg.getExtensionLength().getValue() > 65535) {
            LOGGER.warn("The SessionTLS ticket length shouldn't exceed 2 bytes as defined in RFC 4507. " + "Length was "
                    + msg.getExtensionLength().getValue());
        }
        if (msg.getExtensionLength().getValue() > 0) {
            LOGGER.debug("Parsing session ticket as resumption offer");
            msg.getSessionTicket().setIdentityLength(msg.getExtensionLength().getValue());
            msg.getSessionTicket()
                    .setIdentity(parseByteArrayField(msg.getSessionTicket().getIdentityLength().getValue()));
            SessionTicketParser ticketParser =
                    new SessionTicketParser(0, msg.getSessionTicket().getIdentity().getValue(), msg.getSessionTicket(),
                            configTicketKeyName, configCipherAlgorithm, configMacAlgorithm);
            ticketParser.parse();
        } else {
            LOGGER.debug("Parsing extension as indication for ticket support");
            msg.getSessionTicket().setIdentity(new byte[0]);
            msg.getSessionTicket().setIdentityLength(0);
            LOGGER.debug("Parsed session ticket identity " + bytesToHexString(msg.getSessionTicket().getIdentity()));
        }
    }
}
