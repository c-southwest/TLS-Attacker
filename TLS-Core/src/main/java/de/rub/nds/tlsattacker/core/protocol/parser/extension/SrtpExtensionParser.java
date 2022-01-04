/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SrtpExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;

public class SrtpExtensionParser extends ExtensionParser<SrtpExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SrtpExtensionParser(InputStream stream, Config config) {
        super(stream, config);
    }

    @Override
    public void parseExtensionMessageContent(SrtpExtensionMessage msg) {
        msg.setSrtpProtectionProfilesLength(parseIntField(ExtensionByteLength.SRTP_PROTECTION_PROFILES_LENGTH));
        LOGGER
                .debug("Parsed the srtp protection profiles length of " + msg.getSrtpProtectionProfilesLength().getValue());
        msg.setSrtpProtectionProfiles(parseByteArrayField(msg.getSrtpProtectionProfilesLength().getValue()));
        LOGGER.debug(
                "Parsed the srtp protection profiles " + ArrayConverter.bytesToHexString(msg.getSrtpProtectionProfiles()));
        msg.setSrtpMkiLength(parseIntField(ExtensionByteLength.SRTP_MASTER_KEY_IDENTIFIER_LENGTH));
        LOGGER.debug("Parsed the srtp mki length of " + msg.getSrtpMkiLength().getValue());
        msg.setSrtpMki(parseByteArrayField(msg.getSrtpMkiLength().getValue()));
        LOGGER.debug("Parsed the srtp mki " + ArrayConverter.bytesToHexString(msg.getSrtpMki()));
    }
}
