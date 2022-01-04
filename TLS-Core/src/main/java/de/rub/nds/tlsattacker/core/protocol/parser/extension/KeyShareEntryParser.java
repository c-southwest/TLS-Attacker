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
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.Parser;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;

public class KeyShareEntryParser extends Parser<KeyShareEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private KeyShareEntry entry;

    public KeyShareEntryParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(KeyShareEntry entry) {
        LOGGER.debug("Parsing KeyShareEntry");
        parseKeyShareGroup(entry);
        if (getBytesLeft() > 0) {
            parseKeyShareLength(entry);
            parseKeyShare(entry);
        }
        entry.setGroupConfig(NamedGroup.getNamedGroup(entry.getGroup().getValue()));
    }

    /**
     * Reads the next bytes as the keyShareType of the Extension and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseKeyShareGroup(KeyShareEntry pair) {
        pair.setGroup(parseByteArrayField(ExtensionByteLength.KEY_SHARE_GROUP));
        LOGGER.debug("KeyShareGroup: " + ArrayConverter.bytesToHexString(pair.getGroup().getValue()));
    }

    /**
     * Reads the next bytes as the keyShareLength of the Extension and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseKeyShareLength(KeyShareEntry pair) {
        pair.setPublicKeyLength(parseIntField(ExtensionByteLength.KEY_SHARE_LENGTH));
        LOGGER.debug("KeyShareLength: " + pair.getPublicKeyLength().getValue());
    }

    /**
     * Reads the next bytes as the keyShare of the Extension and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseKeyShare(KeyShareEntry pair) {
        pair.setPublicKey(parseByteArrayField(pair.getPublicKeyLength().getValue()));
        LOGGER.debug("KeyShare: " + ArrayConverter.bytesToHexString(pair.getPublicKey().getValue()));
    }
}
