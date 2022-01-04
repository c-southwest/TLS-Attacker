/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.Serializer;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyShareEntrySerializer extends Serializer<KeyShareEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final KeyShareEntry entry;

    public KeyShareEntrySerializer(KeyShareEntry entry) {
        this.entry = entry;
    }

    @Override
    protected byte[] serializeBytes() {
        LOGGER.debug("Serializing KeySharePair");
        writeKeyShareType(entry);
        writeKeyShareLength(entry);
        writeKeyShare(entry);
        return getAlreadySerialized();
    }

    private void writeKeyShareType(KeyShareEntry pair) {
        appendBytes(pair.getGroup().getValue());
        LOGGER.debug("KeyShareType: " + ArrayConverter.bytesToHexString(pair.getGroup().getValue()));
    }

    private void writeKeyShareLength(KeyShareEntry pair) {
        appendInt(pair.getPublicKeyLength().getValue(), ExtensionByteLength.KEY_SHARE_LENGTH);
        LOGGER.debug("KeyShareLength: " + pair.getPublicKeyLength().getValue());
    }

    private void writeKeyShare(KeyShareEntry entry) {
        appendBytes(entry.getPublicKey().getValue());
        LOGGER.debug("KeyShare: " + ArrayConverter.bytesToHexString(entry.getPublicKey().getValue()));
    }
}
