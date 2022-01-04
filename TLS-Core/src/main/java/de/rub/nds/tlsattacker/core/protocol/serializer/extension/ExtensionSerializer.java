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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @param <T>
 *            The ExtensionMessage that should be serialized
 */
public abstract class ExtensionSerializer<T extends ExtensionMessage> extends Serializer {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ExtensionMessage msg;

    public ExtensionSerializer(T message) {
        super();
        this.msg = message;
    }

    @Override
    protected byte[] serializeBytes() {
        writeType();
        writeLength();
        serializeExtensionContent();

        return getAlreadySerialized();
    }

    private void writeType() {
        appendBytes(msg.getExtensionType().getValue());
        LOGGER.debug("ExtensionType: " + ArrayConverter.bytesToHexString(msg.getExtensionType().getValue()));
    }

    private void writeLength() {
        appendInt(msg.getExtensionLength().getValue(), ExtensionByteLength.EXTENSIONS_LENGTH);
        LOGGER.debug("extensionLength: " + msg.getExtensionLength().getValue());
    }

    public abstract byte[] serializeExtensionContent();
}
