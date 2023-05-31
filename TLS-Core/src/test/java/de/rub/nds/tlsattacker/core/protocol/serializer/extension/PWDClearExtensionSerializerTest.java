/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDClearExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.PWDClearExtensionParserTest;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class PWDClearExtensionSerializerTest
        extends AbstractExtensionMessageSerializerTest<
                PWDClearExtensionMessage, PWDClearExtensionSerializer> {

    public PWDClearExtensionSerializerTest() {
        super(
                PWDClearExtensionMessage::new,
                PWDClearExtensionSerializer::new,
                List.of(
                        (msg, obj) -> msg.setUsernameLength((Integer) obj),
                        (msg, obj) -> msg.setUsername((String) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return PWDClearExtensionParserTest.provideTestVectors();
    }
}
