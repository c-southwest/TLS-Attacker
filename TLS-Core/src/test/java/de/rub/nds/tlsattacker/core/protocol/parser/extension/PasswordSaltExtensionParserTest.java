/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PasswordSaltExtensionMessage;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class PasswordSaltExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
            .asList(new Object[][] { { ArrayConverter.hexStringToByteArray("0010843711c21d47ce6e6383cdda37e47da3"), 16,
                ArrayConverter.hexStringToByteArray("843711c21d47ce6e6383cdda37e47da3") } });
    }

    private final byte[] expectedBytes;
    private final int saltLength;
    private final byte[] salt;

    public PasswordSaltExtensionParserTest(byte[] expectedBytes, int saltLength, byte[] salt) {
        this.expectedBytes = expectedBytes;
        this.saltLength = saltLength;
        this.salt = salt;
    }

    @Test
    public void testParseExtensionMessageContent() {
        PasswordSaltExtensionParser parser =
            new PasswordSaltExtensionParser(new ByteArrayInputStream(expectedBytes), Config.createConfig());
        PasswordSaltExtensionMessage msg = new PasswordSaltExtensionMessage();
        parser.parse(msg);
        assertEquals(saltLength, (long) msg.getSaltLength().getValue());
        assertArrayEquals(salt, msg.getSalt().getValue());
    }

}
