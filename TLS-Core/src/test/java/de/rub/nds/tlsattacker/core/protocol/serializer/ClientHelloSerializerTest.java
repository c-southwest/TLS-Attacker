/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ClientHelloParserTest;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ClientHelloSerializerTest {
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return ClientHelloParserTest.generateData();
    }

    private final byte[] expectedPart;

    private final ProtocolVersion version;
    private final byte[] protocolVersion;
    private final byte[] unixTime;
    private final byte[] random;
    private final int sessionIdLength;
    private final byte[] sessionID;
    private final int cipherSuitesLength;
    private final byte[] cipherSuites;
    private final int compressionsLength;
    private final byte[] compressions;
    private final Integer extensionLength;
    private final byte[] extensionBytes;
    private final Byte cookieLength;
    private final byte[] cookie;

    public ClientHelloSerializerTest(byte[] message, ProtocolVersion version, byte[] protocolVersion, byte[] unixTime,
        byte[] random, int sessionIdLength, byte[] sessionID, int cipherSuitesLength, byte[] cipherSuites,
        int compressionsLength, byte[] compressions, Integer extensionLength, byte[] extensionBytes, Byte cookieLength,
        byte[] cookie, int numberOfExtensions) {
        this.expectedPart = message;
        this.version = version;
        this.protocolVersion = protocolVersion;
        this.unixTime = unixTime;
        this.random = random;
        this.sessionIdLength = sessionIdLength;
        this.sessionID = sessionID;
        this.cipherSuitesLength = cipherSuitesLength;
        this.cipherSuites = cipherSuites;
        this.compressionsLength = compressionsLength;
        this.compressions = compressions;
        this.extensionLength = extensionLength;
        this.extensionBytes = extensionBytes;
        this.cookieLength = cookieLength;
        this.cookie = cookie;
    }

    /**
     * Test of serializeHandshakeMessageContent method, of class ClientHelloSerializer.
     */
    @Test
    public void testSerializeHandshakeMessageContent() {
        ClientHelloMessage clientMessage = new ClientHelloMessage();
        clientMessage.setCipherSuiteLength(cipherSuitesLength);
        clientMessage.setCipherSuites(cipherSuites);
        clientMessage.setCompressionLength(compressionsLength);
        clientMessage.setCompressions(compressions);
        if (cookie != null) {
            clientMessage.setCookie(cookie);
        }
        if (cookieLength != null) {
            clientMessage.setCookieLength(cookieLength);
        }
        if (extensionBytes != null) {
            clientMessage.setExtensionBytes(extensionBytes);
        }
        clientMessage.setExtensionsLength(extensionLength);
        clientMessage.setSessionId(sessionID);
        clientMessage.setSessionIdLength(sessionIdLength);
        clientMessage.setCompleteResultingMessage(expectedPart);
        clientMessage.setUnixTime(unixTime);
        clientMessage.setRandom(random);
        clientMessage.setProtocolVersion(protocolVersion);
        ClientHelloSerializer serializer = new ClientHelloSerializer(clientMessage, version);
        assertArrayEquals(expectedPart, serializer.serializeHandshakeMessageContent());
    }

}
