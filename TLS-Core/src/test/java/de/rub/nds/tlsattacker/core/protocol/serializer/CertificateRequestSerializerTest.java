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
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateRequestParserTest;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class CertificateRequestSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return CertificateRequestParserTest.generateData();
    }

    private byte[] message;
    private int certTypesCount;
    private byte[] certTypes;
    private int sigHashAlgsLength;
    private byte[] sigHashAlgs;
    private int distinguishedNamesLength;
    private byte[] distinguishedNames;
    private ProtocolVersion version;

    public CertificateRequestSerializerTest(byte[] message, int certTypesCount, byte[] certTypes, int sigHashAlgsLength,
        byte[] sigHashAlgs, int distinguishedNamesLength, byte[] distinguishedNames, ProtocolVersion version) {
        this.message = message;
        this.certTypesCount = certTypesCount;
        this.certTypes = certTypes;
        this.sigHashAlgsLength = sigHashAlgsLength;
        this.sigHashAlgs = sigHashAlgs;
        this.distinguishedNamesLength = distinguishedNamesLength;
        this.distinguishedNames = distinguishedNames;
        this.version = version;
    }

    /**
     * Test of serializeHandshakeMessageContent method, of class CertificateRequestSerializer.
     */
    @Test
    public void testSerializeHandshakeMessageContent() {
        CertificateRequestMessage message = new CertificateRequestMessage();
        message.setClientCertificateTypesCount(certTypesCount);
        message.setClientCertificateTypes(certTypes);
        message.setSignatureHashAlgorithmsLength(sigHashAlgsLength);
        message.setSignatureHashAlgorithms(sigHashAlgs);
        message.setDistinguishedNamesLength(distinguishedNamesLength);
        message.setDistinguishedNames(distinguishedNames);
        CertificateRequestSerializer serializer = new CertificateRequestSerializer(message, version);
        assertArrayEquals(this.message, serializer.serializeHandshakeMessageContent());
    }

}
