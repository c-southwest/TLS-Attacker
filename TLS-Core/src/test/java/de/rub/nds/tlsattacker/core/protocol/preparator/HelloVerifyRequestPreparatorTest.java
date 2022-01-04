/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

public class HelloVerifyRequestPreparatorTest {

    private static final Logger LOGGER = LogManager.getLogger();

    private TlsContext context;
    private HelloVerifyRequestPreparator preparator;
    private HelloVerifyRequestMessage message;

    @Before
    public void setUp() {
        this.context = new TlsContext();
        this.message = new HelloVerifyRequestMessage();
        this.preparator = new HelloVerifyRequestPreparator(context.getChooser(), message);
    }

    /**
     * Test of prepareHandshakeMessageContents method, of class HelloVerifyRequestPreparator.
     */
    @Test
    public void testPrepare() {
        context.getConfig().setDtlsDefaultCookieLength(10);
        context.getConfig().setHighestProtocolVersion(ProtocolVersion.DTLS12);
        preparator.prepare();
        LOGGER.info(ArrayConverter.bytesToHexString(message.getCookie().getValue(), false));
        assertArrayEquals(ArrayConverter.hexStringToByteArray("60B420BB3851D9D47ACB"), message.getCookie().getValue());
        assertTrue(10 == message.getCookieLength().getValue());
        assertArrayEquals(ProtocolVersion.DTLS12.getValue(), message.getProtocolVersion().getValue());
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }
}
