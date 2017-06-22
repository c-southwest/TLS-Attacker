/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.DHClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.DHClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.DHClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class DHClientKeyExchangeHandlerTest {

    private DHClientKeyExchangeHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new DHClientKeyExchangeHandler(context);

    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getParser method, of class DHClientKeyExchangeHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof DHClientKeyExchangeParser);
    }

    /**
     * Test of getPreparator method, of class DHClientKeyExchangeHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new DHClientKeyExchangeMessage()) instanceof DHClientKeyExchangePreparator);
    }

    /**
     * Test of getSerializer method, of class DHClientKeyExchangeHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new DHClientKeyExchangeMessage()) instanceof DHClientKeyExchangeSerializer);
    }

    /**
     * Test of adjustTLSContext method, of class DHClientKeyExchangeHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        DHClientKeyExchangeMessage message = new DHClientKeyExchangeMessage();
        message.prepareComputations();
        message.getComputations().setPremasterSecret(new byte[] { 0, 1, 2, 3 });
        message.getComputations().setClientRandom(new byte[] { 1, 2, 3 });

        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);

        // message.getComputations().setMasterSecret(new byte[] { 4, 5, 6 });
        handler.adjustTLSContext(message);
        assertArrayEquals(new byte[] { 0, 1, 2, 3 }, context.getPreMasterSecret());
        // assertArrayEquals(new byte[] { 4, 5, 6 }, context.getMasterSecret());
        // TODO assert master secret was computed correctly
    }
}
