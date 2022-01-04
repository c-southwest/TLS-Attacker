/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class PskEcDhClientKeyExchangeMessageTest {

    PskEcDhClientKeyExchangeMessage message;

    @Before
    public void setUp() {
        message = new PskEcDhClientKeyExchangeMessage();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of toString method, of class PskEcDhClientKeyExchangeMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("PskEcDhClientKeyExchangeMessage:");
        sb.append("\n  PSKIdentity Length: ").append("null");
        sb.append("\n  PSKIdentity: ").append("null");

        assertEquals(message.toString(), sb.toString());
    }

}
