/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.PskDhClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

public class PskDhClientKeyExchangeHandlerTest {

    private PskDhClientKeyExchangeHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new PskDhClientKeyExchangeHandler(context);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of adjustContext method, of class PskDhClientKeyExchangeHandler.
     */
    @Test
    public void testadjustContext() {
        PskDhClientKeyExchangeMessage message = new PskDhClientKeyExchangeMessage();
        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA);
        message.prepareComputations();
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        message.getComputations().setPremasterSecret(ArrayConverter.hexStringToByteArray(
            "0303d3fad5b20109834717bac4e7762e217add183d0c4852ab054f65ba6e93b1ed83ca5c5fa614cd3b810f4766c66feb"));
        message.getComputations().setClientServerRandom(ArrayConverter.hexStringToByteArray(
            "a449532975d478abeefcfafa7522b9312bdbd0bb294fe460c4d52bab13a425b7594d0e9508874a67db6d9b8e91db4f38600e88f006bbe58f2b41deb6811c74cc"));

        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA);

        handler.adjustContext(message);
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "0303d3fad5b20109834717bac4e7762e217add183d0c4852ab054f65ba6e93b1ed83ca5c5fa614cd3b810f4766c66feb"),
            context.getPreMasterSecret());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "FA1D499E795E936751AD43355C26857728E78ABE1C4BCAFA6EF3C90F6D9B9E49DF1ADE262F127EB2A23BB73E142EE122"),
            context.getMasterSecret());
    }
}
