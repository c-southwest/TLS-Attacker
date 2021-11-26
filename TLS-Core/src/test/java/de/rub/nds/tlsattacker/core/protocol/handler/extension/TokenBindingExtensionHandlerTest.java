/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class TokenBindingExtensionHandlerTest {

    private final byte[] extensionBytes = new byte[] { 0x00, 0x18, 0x00, 0x04, 0x00, 0x0d, 0x01, 0x02 };

    private final TokenBindingVersion tokenbindingVersion = TokenBindingVersion.DRAFT_13;

    private final TokenBindingKeyParameters[] keyParameter =
        new TokenBindingKeyParameters[] { TokenBindingKeyParameters.RSA2048_PSS, TokenBindingKeyParameters.ECDSAP256 };
    private final byte[] keyParameterByteArrayRepresentation = new byte[] { 0x01, 0x02 };
    private TlsContext context;
    private TokenBindingExtensionHandler handler;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new TokenBindingExtensionHandler(context);
    }

    @Test
    public void testadjustContext() {
        TokenBindingExtensionMessage message = new TokenBindingExtensionMessage();
        message.setTokenbindingVersion(tokenbindingVersion.getByteValue());
        message.setTokenbindingKeyParameters(keyParameterByteArrayRepresentation);
        handler.adjustContext(message);

        assertEquals(tokenbindingVersion, context.getTokenBindingVersion());
        assertArrayEquals(keyParameter, context.getTokenBindingKeyParameters()
            .toArray(new TokenBindingKeyParameters[context.getTokenBindingKeyParameters().size()]));
    }
}
