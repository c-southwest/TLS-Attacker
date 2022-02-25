/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HelloRequestMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class HelloRequestParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {}); // TODO add Testcases!
    }

    // TODO get a true message
    private final byte[] message;

    private final Config config = Config.createConfig();

    public HelloRequestParserTest(byte[] message) {
        this.message = message;
    }

    /**
     * Test of parse method, of class HelloRequestParser.
     */
    @Test
    public void testParse() {
        TlsContext tlsContext = new TlsContext(config);
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        HelloRequestParser parser = new HelloRequestParser(new ByteArrayInputStream(message), tlsContext);
        HelloRequestMessage msg = new HelloRequestMessage();
        parser.parse(msg);
    }

}
