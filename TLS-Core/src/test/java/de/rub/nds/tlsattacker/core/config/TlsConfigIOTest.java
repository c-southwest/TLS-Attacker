/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.config;

import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;

import javax.xml.bind.JAXBException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.*;

public class TlsConfigIOTest {

    @Rule
    public final ExpectedException exception = ExpectedException.none();

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Test
    public void testReadWriteRead() throws IOException, JAXBException {
        File f = folder.newFile();
        Config config = Config.createConfig();
        ConfigIO.write(config, f);
        config = ConfigIO.read(f);
        assertNotNull(config);
    }

    @Test
    public void testEmptyConfig() {
        InputStream stream = Config.class.getResourceAsStream("/test_empty_config.xml");
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Stream cannot be null");
        Config config = Config.createConfig(stream);
    }

    @Test
    public void testIncompleteConfig() {
        InputStream stream = Config.class.getResourceAsStream("/test_incomplete_config.xml");
        Config config = Config.createConfig(stream);
        assertNotNull(config);
        assertTrue(config.getDefaultClientSupportedCipherSuites().size() == 1);
    }

    @Test
    public void testReadCustomClientConnection() throws IOException, JAXBException {
        OutboundConnection expected = new OutboundConnection("testConnection", 8002, "testHostname");

        InputStream stream = Config.class.getResourceAsStream("/test_config_custom_client_connection.xml");
        Config config = Config.createConfig(stream);
        assertNotNull(config);

        OutboundConnection con = config.getDefaultClientConnection();
        assertNotNull(con);
        assertThat(con, equalTo(expected));
    }

    @Test
    public void testReadCustomServerConnection() throws IOException, JAXBException {
        InputStream stream = Config.class.getResourceAsStream("/test_config_custom_server_connection.xml");

        InboundConnection expected = new InboundConnection("testConnection", 8004);
        Config config = Config.createConfig(stream);
        assertNotNull(config);

        InboundConnection con = config.getDefaultServerConnection();
        assertNotNull(con);
        assertThat(con, equalTo(expected));
    }

}
