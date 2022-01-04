/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.util.BadRandom;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.util.BasicTlsServer;
import de.rub.nds.tlsattacker.core.util.KeyStoreGenerator;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.util.FixedTimeProvider;
import de.rub.nds.tlsattacker.util.TimeHelper;
import de.rub.nds.tlsattacker.util.tests.IntegrationTests;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.*;
import org.junit.experimental.categories.Category;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Random;

import static org.junit.Assert.*;

public class FindReceivedProtocolMessageActionTest {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final int SERVER_PORT = 48385;

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    private final BadRandom random = new BadRandom(new Random(0), null);

    public FindReceivedProtocolMessageActionTest() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of execute method, of class FindReceivedProtocolMessageAction.
     *
     * @throws java.lang.Exception
     */
    @Test
    @Category(IntegrationTests.class)
    public void testExecute() throws Exception {
        Config config = Config.createConfig();
        config.getDefaultClientConnection().setPort(SERVER_PORT);

        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace = factory.createWorkflowTrace(WorkflowTraceType.HELLO, RunningModeType.CLIENT);
        FindReceivedProtocolMessageAction action_find_handshake =
            new FindReceivedProtocolMessageAction(ProtocolMessageType.HANDSHAKE);
        FindReceivedProtocolMessageAction action_find_app_data =
            new FindReceivedProtocolMessageAction(ProtocolMessageType.APPLICATION_DATA);
        trace.addTlsAction(action_find_handshake);
        trace.addTlsAction(action_find_app_data);

        State state = new State(config, trace);

        try {
            TimeHelper.setProvider(new FixedTimeProvider(0));
            KeyPair k = KeyStoreGenerator.createRSAKeyPair(1024, random);
            KeyStore ks = KeyStoreGenerator.createKeyStore(k, random);
            BasicTlsServer tlsServer = new BasicTlsServer(ks, KeyStoreGenerator.PASSWORD, "TLS", SERVER_PORT);

            LOGGER.info("Starting test server");
            new Thread(tlsServer).start();
            while (!tlsServer.isInitialized())
                ;

            WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
            executor.executeWorkflow();

            LOGGER.info("Killing server...");
            tlsServer.shutdown();
            LOGGER.info("Done.");
        } catch (NoSuchAlgorithmException | CertificateException | IOException | InvalidKeyException | KeyStoreException
            | NoSuchProviderException | SignatureException | UnrecoverableKeyException | KeyManagementException ex) {
            fail();
        }

        assertTrue(action_find_handshake.isFound());
        assertFalse(action_find_app_data.isFound());
    }
}
