/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.ManInTheMiddleAttackCommandConfig;
import de.rub.nds.tlsattacker.attacks.mitm.MitMWorkflowExecutor;
import de.rub.nds.tlsattacker.attacks.mitm.RSAExampleMitMWorkflowConfiguration;
import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.config.ServerCommandConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Executes a generic Man in the Middle attack against a target server and a
 * client.
 * 
 * @author Philip Riese <philip.riese@rub.de>
 */
public class ManInTheMiddleAttack extends Attacker<ManInTheMiddleAttackCommandConfig> {

    public static Logger LOGGER = LogManager.getLogger(ManInTheMiddleAttack.class);

    public ManInTheMiddleAttack(ManInTheMiddleAttackCommandConfig config) {
	super(config);
    }

    @Override
    public void executeAttack(ConfigHandler clientConfigHandler) {
	// create server objects
	ServerCommandConfig serverCommandConfig = new ServerCommandConfig();
	serverCommandConfig.setPort(config.getPort());
	serverCommandConfig.setCipherSuites(config.getCipherSuites());
	serverCommandConfig.setKeystore(config.getKeystore());
	serverCommandConfig.setPassword(config.getPassword());
	serverCommandConfig.setAlias(config.getAlias());
	serverCommandConfig.setWorkflowTraceType(config.getWorkflowTraceType());

	GeneralConfig generalConfig = new GeneralConfig();
	ConfigHandler serverConfigHandler = ConfigHandlerFactory.createConfigHandler("server");
	serverConfigHandler.initialize(generalConfig);
	TransportHandler serverTransportHandler = serverConfigHandler.initializeTransportHandler(serverCommandConfig);
	TlsContext serverTlsContext = serverConfigHandler.initializeTlsContext(serverCommandConfig);

	// create client objects
	TransportHandler clientTransportHandler = clientConfigHandler.initializeTransportHandler(config);
	TlsContext clientTlsContext = clientConfigHandler.initializeTlsContext(config);

	// load workflow into the tlsContext objects
	RSAExampleMitMWorkflowConfiguration clientwf = new RSAExampleMitMWorkflowConfiguration(clientTlsContext, config);
	clientwf.createWorkflow();

	RSAExampleMitMWorkflowConfiguration serverwf = new RSAExampleMitMWorkflowConfiguration(serverTlsContext, config);
	serverwf.createWorkflow();

	// should the whole workflow trace be modified
	boolean mod = config.isModify();

	MitMWorkflowExecutor mitmWorkflowExecutor = new MitMWorkflowExecutor(clientTransportHandler,
		serverTransportHandler, clientTlsContext, serverTlsContext, mod);

	mitmWorkflowExecutor.executeWorkflow();

	clientTransportHandler.closeConnection();
	serverTransportHandler.closeConnection();
    }
}
