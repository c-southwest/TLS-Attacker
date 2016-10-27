/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.config.mutator.certificate;

import java.io.File;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import tlsattacker.fuzzer.certificate.ClientCertificateStructure;
import tlsattacker.fuzzer.certificate.ServerCertificateStructure;
import tlsattacker.fuzzer.config.ConfigManager;

/**
 * A configuration class for the FixedCertificateMutator
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class FixedCertificateMutatorConfig implements Serializable {
    // Fixes the configuration File after a selftest and serializes it

    /**
     *
     */
    private boolean autofix = true;

    /**
     *
     */
    private List<ClientCertificateStructure> clientCertificates;

    /**
     *
     */
    private List<ServerCertificateStructure> serverCertificates;

    /**
     *
     */
    public FixedCertificateMutatorConfig() {
	clientCertificates = new ArrayList<>();
	// Initialize the Config File with some certificates if we can find them
	new File(ConfigManager.getInstance().getConfig().getOutputClientCertificateFolder()).mkdirs();
	File jksFile = new File(ConfigManager.getInstance().getConfig().getOutputClientCertificateFolder() + "rsa1024.jks");
	if (jksFile.exists()) {
	    clientCertificates.add(new ClientCertificateStructure("password", "alias", jksFile));
	}
	serverCertificates = new ArrayList<>();
	File keyFile = new File(ConfigManager.getInstance().getConfig().getOutputServerCertificateFolder()
		+ "dsakey.pem");
	File certFile = new File(ConfigManager.getInstance().getConfig().getOutputServerCertificateFolder()
		+ "dsacert.pem");
	if (keyFile.exists() && certFile.exists()) {
	    serverCertificates.add(new ServerCertificateStructure(keyFile, certFile));
	}
    }

    /**
     * 
     * @return
     */
    public boolean isAutofix() {
	return autofix;
    }

    /**
     * 
     * @param autofix
     */
    public void setAutofix(boolean autofix) {
	this.autofix = autofix;
    }

    /**
     * 
     * @return
     */
    public List<ClientCertificateStructure> getClientCertificates() {
	return Collections.unmodifiableList(clientCertificates);
    }

    /**
     * 
     * @param clientCertificates
     */
    public void setClientCertificates(List<ClientCertificateStructure> clientCertificates) {
	this.clientCertificates = clientCertificates;
    }

    /**
     * 
     * @return
     */
    public List<ServerCertificateStructure> getServerCertificates() {
	return Collections.unmodifiableList(serverCertificates);
    }

    /**
     * 
     * @param serverCertificates
     */
    public void setServerCertificates(List<ServerCertificateStructure> serverCertificates) {
	this.serverCertificates = serverCertificates;
    }

    private static final Logger LOG = Logger.getLogger(FixedCertificateMutatorConfig.class.getName());

}
