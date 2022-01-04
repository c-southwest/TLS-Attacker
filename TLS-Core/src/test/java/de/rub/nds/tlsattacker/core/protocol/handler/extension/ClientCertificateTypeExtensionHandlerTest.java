/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.CertificateType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class ClientCertificateTypeExtensionHandlerTest {

    private final List<CertificateType> certList =
        Arrays.asList(CertificateType.OPEN_PGP, CertificateType.X509, CertificateType.RAW_PUBLIC_KEY);
    private ClientCertificateTypeExtensionHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new ClientCertificateTypeExtensionHandler(context);
    }

    @Test
    public void testadjustContext() {
        ClientCertificateTypeExtensionMessage msg = new ClientCertificateTypeExtensionMessage();
        msg.setCertificateTypes(CertificateType.toByteArray(certList));

        handler.adjustContext(msg);

        assertThat(certList, is(context.getClientCertificateTypeDesiredTypes()));
    }
}
