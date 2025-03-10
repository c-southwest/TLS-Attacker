/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ClientCertificateUrlExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ClientCertificateUrlExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ClientCertificateUrlExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ClientCertificateUrlExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement(name = "ClientCertificateUrlExtension")
public class ClientCertificateUrlExtensionMessage extends ExtensionMessage {

    public ClientCertificateUrlExtensionMessage() {
        super(ExtensionType.CLIENT_CERTIFICATE_URL);
    }

    @Override
    public ClientCertificateUrlExtensionParser getParser(Context context, InputStream stream) {
        return new ClientCertificateUrlExtensionParser(stream, context.getTlsContext());
    }

    @Override
    public ClientCertificateUrlExtensionPreparator getPreparator(Context context) {
        return new ClientCertificateUrlExtensionPreparator(context.getChooser(), this);
    }

    @Override
    public ClientCertificateUrlExtensionSerializer getSerializer(Context context) {
        return new ClientCertificateUrlExtensionSerializer(this);
    }

    @Override
    public ClientCertificateUrlExtensionHandler getHandler(Context context) {
        return new ClientCertificateUrlExtensionHandler(context.getTlsContext());
    }
}
