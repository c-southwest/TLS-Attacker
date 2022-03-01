/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.HelloRequestHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.HelloRequestParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.HelloRequestPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.HelloRequestSerializer;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import java.io.InputStream;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "HelloRequest")
public class HelloRequestMessage extends HandshakeMessage {

    public HelloRequestMessage(Config tlsConfig) {
        super(tlsConfig, HandshakeMessageType.HELLO_REQUEST);
        isIncludeInDigestDefault = false;
    }

    public HelloRequestMessage() {
        super(HandshakeMessageType.HELLO_REQUEST);
        isIncludeInDigestDefault = false;
    }

    @Override
    public HelloRequestHandler getHandler(TlsContext tlsContext) {
        return new HelloRequestHandler(tlsContext);
    }

    @Override
    public HelloRequestParser getParser(TlsContext tlsContext, InputStream stream) {
        return new HelloRequestParser(stream, tlsContext.getChooser().getLastRecordVersion(), tlsContext);
    }

    @Override
    public HelloRequestPreparator getPreparator(TlsContext tlsContext) {
        return new HelloRequestPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public HelloRequestSerializer getSerializer(TlsContext tlsContext) {
        return new HelloRequestSerializer(this, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("HelloRequestMessage:");

        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "HR";
    }
}
