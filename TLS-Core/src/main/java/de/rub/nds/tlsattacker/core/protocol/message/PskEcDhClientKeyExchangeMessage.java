/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.handler.ECDHClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.PskEcDhClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.PskEcDhClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PskEcDhClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PskEcDhClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.InputStream;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "PskEcDhClientKeyExchange")
public class PskEcDhClientKeyExchangeMessage extends ECDHClientKeyExchangeMessage {

    @ModifiableVariableProperty(format = ModifiableVariableProperty.Format.PKCS1,
        type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableByteArray identity;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger identityLength;

    public PskEcDhClientKeyExchangeMessage() {
        super();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("PskEcDhClientKeyExchangeMessage:");
        sb.append("\n  PSKIdentity Length: ");
        if (identityLength != null && identityLength.getValue() != null) {
            sb.append(identityLength.getValue());
        } else {
            sb.append("null");
        }
        sb.append("\n  PSKIdentity: ");
        if (identity != null) {
            sb.append(ArrayConverter.bytesToHexString(identity.getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    public ModifiableByteArray getIdentity() {
        return identity;
    }

    public void setIdentity(ModifiableByteArray identity) {
        this.identity = identity;
    }

    public void setIdentity(byte[] identity) {
        this.identity = ModifiableVariableFactory.safelySetValue(this.identity, identity);
    }

    public ModifiableInteger getIdentityLength() {
        return identityLength;
    }

    public void setIdentityLength(ModifiableInteger identityLength) {
        this.identityLength = identityLength;
    }

    public void setIdentityLength(Integer identityLength) {
        this.identityLength = ModifiableVariableFactory.safelySetValue(this.identityLength, identityLength);
    }

    @Override
    public ECDHClientKeyExchangeHandler<PskEcDhClientKeyExchangeMessage> getHandler(TlsContext context) {
        return new PskEcDhClientKeyExchangeHandler(context);
    }

    @Override
    public PskEcDhClientKeyExchangeParser getParser(TlsContext tlsContext, InputStream stream) {
        return new PskEcDhClientKeyExchangeParser(stream, tlsContext);
    }

    @Override
    public PskEcDhClientKeyExchangePreparator getPreparator(TlsContext tlsContext) {
        return new PskEcDhClientKeyExchangePreparator(tlsContext.getChooser(), this);
    }

    @Override
    public PskEcDhClientKeyExchangeSerializer getSerializer(TlsContext tlsContext) {
        return new PskEcDhClientKeyExchangeSerializer(this);
    }

    @Override
    public String toCompactString() {
        return "PSK_ECDH_CLIENT_KEY_EXCHANGE";
    }

    @Override
    public String toShortString() {
        return "PSK_ECDH_CKE";
    }
}
