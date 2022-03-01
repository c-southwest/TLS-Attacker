/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.handler.PskRsaClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.RSAClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.PskRsaClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PskRsaClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PskRsaClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import java.io.InputStream;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "PskRsaClientKeyExchange")
public class PskRsaClientKeyExchangeMessage extends RSAClientKeyExchangeMessage {

    @HoldsModifiableVariable
    @XmlElement
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableByteArray identity;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger identityLength;

    public PskRsaClientKeyExchangeMessage(Config tlsConfig) {
        super(tlsConfig);
    }

    public PskRsaClientKeyExchangeMessage() {
        super();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("PskRsaClientKeyExchangeMessage:");
        sb.append("\n  PSKIdentityLength: ");
        if (identityLength != null && identityLength.getValue() != null) {
            sb.append(identityLength.getValue());
        } else {
            sb.append("null");
        }
        sb.append("\n  PSKIdentity: ");
        if (identity != null && identity.getValue() != null) {
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

    public void setIdentityLength(int identityLength) {
        this.identityLength = ModifiableVariableFactory.safelySetValue(this.identityLength, identityLength);
    }

    @Override
    public RSAClientKeyExchangeHandler<PskRsaClientKeyExchangeMessage> getHandler(TlsContext tlsContext) {
        return new PskRsaClientKeyExchangeHandler(tlsContext);
    }

    @Override
    public PskRsaClientKeyExchangeParser getParser(TlsContext tlsContext, InputStream stream) {
        return new PskRsaClientKeyExchangeParser(stream, tlsContext.getChooser().getLastRecordVersion(), tlsContext);
    }

    @Override
    public PskRsaClientKeyExchangePreparator getPreparator(TlsContext tlsContext) {
        return new PskRsaClientKeyExchangePreparator(tlsContext.getChooser(), this);
    }

    @Override
    public PskRsaClientKeyExchangeSerializer getSerializer(TlsContext tlsContext) {
        return new PskRsaClientKeyExchangeSerializer(this, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public String toCompactString() {
        return "PSK_RSA_CLIENT_KEY_EXCHANGE";
    }

    @Override
    public String toShortString() {
        return "PSK_RSA_CKE";
    }
}
