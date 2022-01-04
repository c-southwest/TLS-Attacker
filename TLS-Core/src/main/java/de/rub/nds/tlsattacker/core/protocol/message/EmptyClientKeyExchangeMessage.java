/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.handler.EmptyClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.message.computations.EmptyClientComputations;
import de.rub.nds.tlsattacker.core.protocol.parser.EmptyClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.EmptyClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.EmptyClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

import javax.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.List;

@XmlRootElement(name = "EmptyClientKeyExchange")
public class EmptyClientKeyExchangeMessage extends ClientKeyExchangeMessage {

    @HoldsModifiableVariable
    protected EmptyClientComputations computations;

    public EmptyClientKeyExchangeMessage() {
        super();
    }

    public EmptyClientKeyExchangeMessage(Config tlsConfig) {
        super(tlsConfig);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("EmptyClientKeyExchangeMessage:");
        return sb.toString();
    }

    @Override
    public EmptyClientComputations getComputations() {
        return computations;
    }

    @Override
    public EmptyClientKeyExchangeHandler getHandler(TlsContext context) {
        return new EmptyClientKeyExchangeHandler(context);
    }

    @Override
    public EmptyClientKeyExchangeParser getParser(TlsContext tlsContext, InputStream stream) {
        return new EmptyClientKeyExchangeParser(stream, tlsContext.getChooser().getLastRecordVersion(), tlsContext);
    }

    @Override
    public EmptyClientKeyExchangePreparator getPreparator(TlsContext tlsContext) {
        return new EmptyClientKeyExchangePreparator(tlsContext.getChooser(), this);
    }

    @Override
    public EmptyClientKeyExchangeSerializer getSerializer(TlsContext tlsContext) {
        return new EmptyClientKeyExchangeSerializer(this, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public String toCompactString() {
        return "EMPTY_CLIENT_KEY_EXCHANGE";
    }

    @Override
    public String toShortString() {
        return "E_CKE";
    }

    @Override
    public void prepareComputations() {
        if (getComputations() == null) {
            computations = new EmptyClientComputations();
        }
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (computations != null) {
            holders.add(computations);
        }
        return holders;
    }
}
