/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AcknowledgementPreparator extends ProtocolMessagePreparator<AcknowledgementMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final AcknowledgementMessage msg;

    public AcknowledgementPreparator(
            Chooser chooser, AcknowledgementMessage acknowledgementMessage) {
        super(chooser, acknowledgementMessage);
        this.msg = acknowledgementMessage;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        LOGGER.error("Not implemented yet");
    }
}
