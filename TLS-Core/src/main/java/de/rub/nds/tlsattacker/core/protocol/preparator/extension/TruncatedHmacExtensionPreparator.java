/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.TruncatedHmacExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class TruncatedHmacExtensionPreparator
        extends ExtensionPreparator<TruncatedHmacExtensionMessage> {

    public TruncatedHmacExtensionPreparator(
            Chooser chooser, TruncatedHmacExtensionMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareExtensionContent() {
        // Nothing to prepare here, since it's an opt-in extension
    }
}
