/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class DtlsHandshakeMessageFragmentHandler extends HandshakeMessageHandler<DtlsHandshakeMessageFragment> {

    public DtlsHandshakeMessageFragmentHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(DtlsHandshakeMessageFragment message) {
    }
}
