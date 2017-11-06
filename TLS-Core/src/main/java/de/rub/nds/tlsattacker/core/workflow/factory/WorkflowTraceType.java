/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.factory;

public enum WorkflowTraceType {
    FULL,
    HANDSHAKE,
    HELLO,
    SHORT_HELLO,
    RESUMPTION,
    FULL_RESUMPTION,
    CLIENT_RENEGOTIATION,
    SERVER_RENEGOTIATION,
    HTTPS,
    SSL2_HELLO,
    SIMPLE_MITM_PROXY;
}
