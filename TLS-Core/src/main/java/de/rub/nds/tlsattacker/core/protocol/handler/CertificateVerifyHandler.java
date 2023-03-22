/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;

public class CertificateVerifyHandler extends HandshakeMessageHandler<CertificateVerifyMessage> {

    public CertificateVerifyHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(CertificateVerifyMessage message) {
        byte[] signatureAndHashAlgorithmBytes = message.getSignatureHashAlgorithm().getValue();
        SignatureAndHashAlgorithm signatureAndHashAlgorithm =
                SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(
                        signatureAndHashAlgorithmBytes);
        tlsContext.setSelectedSignatureAndHashAlgorithm(signatureAndHashAlgorithm);
    }
}
