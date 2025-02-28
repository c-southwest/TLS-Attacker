/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedLayerInputStream;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.udp.UdpDataPacket;
import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 * The UDP layer is a wrapper around an underlying UDP socket. It forwards the sockets InputStream
 * for reading and sends any data over the UDP layer without modifications.
 */
public class FirstCachedUdpLayer extends UdpLayer {

    private byte[] firstClientHello = null;
    private boolean isFirstClientHelloConsumed = false;

    public boolean isFuzzingClient = false;

    public FirstCachedUdpLayer(Context context) {
        super(context);
    }

    public void setFirstClientHelo(byte[] bytes) {
        this.firstClientHello = bytes;
    }

    public byte[] getFirstClientHelo() {
        return this.firstClientHello;
    }

    @Override
    public void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException {
        byte[] receivedPacket = null;
        if (!isFirstClientHelloConsumed && isFuzzingClient) {
            receivedPacket = firstClientHello;
            isFirstClientHelloConsumed = true;
        } else {
            receivedPacket = getTransportHandler().fetchData();
        }
        UdpDataPacket udpDataPacket = new UdpDataPacket();
        udpDataPacket
                .getParser(context, new ByteArrayInputStream(receivedPacket))
                .parse(udpDataPacket);
        udpDataPacket.getPreparator(context).prepareAfterParse();
        udpDataPacket.getHandler(context).adjustContext(udpDataPacket);
        addProducedContainer(udpDataPacket);
        if (currentInputStream == null) {
            currentInputStream = new HintedLayerInputStream(null, this);
            currentInputStream.extendStream(receivedPacket);
        } else {
            currentInputStream.extendStream(receivedPacket);
        }
    }
}
