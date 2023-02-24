/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.exceptions.EndOfStreamException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.exceptions.TimeoutException;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.hints.RecordLayerHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.tlsattacker.core.layer.stream.HintedLayerInputStream;
import de.rub.nds.tlsattacker.core.protocol.MessageFactory;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The MessageLayer handles TLS Handshake messages. The encapsulation into records happens in the
 * {@link RecordLayer}.
 */
public class MessageLayer extends ProtocolLayer<LayerProcessingHint, ProtocolMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsContext context;

    public MessageLayer(TlsContext context) {
        super(ImplementedLayers.MESSAGE);
        this.context = context;
    }

    /**
     * Sends the given handshake messages using the lower layer.
     *
     * @return LayerProcessingResult A result object containing information about the sent data.
     * @throws IOException When the data cannot be sent.
     */
    @Override
    public LayerProcessingResult sendConfiguration() throws IOException {
        LayerConfiguration<ProtocolMessage> configuration = getLayerConfiguration();
        if (configuration != null && configuration.getContainerList() != null) {
            for (ProtocolMessage message : configuration.getContainerList()) {
                ProtocolMessagePreparator preparator = message.getPreparator(context);
                try {
                    preparator.prepare();
                    preparator.afterPrepare();
                } catch (PreparationException ex) {
                    LOGGER.error(
                            "Could not prepare message "
                                    + message.toCompactString()
                                    + ". Therefore, we skip it: ",
                            ex);
                    continue;
                }
                ProtocolMessageSerializer serializer = message.getSerializer(context);
                byte[] serializedMessage = serializer.serialize();
                message.setCompleteResultingMessage(serializedMessage);
                message.getHandler(context).updateDigest(message, true);
                message.getHandler(context).adjustContext(message);
                getLowerLayer()
                        .sendData(
                                new RecordLayerHint(message.getProtocolMessageType()),
                                serializedMessage);
                message.getHandler(context).adjustContextAfterSerialize(message);
                addProducedContainer(message);
            }
        }
        return getLayerResult();
    }

    @Override
    public LayerProcessingResult sendData(LayerProcessingHint hint, byte[] additionalData)
            throws IOException {
        throw new UnsupportedOperationException(
                "Not supported yet."); // To change body of generated methods, choose
        // Tools | Templates.
    }

    @Override
    public HintedLayerInputStream getDataStream() {
        throw new UnsupportedOperationException(
                "Not supported yet."); // To change body of generated methods, choose
        // Tools | Templates.
    }

    /**
     * Receives handshake message from the lower layer.
     *
     * @return LayerProcessingResult A result object containing information about the received data.
     */
    @Override
    public LayerProcessingResult receiveData() {
        try {
            HintedInputStream dataStream;
            do {
                try {
                    dataStream = getLowerLayer().getDataStream();
                } catch (IOException e) {
                    // the lower layer does not give us any data so we can simply return here
                    LOGGER.warn("The lower layer did not produce a data stream: ", e);
                    return getLayerResult();
                }
                LayerProcessingHint tempHint = dataStream.getHint();
                if (tempHint == null) {
                    LOGGER.warn(
                            "The TLS message layer requires a processing hint. E.g. a record type. Parsing as an unknown message");
                    readUnknownProtocolData();
                } else if (tempHint instanceof RecordLayerHint) {
                    RecordLayerHint hint = (RecordLayerHint) dataStream.getHint();
                    switch (hint.getType()) {
                            // use correct parser for the message
                        case ALERT:
                            readAlertProtocolData();
                            break;
                        case APPLICATION_DATA:
                            readAppDataProtocolData();
                            break;
                        case CHANGE_CIPHER_SPEC:
                            readCcsProtocolData(hint.getEpoch());
                            break;
                        case HANDSHAKE:
                            readHandshakeProtocolData();
                            break;
                        case HEARTBEAT:
                            readHeartbeatProtocolData();
                            break;
                        case UNKNOWN:
                            readUnknownProtocolData();
                            break;
                        default:
                            LOGGER.error("Undefined record layer type");
                            break;
                    }
                }
                // receive until the layer configuration is satisfied or no data is left
            } while (shouldContinueProcessing());
        } catch (TimeoutException ex) {
            LOGGER.debug(ex);
        } catch (EndOfStreamException ex) {
            LOGGER.debug("Reached end of stream, cannot parse more messages", ex);
        }

        return getLayerResult();
    }

    private void readAlertProtocolData() {
        AlertMessage message = new AlertMessage();
        readDataContainer(message, context);
    }

    private void readAppDataProtocolData() {
        ApplicationMessage message = new ApplicationMessage();
        readDataContainer(message, context);
        getLowerLayer().removeDrainedInputStream();
    }

    private void readCcsProtocolData(Integer epoch) {
        ChangeCipherSpecMessage message = new ChangeCipherSpecMessage();
        if (context.getSelectedProtocolVersion().isDTLS()) {
            if (context.getDtlsReceivedChangeCipherSpecEpochs().contains(epoch)
                    && context.getConfig().isIgnoreRetransmittedCcsInDtls()) {
                message.setAdjustContext(false);
            } else {
                context.addDtlsReceivedChangeCipherSpecEpochs(epoch);
            }
        }
        readDataContainer(message, context);
    }

    /**
     * Parses the handshake layer header from the given message and parses the encapsulated message
     * using the correct parser.
     *
     * @throws IOException
     */
    private void readHandshakeProtocolData() {
        byte[] readBytes = new byte[0];
        byte type;
        int length;
        byte[] payload;
        HandshakeMessage handshakeMessage;
        HintedInputStream handshakeStream;
        try {
            handshakeStream = getLowerLayer().getDataStream();
            type = handshakeStream.readByte();
            readBytes = ArrayConverter.concatenate(readBytes, new byte[] {type});
            handshakeMessage =
                    MessageFactory.generateHandshakeMessage(
                            HandshakeMessageType.getMessageType(type), context);
            handshakeMessage.setType(type);
            byte[] lengthBytes =
                    handshakeStream.readChunk(HandshakeByteLength.MESSAGE_LENGTH_FIELD);
            length = ArrayConverter.bytesToInt(lengthBytes);
            readBytes = ArrayConverter.concatenate(readBytes, lengthBytes);
            handshakeMessage.setLength(length);
            payload = handshakeStream.readChunk(length);
            readBytes = ArrayConverter.concatenate(readBytes, payload);

        } catch (IOException ex) {
            LOGGER.error("Could not parse message header. Setting bytes as unread: ", ex);
            // not being able to parse the header leaves us with unreadable bytes
            // append instead of replace because we can read multiple messages in one read action
            setUnreadBytes(ArrayConverter.concatenate(this.getUnreadBytes(), readBytes));
            return;
        }
        Handler handler = handshakeMessage.getHandler(context);
        handshakeMessage.setMessageContent(payload);

        try {
            handshakeMessage.setCompleteResultingMessage(
                    ArrayConverter.concatenate(
                            new byte[] {type},
                            ArrayConverter.intToBytes(
                                    length, HandshakeByteLength.MESSAGE_LENGTH_FIELD),
                            payload));
            Parser parser = handshakeMessage.getParser(context, new ByteArrayInputStream(payload));
            parser.parse(handshakeMessage);
            Preparator preparator = handshakeMessage.getPreparator(context);
            preparator.prepareAfterParse();
            if (context.getChooser().getSelectedProtocolVersion().isDTLS()) {
                handshakeMessage.setMessageSequence(
                        ((RecordLayerHint) handshakeStream.getHint()).getMessageSequence());
            }
            handshakeMessage.getHandler(context).updateDigest(handshakeMessage, false);
            handler.adjustContext(handshakeMessage);
            addProducedContainer(handshakeMessage);
        } catch (RuntimeException ex) {
            LOGGER.error("Could not adjust context", ex);
            // not being able to handle the handshake message results in an UnknownMessageContainer
            UnknownHandshakeMessage message = new UnknownHandshakeMessage();
            message.setData(payload);
            addProducedContainer(message);
        }
    }

    private void readHeartbeatProtocolData() {
        HeartbeatMessage message = new HeartbeatMessage();
        readDataContainer(message, context);
    }

    private void readUnknownProtocolData() {
        UnknownMessage message = new UnknownMessage();
        readDataContainer(message, context);
        getLowerLayer().removeDrainedInputStream();
    }

    @Override
    public void receiveMoreDataForHint(LayerProcessingHint hint) {
        throw new UnsupportedOperationException(
                "Not supported yet."); // To change body of generated methods, choose
        // Tools | Templates.
    }
}
