/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.exception.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageSerializer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AcknowledgementSerializer extends ProtocolMessageSerializer<AcknowledgementMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AcknowledgementSerializer(AcknowledgementMessage message) {
        super(message);
    }

    @Override
    protected byte[] serializeBytes() {
        writeRecordNumberLength();
        writeRecordNumbers();
        return getAlreadySerialized();
    }

    private void writeRecordNumberLength() {
        appendInt(message.getRecordNumberLength().getValue(), 2);
        LOGGER.debug("RecordNumberLength: {}", message.getRecordNumberLength().getValue());
    }

    private void writeRecordNumbers() {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        List<AcknowledgementMessage.RecordNumberStruct> records = message.getParsedRecordNumbers();

        if (records != null && !records.isEmpty()) {
            try {
                for (AcknowledgementMessage.RecordNumberStruct record : records) {
                    // Write epoch (8 bytes)
                    byte[] epochBytes = new byte[8];
                    long epoch = record.getEpoch();
                    for (int i = 7; i >= 0; i--) {
                        epochBytes[i] = (byte) (epoch & 0xFF);
                        epoch >>= 8;
                    }
                    outputStream.write(epochBytes);

                    // Write sequence number (8 bytes)
                    byte[] seqBytes = new byte[8];
                    long seq = record.getSequenceNumber();
                    for (int i = 7; i >= 0; i--) {
                        seqBytes[i] = (byte) (seq & 0xFF);
                        seq >>= 8;
                    }
                    outputStream.write(seqBytes);

                    LOGGER.debug(
                            "Serialized record number: epoch={}, sequenceNumber={}",
                            record.getEpoch(),
                            record.getSequenceNumber());
                }

                byte[] recordNumbersBytes = outputStream.toByteArray();
                appendBytes(recordNumbersBytes);
                LOGGER.debug(
                        "RecordNumbers: {}", ArrayConverter.bytesToHexString(recordNumbersBytes));

            } catch (IOException ex) {
                throw new PreparationException("Could not write RecordNumbers", ex);
            }
        } else {
            LOGGER.debug("No RecordNumbers to serialize");
        }
    }
}
