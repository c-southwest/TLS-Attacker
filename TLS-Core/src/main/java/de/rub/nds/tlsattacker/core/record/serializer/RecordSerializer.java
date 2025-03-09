/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record.serializer;

import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.record.Record;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordSerializer extends Serializer<Record> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Record record;

    public RecordSerializer(Record record) {
        this.record = record;
    }

    @Override
    protected byte[] serializeBytes() {
        LOGGER.debug("Serializing Record");
        if (record.getUnifiedHeaderBitmask() != null) {
            // this record is version DTLS 1.3
            writeUnifiedHeader();
            writeProtocolMessageBytes(record);
        } else {
            writeContentType(record);
            writeProtocolVersion(record);
            if (record.getEpoch() != null) {
                writeEpoch(record);
                writeSequenceNumber(record);
            }
            if (record.getConnectionId() != null) {
                writeConnectionId(record);
            }
            writeLength(record);
            writeProtocolMessageBytes(record);
        }

        return getAlreadySerialized();
    }

    private void writeUnifiedHeader() {
        byte bitmask = record.getUnifiedHeaderBitmask().getValue();
        appendByte(bitmask);
        LOGGER.debug("[DEBUG] write Unified Header Bitmask: {}", bitmask);

        if ((bitmask & 0x10) != 0 && record.getConnectionId() != null) {
            writeConnectionId(record);
        }

        int seqNumLength = ((bitmask & 0x08) != 0) ? 2 : 1;
        appendInt(record.getSequenceNumberSuffix().getValue(), seqNumLength);
        LOGGER.debug(
                "[DEBUG] write Sequence Number Suffix: {}",
                record.getSequenceNumberSuffix().getValue());

        if ((bitmask & 0x04) != 0) {
            writeLength(record);
        }
    }

    private void writeContentType(Record record) {
        appendByte(record.getContentType().getValue());
        LOGGER.debug("ContentType: {}", record.getContentType().getValue());
    }

    private void writeProtocolVersion(Record record) {
        appendBytes(record.getProtocolVersion().getValue());
        LOGGER.debug("ProtocolVersion: {}", record.getProtocolVersion().getValue());
    }

    private void writeLength(Record record) {
        appendInt(record.getLength().getValue(), RecordByteLength.RECORD_LENGTH);
        LOGGER.debug("Length: {}", record.getLength().getValue());
    }

    private void writeConnectionId(Record record) {
        appendBytes(record.getConnectionId().getValue());
        LOGGER.debug("ConnectionID: {}", record.getConnectionId().getValue());
    }

    private void writeEpoch(Record record) {
        appendInt(record.getEpoch().getValue(), RecordByteLength.DTLS_EPOCH);
        LOGGER.debug("Epoch: {}", record.getEpoch().getValue());
    }

    private void writeSequenceNumber(Record record) {
        appendBigInteger(
                record.getSequenceNumber().getValue(), RecordByteLength.DTLS_SEQUENCE_NUMBER);
        LOGGER.debug("SequenceNumber: {}", record.getSequenceNumber().getValue());
    }

    private void writeProtocolMessageBytes(Record record) {
        appendBytes(record.getProtocolMessageBytes().getValue());
        LOGGER.debug("ProtocolMessageBytes: {}", record.getProtocolMessageBytes().getValue());
    }
}
