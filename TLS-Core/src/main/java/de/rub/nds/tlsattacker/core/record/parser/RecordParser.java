/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record.parser;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.record.Record;
import java.io.InputStream;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordParser extends Parser<Record> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ProtocolVersion version;
    private final TlsContext tlsContext;

    public RecordParser(InputStream stream, ProtocolVersion version, TlsContext tlsContext) {
        super(stream);
        this.version = version;
        this.tlsContext = tlsContext;
    }

    @Override
    public void parse(Record record) {
        LOGGER.debug("Parsing Record");
        byte firstByte = parseByteField(1);
        if ((firstByte & 0xE0) == 0x20) { // 检查前三位是否为001
            // DTLS 1.3 unified header
            LOGGER.debug("Parsing DTLS 1.3 Record with Unified Header");
            record.setUnifiedHeaderBitmask(firstByte);
            parseUnifiedHeader(record, firstByte);
        } else {
            record.setContentType(firstByte);
            LOGGER.debug("ContentType: {}", record.getContentType().getValue());
            ProtocolMessageType protocolMessageType =
                    ProtocolMessageType.getContentType(record.getContentType().getValue());
            if (protocolMessageType == null) {
                protocolMessageType = ProtocolMessageType.UNKNOWN;
            }
            record.setContentMessageType(protocolMessageType);
            parseVersion(record);
            if (version.isDTLS()) {
                parseEpoch(record);
                parseSequenceNumber(record);
                if (protocolMessageType == ProtocolMessageType.TLS12_CID) {
                    parseConnectionId(record);
                }
            }
            parseLength(record);
            parseProtocolMessageBytes(record);
        }
        record.setCompleteRecordBytes(getAlreadyParsed());
    }

    private void parseUnifiedHeader(Record record, byte bitmask) {
        // Connection ID
        if ((bitmask & 0x10) != 0) {
            LOGGER.error("Don't support Connection ID yet.");
        }

        // sequence number
        int seqNumLength = ((bitmask & 0x08) != 0) ? 2 : 1;
        int seqNumValue = parseIntField(seqNumLength);
        record.setSequenceNumberSuffix(seqNumValue);

        // TODO: seqNumLength is only 2 bytes, but the real sequence number is 6 bytes
        record.setSequenceNumber(BigInteger.valueOf(seqNumValue));
        LOGGER.debug("SequenceNumber: {}", record.getSequenceNumber().getValue());

        // epoch
        int epochValue = bitmask & 0x03;
        record.setEpoch(epochValue);
        LOGGER.debug("Epoch: {}", record.getEpoch().getValue());

        // length
        if ((bitmask & 0x04) != 0) {
            record.setLength(parseIntField(2));
            LOGGER.debug("Length: {}", record.getLength().getValue());
        } else {
            record.setLength(getBytesLeft());
        }

        // 解析加密的记录内容
        parseProtocolMessageBytes(record);

        // 由于没有明确的ContentType字段，需要根据epoch推断
        // 这在解密后才能确定
        record.setContentType((byte) 22); // 假设是Handshake类型
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);

        // DTLS 1.3使用TLS 1.2的版本号
        record.setProtocolVersion(ProtocolVersion.DTLS12.getValue());
    }

    private void parseEpoch(Record record) {
        record.setEpoch(parseIntField(RecordByteLength.DTLS_EPOCH));
        LOGGER.debug("Epoch: {}", record.getEpoch().getValue());
    }

    private void parseSequenceNumber(Record record) {
        record.setSequenceNumber(parseBigIntField(RecordByteLength.DTLS_SEQUENCE_NUMBER));
        LOGGER.debug("SequenceNumber: {}", record.getSequenceNumber().getValue());
    }

    private void parseConnectionId(Record record) {
        int connectionIdLength =
                tlsContext
                        .getRecordLayer()
                        .getDecryptor()
                        .getRecordCipher(record.getEpoch().getValue())
                        .getState()
                        .getConnectionId()
                        .length;
        record.setConnectionId(parseByteArrayField(connectionIdLength));
        LOGGER.debug("ConnectionID: {}", record.getConnectionId().getValue());
    }

    private void parseContentType(Record record) {
        record.setContentType(parseByteField(RecordByteLength.CONTENT_TYPE));
        LOGGER.debug("ContentType: {}", record.getContentType().getValue());
    }

    private void parseVersion(Record record) {
        record.setProtocolVersion(parseByteArrayField(RecordByteLength.PROTOCOL_VERSION));
        LOGGER.debug("ProtocolVersion: {}", record.getProtocolVersion().getValue());
    }

    private void parseLength(Record record) {
        record.setLength(parseIntField(RecordByteLength.RECORD_LENGTH));
        LOGGER.debug("Length: {}", record.getLength().getValue());
    }

    private void parseProtocolMessageBytes(Record record) {
        record.setProtocolMessageBytes(parseByteArrayField(record.getLength().getValue()));
        LOGGER.debug("ProtocolMessageBytes: {}", record.getProtocolMessageBytes().getValue());
    }
}
