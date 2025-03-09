/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import static de.rub.nds.tlsattacker.core.util.LoggerPrintConverter.bytesToHexWithSpaces;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageParser;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AcknowledgementParser extends ProtocolMessageParser<AcknowledgementMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AcknowledgementParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(AcknowledgementMessage message) {
        LOGGER.debug("[DEBUG] Parsing AcknowledgementMessage");
        parseRecordNumberLength(message);
        parseRecordNumbers(message);
        message.setCompleteResultingMessage(getAlreadyParsed());
    }

    private void parseRecordNumberLength(AcknowledgementMessage message) {
        message.setRecordNumberLength(parseIntField(2));
        LOGGER.debug("[DEBUG] RecordNumberLength: " + message.getRecordNumberLength().getValue());
    }

    private void parseRecordNumbers(AcknowledgementMessage message) {
        int bytesLeft = getBytesLeft();
        byte[] recordNumbersBytes = parseByteArrayField(bytesLeft);
        message.setRecordNumbers(recordNumbersBytes);
        LOGGER.debug("[DEBUG] RecordNumbers (raw): {}", bytesToHexWithSpaces(recordNumbersBytes));

        List<AcknowledgementMessage.RecordNumberStruct> parsedRecordNumbers = new ArrayList<>();

        int recordNumberSize = 16; // 8 bytes for epoch + 8 bytes for sequence number

        if (bytesLeft % recordNumberSize != 0) {
            LOGGER.warn(
                    "Record numbers data length ({}) is not a multiple of RecordNumber size ({})",
                    bytesLeft,
                    recordNumberSize);
        }

        for (int i = 0; i < bytesLeft; i += recordNumberSize) {
            if (i + recordNumberSize <= bytesLeft) {
                // parse epoch
                long epoch = 0;
                for (int j = 0; j < 8; j++) {
                    epoch = (epoch << 8) | (recordNumbersBytes[i + j] & 0xFF);
                }
                // parse sequence number
                long sequenceNumber = 0;
                for (int j = 0; j < 8; j++) {
                    sequenceNumber = (sequenceNumber << 8) | (recordNumbersBytes[i + 8 + j] & 0xFF);
                }

                parsedRecordNumbers.add(
                        new AcknowledgementMessage.RecordNumberStruct(epoch, sequenceNumber));
                LOGGER.debug(
                        "[DEBUG] Parsed record number: epoch={}, sequenceNumber={}",
                        epoch,
                        sequenceNumber);
            }
        }

        message.setParsedRecordNumbers(parsedRecordNumbers);
    }
}
