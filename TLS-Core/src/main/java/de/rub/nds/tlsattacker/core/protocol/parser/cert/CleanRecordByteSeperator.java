/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.cert;

import de.rub.nds.tlsattacker.core.protocol.Parser;
import de.rub.nds.tlsattacker.core.record.Record;
import java.io.InputStream;
import java.util.List;

/**
 * //TODO I am not sure if this implementation is so smart since it extends Parser which is designed for Message objects
 * and is called ByteSeperator //I Think another logical abstraction is needed here
 */
public class CleanRecordByteSeperator extends Parser<List<Record>> {

    private final int defaultMaxSize;

    public CleanRecordByteSeperator(int defaultMaxSize, InputStream stream) {
        super(stream);
        this.defaultMaxSize = defaultMaxSize;
    }

    @Override
    public void parse(List<Record> records) {
        for (Record record : records) {
            Integer maxData = record.getMaxRecordLengthConfig();
            if (maxData == null) {
                maxData = defaultMaxSize;
            }
            record.setCleanProtocolMessageBytes(parseArrayOrTillEnd(maxData));
        }
    }

}
