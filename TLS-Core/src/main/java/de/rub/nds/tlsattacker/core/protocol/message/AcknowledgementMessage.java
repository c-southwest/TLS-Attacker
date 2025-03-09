/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@XmlRootElement(name = "Acknowledgement")
public class AcknowledgementMessage extends ProtocolMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger recordNumberLength;

    @ModifiableVariableProperty private ModifiableByteArray recordNumbers;

    private transient List<RecordNumberStruct> parsedRecordNumbers;

    public AcknowledgementMessage() {
        super();
        this.protocolMessageType = ProtocolMessageType.Acknowledgement;
        this.parsedRecordNumbers = new ArrayList<>();
    }

    public ModifiableInteger getRecordNumberLength() {
        return recordNumberLength;
    }

    public void setRecordNumberLength(ModifiableInteger recordNumberLength) {
        this.recordNumberLength = recordNumberLength;
    }

    public void setRecordNumberLength(int recordNumberLength) {
        this.recordNumberLength =
                ModifiableVariableFactory.safelySetValue(
                        this.recordNumberLength, recordNumberLength);
    }

    public ModifiableByteArray getRecordNumbers() {
        return recordNumbers;
    }

    public void setRecordNumbers(ModifiableByteArray recordNumbers) {
        this.recordNumbers = recordNumbers;
    }

    public void setRecordNumbers(byte[] recordNumbers) {
        this.recordNumbers =
                ModifiableVariableFactory.safelySetValue(this.recordNumbers, recordNumbers);
    }

    public List<RecordNumberStruct> getParsedRecordNumbers() {
        return parsedRecordNumbers;
    }

    public void setParsedRecordNumbers(List<RecordNumberStruct> parsedRecordNumbers) {
        this.parsedRecordNumbers = parsedRecordNumbers;
    }

    public void addRecordNumber(int epoch, long sequenceNumber) {
        this.parsedRecordNumbers.add(new RecordNumberStruct(epoch, sequenceNumber));
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("AckMessage:");
        sb.append("\n  Record Number Length: ");
        if (recordNumberLength != null && recordNumberLength.getValue() != null) {
            sb.append(recordNumberLength.getValue());
        } else {
            sb.append("null");
        }
        sb.append("\n  Record Numbers: ");
        if (parsedRecordNumbers != null && !parsedRecordNumbers.isEmpty()) {
            sb.append("[");
            for (int i = 0; i < parsedRecordNumbers.size(); i++) {
                if (i > 0) {
                    sb.append(", ");
                }
                RecordNumberStruct rn = parsedRecordNumbers.get(i);
                sb.append("(epoch=")
                        .append(rn.getEpoch())
                        .append(", seq=")
                        .append(rn.getSequenceNumber())
                        .append(")");
            }
            sb.append("]");
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Acknowledgement".toUpperCase());
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "ACK";
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final AcknowledgementMessage other = (AcknowledgementMessage) obj;
        if (!Objects.equals(this.recordNumberLength, other.recordNumberLength)) {
            return false;
        }
        return Objects.equals(this.recordNumbers, other.recordNumbers);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 97 * hash + Objects.hashCode(this.recordNumberLength);
        hash = 97 * hash + Objects.hashCode(this.recordNumbers);
        return hash;
    }

    @Override
    public AcknowledgementHandler getHandler(Context context) {
        return new AcknowledgementHandler(context.getTlsContext());
    }

    @Override
    public AcknowledgementParser getParser(Context context, InputStream stream) {
        return new AcknowledgementParser(stream);
    }

    @Override
    public AcknowledgementPreparator getPreparator(Context context) {
        return new AcknowledgementPreparator(context.getChooser(), this);
    }

    @Override
    public AcknowledgementSerializer getSerializer(Context context) {
        return new AcknowledgementSerializer(this);
    }

    public static class RecordNumberStruct {
        private long epoch;
        private long sequenceNumber;

        public RecordNumberStruct(long epoch, long sequenceNumber) {
            this.epoch = epoch;
            this.sequenceNumber = sequenceNumber;
        }

        public long getEpoch() {
            return epoch;
        }

        public void setEpoch(long epoch) {
            this.epoch = epoch;
        }

        public long getSequenceNumber() {
            return sequenceNumber;
        }

        public void setSequenceNumber(long sequenceNumber) {
            this.sequenceNumber = sequenceNumber;
        }
    }
}
