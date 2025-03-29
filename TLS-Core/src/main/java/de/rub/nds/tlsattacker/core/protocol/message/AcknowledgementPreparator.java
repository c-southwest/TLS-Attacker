package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AcknowledgementPreparator extends ProtocolMessagePreparator<AcknowledgementMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final AcknowledgementMessage msg;

    public AcknowledgementPreparator(
            Chooser chooser, AcknowledgementMessage acknowledgementMessage) {
        super(chooser, acknowledgementMessage);
        this.msg = acknowledgementMessage;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        var tlsContext = chooser.getContext().getTlsContext();
        int size = tlsContext.trackedAckSeqNumber.size();
        for (int i = 0; i < size; i++) {
            msg.addRecordNumber(
                    tlsContext.trackedAckEpoch.get(i), tlsContext.trackedAckSeqNumber.get(i));
        }
        msg.setRecordNumberLength(16 * size); // 8 for epoch & 8 for seq number
    }
}
