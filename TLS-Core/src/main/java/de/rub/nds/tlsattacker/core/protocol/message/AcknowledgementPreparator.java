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
        LOGGER.error("Not implemented yet");
    }
}
