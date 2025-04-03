package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageSerializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AcknowledgementSerializer extends ProtocolMessageSerializer<AcknowledgementMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AcknowledgementSerializer(AcknowledgementMessage message) {
        super(message);
    }

    @Override
    protected byte[] serializeBytes() {
        LOGGER.error("Not implemented yet");
        return getAlreadySerialized();
    }
}
