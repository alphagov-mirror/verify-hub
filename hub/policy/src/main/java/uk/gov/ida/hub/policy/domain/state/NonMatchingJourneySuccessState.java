package uk.gov.ida.hub.policy.domain.state;

import com.google.common.base.Optional;
import org.joda.time.DateTime;
import uk.gov.ida.hub.policy.domain.AbstractState;
import uk.gov.ida.hub.policy.domain.SessionId;

import java.net.URI;
import java.util.List;

public class NonMatchingJourneySuccessState extends AbstractState implements ResponsePreparedState {

    private final Optional<String> relayState;
    private final List<String> encryptedAssertions;

    public NonMatchingJourneySuccessState(
        final String requestId,
        final String requestIssuerEntityId,
        final DateTime sessionExpiryTimestamp,
        final URI assertionConsumerServiceUri,
        final SessionId sessionId,
        final boolean transactionSupportsEidas,
        final Optional<String> relayState,
        final List<String> encryptedAssertions
    ) {
        super(
            requestId,
            requestIssuerEntityId,
            sessionExpiryTimestamp,
            assertionConsumerServiceUri,
            sessionId,
            transactionSupportsEidas,
            null
        );

        this.relayState = relayState;
        this.encryptedAssertions = encryptedAssertions;

        /*
         TODO - We're also going to need:
           * A status (TransactionIdaStatus)  <-- it looks like this is derived elsewhere and won't be needed here.
           * A responseId - but I suspect we get that from somewhere else.
         */
    }

    @Override
    public Optional<String> getRelayState() {
        return relayState;
    }

}
