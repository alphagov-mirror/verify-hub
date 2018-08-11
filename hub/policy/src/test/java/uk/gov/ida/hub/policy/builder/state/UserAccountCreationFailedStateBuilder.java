package uk.gov.ida.hub.policy.builder.state;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import uk.gov.ida.hub.policy.builder.domain.SessionIdBuilder;
import uk.gov.ida.hub.policy.domain.SessionId;
import uk.gov.ida.hub.policy.domain.state.UserAccountCreationFailedState;

import java.net.URI;
import java.util.Optional;

public class UserAccountCreationFailedStateBuilder {

    private String requestId = "requestId";
    private String requestIssuerId = "requestIssuerId";
    private URI assertionConsumerServiceUri = URI.create("/default-service-index");
    private DateTime sessionExpiryTimestamp = DateTime.now(DateTimeZone.UTC).plusMinutes(10);
    private SessionId sessionId = SessionIdBuilder.aSessionId().build();
    private boolean transactionSupportsEidas = false;

    public static UserAccountCreationFailedStateBuilder aUserAccountCreationFailedState() {
        return new UserAccountCreationFailedStateBuilder();
    }

    public UserAccountCreationFailedState build() {
        return new UserAccountCreationFailedState(
                requestId,
                requestIssuerId,
                sessionExpiryTimestamp,
                assertionConsumerServiceUri,
                Optional.empty(),
                sessionId,
                transactionSupportsEidas
        );
    }

    public UserAccountCreationFailedStateBuilder withSessionId(SessionId sessionId) {
        this.sessionId = sessionId;
        return this;
    }
}
