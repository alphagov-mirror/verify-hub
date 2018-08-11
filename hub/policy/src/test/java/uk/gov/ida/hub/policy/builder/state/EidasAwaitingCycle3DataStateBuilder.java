package uk.gov.ida.hub.policy.builder.state;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import uk.gov.ida.hub.policy.domain.LevelOfAssurance;
import uk.gov.ida.hub.policy.domain.PersistentId;
import uk.gov.ida.hub.policy.domain.SessionId;
import uk.gov.ida.hub.policy.domain.state.EidasAwaitingCycle3DataState;

import java.net.URI;
import java.util.Optional;

public class EidasAwaitingCycle3DataStateBuilder {

    private SessionId sessionId = new SessionId("sessionId");

    public static EidasAwaitingCycle3DataStateBuilder anEidasAwaitingCycle3DataState() {
        return new EidasAwaitingCycle3DataStateBuilder();
    }

    public EidasAwaitingCycle3DataStateBuilder withSessionId(SessionId sessionId) {
        this.sessionId = sessionId;
        return this;
    }

    public EidasAwaitingCycle3DataState build() {
        return new EidasAwaitingCycle3DataState(
            "requestId",
            "requestIssuerId",
            DateTime.now(DateTimeZone.UTC).plusMinutes(10),
            URI.create("assertionConsumerServiceUri"),
            sessionId,
            true,
            "identityProviderEntityId",
            "matchingServiceAdapterEntityId",
            Optional.of("relayState"),
            new PersistentId("nameId"),
            LevelOfAssurance.LEVEL_2,
            "encryptedIdentityAssertion"
        );
    }
}
