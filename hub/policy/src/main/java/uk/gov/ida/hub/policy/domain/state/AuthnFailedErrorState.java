package uk.gov.ida.hub.policy.domain.state;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Optional;
import org.joda.time.DateTime;
import uk.gov.ida.hub.policy.domain.AbstractState;
import uk.gov.ida.hub.policy.domain.SessionId;

import java.net.URI;

public class AuthnFailedErrorState extends AbstractState implements IdpSelectingState, ResponsePreparedState {

    private static final long serialVersionUID = 8101005936409595481L;

    private String relayState;
    private String idpEntityId;
    private Boolean forceAuthentication;

    @JsonCreator
    public AuthnFailedErrorState(
            @JsonProperty("requestId") String requestId,
            @JsonProperty("authnRequestIssuerEntityId") String authnRequestIssuerEntityId,
            @JsonProperty("sessionExpiryTimestamp") DateTime sessionExpiryTimestamp,
            @JsonProperty("assertionConsumerServiceUri") URI assertionConsumerServiceUri,
            @JsonProperty("relayState") String relayState,
            @JsonProperty("sessionId") SessionId sessionId,
            @JsonProperty("idpEntityId") String idpEntityId,
            @JsonProperty("forceAuthentication") Boolean forceAuthentication,
            @JsonProperty("transactionSupportsEidas") boolean transactionSupportsEidas) {

        super(requestId, authnRequestIssuerEntityId, sessionExpiryTimestamp, assertionConsumerServiceUri, sessionId, transactionSupportsEidas);

        this.relayState = relayState;
        this.idpEntityId = idpEntityId;
        this.forceAuthentication = forceAuthentication;
    }

    @Override
    public Optional<Boolean> getForceAuthentication() {
        return Optional.fromNullable(forceAuthentication);
    }

    @Override
    public Optional<String> getRelayState() {
        return Optional.fromNullable(relayState);
    }

    public String getIdpEntityId() {
        return idpEntityId;
    }
}
