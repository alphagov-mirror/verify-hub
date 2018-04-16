package uk.gov.ida.hub.policy.domain.state;

import org.joda.time.DateTime;
import uk.gov.ida.hub.policy.domain.LevelOfAssurance;
import uk.gov.ida.hub.policy.domain.PersistentId;
import uk.gov.ida.hub.policy.domain.SessionId;
import uk.gov.ida.hub.policy.statemachine.StateTNG;

import java.io.Serializable;
import java.net.URI;

public class Cycle3MatchRequestSentState extends Cycle0And1MatchRequestSentState implements Serializable {

    private static final long serialVersionUID = 7239719376154151711L;

    public Cycle3MatchRequestSentState(
            final String requestId,
            final String requestIssuerEntityId,
            final DateTime sessionExpiryTime,
            final URI assertionConsumerServiceIndex,
            final SessionId sessionId,
            final boolean transactionSupportsEidas,
            final String identityProviderEntityId,
            final String relayState,
            final LevelOfAssurance idpLevelOfAssurance,
            final boolean registering,
            final String matchingServiceAdapterEntityId,
            final String encryptedMatchingDatasetAssertion,
            final String authnStatementAssertion,
            final PersistentId persistentId) {

        super(
                requestId,
                requestIssuerEntityId,
                sessionExpiryTime,
                assertionConsumerServiceIndex,
                sessionId,
                transactionSupportsEidas,
                registering,
                identityProviderEntityId,
                relayState,
                idpLevelOfAssurance,
                matchingServiceAdapterEntityId,
                encryptedMatchingDatasetAssertion,
                authnStatementAssertion,
                persistentId
        );
    }

    @Override
    public StateTNG getThisState(){
        return StateTNG.Cycle3_Match_Request_Sent;
    }
}
