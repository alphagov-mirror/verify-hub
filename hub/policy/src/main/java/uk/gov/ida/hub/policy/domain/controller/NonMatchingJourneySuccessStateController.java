package uk.gov.ida.hub.policy.domain.controller;

import uk.gov.ida.hub.policy.domain.ResponseFromHub;
import uk.gov.ida.hub.policy.domain.ResponseFromHubFactory;
import uk.gov.ida.hub.policy.domain.StateController;
import uk.gov.ida.hub.policy.domain.state.NonMatchingJourneySuccessState;

public class NonMatchingJourneySuccessStateController implements StateController, ErrorResponsePreparedStateController {

    private final NonMatchingJourneySuccessState state;
    private final ResponseFromHubFactory responseFromHubFactory;

    public NonMatchingJourneySuccessStateController(
        final NonMatchingJourneySuccessState state,
        final ResponseFromHubFactory responseFromHubFactory) {

        this.state = state;
        this.responseFromHubFactory = responseFromHubFactory;
    }

    @Override
    public ResponseFromHub getErrorResponse() {
        return responseFromHubFactory.createNoAuthnContextResponseFromHub(
            state.getRequestId(),
            state.getRelayState(),
            state.getRequestIssuerEntityId(),
            state.getAssertionConsumerServiceUri()
        );
    }
}
