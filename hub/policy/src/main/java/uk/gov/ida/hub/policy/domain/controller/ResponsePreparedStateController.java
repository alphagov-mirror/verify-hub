package uk.gov.ida.hub.policy.domain.controller;

import uk.gov.ida.hub.policy.domain.ResponseFromHub;
import uk.gov.ida.hub.policy.domain.StateController;

public interface ResponsePreparedStateController extends StateController {
    ResponseFromHub getPreparedResponse();
}
