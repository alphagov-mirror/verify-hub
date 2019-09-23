package uk.gov.ida.hub.samlproxy.controllogic;

import java.util.List;
import java.util.Optional;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.slf4j.event.Level;
import uk.gov.ida.common.SessionId;
import uk.gov.ida.hub.samlproxy.contracts.AuthnResponseFromHubContainerDto;
import uk.gov.ida.hub.samlproxy.domain.AuthnRequestFromHubContainerDto;
import uk.gov.ida.hub.samlproxy.factories.EidasValidatorFactory;
import uk.gov.ida.hub.samlproxy.logging.ExternalCommunicationEventLogger;
import uk.gov.ida.hub.samlproxy.logging.ProtectiveMonitoringLogger;
import uk.gov.ida.hub.samlproxy.proxy.SessionProxy;
import uk.gov.ida.hub.samlproxy.repositories.Direction;
import uk.gov.ida.hub.samlproxy.repositories.SignatureStatus;
import uk.gov.ida.saml.core.validation.SamlTransformationErrorException;
import uk.gov.ida.saml.core.validation.SamlValidationResponse;
import uk.gov.ida.saml.core.validation.SamlValidationSpecificationFailure;
import uk.gov.ida.saml.deserializers.StringToOpenSamlObjectTransformer;
import uk.gov.ida.saml.security.SamlMessageSignatureValidator;

import javax.inject.Inject;

public class SamlMessageSenderHandler {

    private final StringToOpenSamlObjectTransformer<Response> responseTransformer;
    private final StringToOpenSamlObjectTransformer<AuthnRequest> authnRequestTransformer;
    private final SamlMessageSignatureValidator samlMessageSignatureValidator;
    private final ExternalCommunicationEventLogger externalCommunicationEventLogger;
    private final ProtectiveMonitoringLogger protectiveMonitoringLogger;
    private final SessionProxy sessionProxy;
    private final Optional<EidasValidatorFactory> eidasValidatorFactory;


    @Inject
    public SamlMessageSenderHandler(
            StringToOpenSamlObjectTransformer<Response> responseTransformer,
            StringToOpenSamlObjectTransformer<AuthnRequest> authnRequestTransformer,
            SamlMessageSignatureValidator samlMessageSignatureValidator,
            ExternalCommunicationEventLogger externalCommunicationEventLogger,
            ProtectiveMonitoringLogger protectiveMonitoringLogger,
            SessionProxy sessionProxy,
            Optional<EidasValidatorFactory> eidasValidatorFactory) {

        this.responseTransformer = responseTransformer;
        this.authnRequestTransformer = authnRequestTransformer;
        this.samlMessageSignatureValidator = samlMessageSignatureValidator;
        this.externalCommunicationEventLogger = externalCommunicationEventLogger;
        this.protectiveMonitoringLogger = protectiveMonitoringLogger;
        this.sessionProxy = sessionProxy;
        this.eidasValidatorFactory = eidasValidatorFactory;
    }

    public static class SamlMessage {

        private String samlMessage;
        private SamlMessageType samlMessageType;
        private Optional<String> relayState;
        private String postEndpoint;
        private Optional<Boolean> registration;
        private Optional<List<String>> encryptedKeys;

        @SuppressWarnings("unused") // Needed for JAXB
        public SamlMessage() {
        }

        public SamlMessage(
                String samlMessage,
                SamlMessageType samlMessageType,
                Optional<String> relayState,
                String postEndpoint,
                Optional<Boolean> registration,
                Optional<List<String>> encryptedKeys
        ) {
            this.samlMessage = samlMessage;
            this.samlMessageType = samlMessageType;
            this.relayState = relayState;
            this.postEndpoint = postEndpoint;
            this.registration = registration;
            this.encryptedKeys = encryptedKeys;
        }

        public String getSamlMessage() {
            return samlMessage;
        }

        public SamlMessageType getSamlMessageType() {
            return samlMessageType;
        }

        public Optional<String> getRelayState() {
            return relayState;
        }

        public String getPostEndpoint() {
            return postEndpoint;
        }

        public Optional<Boolean> getRegistration() {
            return registration;
        }

        public Optional<List<String>> getEncryptedKeys() { return encryptedKeys; }
    }

    public SamlMessage generateAuthnResponseFromHub(SessionId sessionId, String principalIpAddressAsSeenByHub) {
        AuthnResponseFromHubContainerDto authnResponseFromHub = sessionProxy.getAuthnResponseFromHub(sessionId);
        Response samlResponse = responseTransformer.apply(authnResponseFromHub.getSamlResponse());
        validateAndLogSamlResponseSignature(samlResponse);
        SamlMessage samlMessage = new SamlMessage(
                authnResponseFromHub.getSamlResponse(),
                SamlMessageType.SAML_RESPONSE,
                authnResponseFromHub.getRelayState(),
                authnResponseFromHub.getPostEndpoint().toString(),
                Optional.empty(),
                authnResponseFromHub.getEncryptedKeys()
        );
        externalCommunicationEventLogger.logResponseFromHub(samlResponse.getID(), sessionId, authnResponseFromHub.getPostEndpoint(), principalIpAddressAsSeenByHub);
        return samlMessage;
    }

    public SamlMessage generateErrorResponseFromHub(final SessionId sessionId, String principalIpAddressAsSeenByHub) {
        AuthnResponseFromHubContainerDto authnResponseFromHub = sessionProxy.getErrorResponseFromHub(sessionId);
        Response samlResponse = responseTransformer.apply(authnResponseFromHub.getSamlResponse());
        validateAndLogSamlResponseSignature(samlResponse);
        SamlMessage samlMessage = new SamlMessage(authnResponseFromHub.getSamlResponse(), SamlMessageType.SAML_RESPONSE, authnResponseFromHub.getRelayState(), authnResponseFromHub.getPostEndpoint().toString(), Optional.empty(), Optional.empty());
        externalCommunicationEventLogger.logResponseFromHub(authnResponseFromHub.getResponseId(), sessionId, authnResponseFromHub.getPostEndpoint(), principalIpAddressAsSeenByHub);
        return samlMessage;
    }

    public SamlMessage generateAuthnRequestFromHub(SessionId sessionId, String principalIpAddress) {
        AuthnRequestFromHubContainerDto authnRequestFromHub = sessionProxy.getAuthnRequestFromHub(sessionId);

        AuthnRequest request = authnRequestTransformer.apply(authnRequestFromHub.getSamlRequest());

        SamlValidationResponse samlSignatureValidationResponse = samlMessageSignatureValidator.validate(request, SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        protectiveMonitoringLogger.logAuthnRequest(request, Direction.OUTBOUND, SignatureStatus.fromValidationResponse(samlSignatureValidationResponse));

        if (!samlSignatureValidationResponse.isOK()) {
            SamlValidationSpecificationFailure failure = samlSignatureValidationResponse.getSamlValidationSpecificationFailure();
            throw new SamlTransformationErrorException(failure.getErrorMessage(), samlSignatureValidationResponse.getCause(), Level.ERROR);
        }
        SamlMessage samlMessage = new SamlMessage(authnRequestFromHub.getSamlRequest(), SamlMessageType.SAML_REQUEST, Optional.ofNullable(sessionId.toString()), authnRequestFromHub.getPostEndpoint().toString(), Optional.of(authnRequestFromHub.getRegistering()), Optional.empty());

        externalCommunicationEventLogger.logIdpAuthnRequest(request.getID(), sessionId, authnRequestFromHub.getPostEndpoint(), principalIpAddress);
        return samlMessage;
    }

    private void validateAndLogSamlResponseSignature(Response samlResponse) {
        Issuer issuer = samlResponse.getIssuer();
        boolean isSigned = issuer != null;
        if (isSigned && shouldValidateCountrySignature(issuer)) {
            eidasValidatorFactory.get().getValidatedResponse(samlResponse);
            protectiveMonitoringLogger.logAuthnResponse(samlResponse, Direction.OUTBOUND, SignatureStatus.COUNTRY_SIGNATURE);

        } else if (isSigned) {
            SamlValidationResponse signatureValidationResponse = samlMessageSignatureValidator.validate(samlResponse, SPSSODescriptor.DEFAULT_ELEMENT_NAME);
            protectiveMonitoringLogger.logAuthnResponse(samlResponse, Direction.OUTBOUND, SignatureStatus.fromValidationResponse(signatureValidationResponse));

            if (!signatureValidationResponse.isOK()) {
                SamlValidationSpecificationFailure failure = signatureValidationResponse.getSamlValidationSpecificationFailure();
                throw new SamlTransformationErrorException(failure.getErrorMessage(), signatureValidationResponse.getCause(), Level.ERROR);
            }
        } else {
            protectiveMonitoringLogger.logAuthnResponse(samlResponse, Direction.OUTBOUND, SignatureStatus.NO_SIGNATURE);
        }
    }

    private boolean shouldValidateCountrySignature(Issuer issuer) {
        return !issuer.getValue().endsWith("signing.service.gov.uk") && eidasValidatorFactory.isPresent();
    }
}
