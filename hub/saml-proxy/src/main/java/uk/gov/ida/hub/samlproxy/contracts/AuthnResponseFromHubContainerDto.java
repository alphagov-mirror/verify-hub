package uk.gov.ida.hub.samlproxy.contracts;
import java.util.List;
import java.util.Optional;

import java.net.URI;

public class AuthnResponseFromHubContainerDto {

    private String samlResponse;
    private URI postEndpoint;
    private Optional<String> relayState = Optional.empty();
    private String responseId;
    private Optional<List<String>> encryptedKeys;

    @SuppressWarnings("unused") //Needed for JAXB
    private AuthnResponseFromHubContainerDto() {
    }

    public AuthnResponseFromHubContainerDto(
            final String samlResponse,
            final URI postEndpoint,
            final Optional<String> relayState,
            String responseId,
            final Optional<List<String>> encryptedKeys) {

        this.samlResponse = samlResponse;
        this.postEndpoint = postEndpoint;
        this.relayState = relayState;
        this.responseId = responseId;
        this.encryptedKeys = encryptedKeys;
    }

    public String getSamlResponse() {
        return samlResponse;
    }

    public URI getPostEndpoint() {
        return postEndpoint;
    }

    public Optional<String> getRelayState() {
        return relayState;
    }

    public String getResponseId() {
        return responseId;
    }

    public Optional<List<String>> getEncryptedKeys() { return encryptedKeys; }
}
