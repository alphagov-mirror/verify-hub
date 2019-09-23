package uk.gov.ida.hub.policy.contracts;

import java.net.URI;
import java.util.List;
import java.util.Optional;

public interface AuthnResponseContainerDto {
    String getSamlResponse();
    List<String> getEncryptedKeys();
    URI getPostEndpoint();
    Optional<String> getRelayState();
    String getResponseId();
}
