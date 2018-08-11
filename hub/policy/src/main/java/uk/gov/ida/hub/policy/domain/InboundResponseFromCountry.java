package uk.gov.ida.hub.policy.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.Optional;

// This annotation is required for ZDD where we may add fields to newer versions of this DTO
@JsonIgnoreProperties(ignoreUnknown = true)
public class InboundResponseFromCountry {
    private IdpIdaStatus.Status status;
    private String issuer;
    private Optional<String> persistentId;
    private Optional<String> statusMessage;
    private Optional<String> encryptedIdentityAssertionBlob;
    private Optional<LevelOfAssurance> levelOfAssurance;

    public InboundResponseFromCountry(IdpIdaStatus.Status status, Optional<String> statusMessage, String issuer, Optional<String> encryptedIdentityAssertionBlob, Optional<String> persistentId, Optional<LevelOfAssurance> levelOfAssurance) {
        this.status = status;
        this.statusMessage = statusMessage;
        this.issuer = issuer;
        this.encryptedIdentityAssertionBlob = encryptedIdentityAssertionBlob;
        this.persistentId = persistentId;
        this.levelOfAssurance = levelOfAssurance;
    }

    protected InboundResponseFromCountry() {
    }

    public IdpIdaStatus.Status getStatus() {
        return status;
    }

    public String getIssuer() {
        return issuer;
    }

    public Optional<String> getStatusMessage() {
        return statusMessage;
    }

    public Optional<String> getPersistentId() {
        return persistentId;
    }

    public Optional<LevelOfAssurance> getLevelOfAssurance() {
        return levelOfAssurance;
    }

    public Optional<String> getEncryptedIdentityAssertionBlob() {
        return encryptedIdentityAssertionBlob;
    }
}

