package uk.gov.ida.hub.policy.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.joda.time.DateTime;
import uk.gov.ida.saml.core.domain.EidasUnsignedAssertions;

import java.util.Optional;
import java.util.List;

// This annotation is required for ZDD where we may add fields to newer versions of this DTO
@JsonIgnoreProperties(ignoreUnknown = true)
public class InboundResponseFromCountry {
    private CountryAuthenticationStatus.Status status;
    private String issuer;
    private Optional<String> persistentId;
    private Optional<String> statusMessage;
    private Optional<String> encryptedIdentityAssertionBlob;
    private Optional<LevelOfAssurance> levelOfAssurance;
    private Optional<DateTime> notOnOrAfter;
    private Optional<EidasUnsignedAssertions> unsignedAssertions;

    public InboundResponseFromCountry(CountryAuthenticationStatus.Status status,
                                      Optional<String> statusMessage, String issuer,
                                      Optional<String> encryptedIdentityAssertionBlob,
                                      Optional<String> persistentId,
                                      Optional<LevelOfAssurance> levelOfAssurance,
                                      Optional<DateTime> notOnOrAfter,
                                      Optional<EidasUnsignedAssertions> unsignedAssertions) {
        this.status = status;
        this.statusMessage = statusMessage;
        this.issuer = issuer;
        this.encryptedIdentityAssertionBlob = encryptedIdentityAssertionBlob;
        this.persistentId = persistentId;
        this.levelOfAssurance = levelOfAssurance;
        this.notOnOrAfter = notOnOrAfter;
        this.unsignedAssertions = unsignedAssertions;
    }

    protected InboundResponseFromCountry() {
    }

    public CountryAuthenticationStatus.Status getStatus() {
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

    public Optional<DateTime> getNotOnOrAfter() {
        return notOnOrAfter;
    }

    public Optional<EidasUnsignedAssertions> getUnsignedAssertions() {
        return unsignedAssertions;
    }
}
