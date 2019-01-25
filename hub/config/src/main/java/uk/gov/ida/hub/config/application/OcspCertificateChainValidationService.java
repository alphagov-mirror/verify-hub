package uk.gov.ida.hub.config.application;

import io.prometheus.client.Gauge;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.hub.config.domain.CertificateDetails;
import uk.gov.ida.hub.config.domain.OCSPCertificateChainValidityChecker;

import java.security.cert.CertificateException;
import java.util.Set;

public class OcspCertificateChainValidationService implements Runnable {
    private static final Logger LOG = LoggerFactory.getLogger(OcspCertificateChainValidationService.class);
    public static final double VALID = 1.0;
    public static final double INVALID = 0.0;
    private final OCSPCertificateChainValidityChecker ocspCertificateChainValidityChecker;
    private final CertificateService certificateService;
    private final Gauge gauge;

    public OcspCertificateChainValidationService(final OCSPCertificateChainValidityChecker ocspCertificateChainValidityChecker,
                                                 final CertificateService certificateService,
                                                 final Gauge gauge) {
        this.ocspCertificateChainValidityChecker = ocspCertificateChainValidityChecker;
        this.certificateService = certificateService;
        this.gauge = gauge;
    }

    @Override
    public void run() {
        final Set<CertificateDetails> certificateDetailsSet = certificateService.getAllCertificatesDetails();
        final String TIMESTAMP = DateTime.now(DateTimeZone.UTC).toString();
        gauge.clear();
        certificateDetailsSet.forEach(
            certificateDetails -> {
                try {
                    gauge.labels(
                        certificateDetails.getIssuerId(),
                        certificateDetails.getCertificate().getCertificateType().toString(),
                        certificateDetails.getCertificate().getSubject(),
                        certificateDetails.getCertificate().getFingerprint(),
                        TIMESTAMP)
                         .set(ocspCertificateChainValidityChecker.isValid(
                             certificateDetails.getCertificate(),
                             certificateDetails.getFederationEntityType()) ? VALID : INVALID);
                } catch (CertificateException e) {
                    LOG.warn(String.format("Invalid X.509 certificate [issuer id: %s]", certificateDetails.getIssuerId()));
                }
            });
        LOG.info("Updated Certificates OCSP Revocation Statuses Metrics.");
    }
}
