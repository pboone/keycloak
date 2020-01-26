package org.keycloak.utils;

import static org.junit.Assert.fail;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.security.auth.x500.X500Principal;

import org.junit.Test;
import org.keycloak.provider.Provider;
import org.keycloak.services.DefaultKeycloakSession;
import org.keycloak.services.DefaultKeycloakSessionFactory;
import org.keycloak.truststore.HostnameVerificationPolicy;
import org.keycloak.truststore.TruststoreProvider;

/**
 * Tests for {@link CRLUtils}.
 *
 * @author Paul Boone
 */
public class CRLUtilsTest {

    @Test
    public void testCheck() throws Exception {

        MockSession session = new MockSession();
        session.init();

        List<X509Certificate> certs;
        X509CRL crl;

        // valid certificate (not revoked)
        certs = new ArrayList<>();
        certs.addAll(readCertificates(new File(getClass().getResource("/certs/client1-valid.crt").toURI())));
        certs.addAll(readCertificates(new File(getClass().getResource("/certs/ia1.crt").toURI())));
        certs.addAll(readCertificates(new File(getClass().getResource("/certs/ca1.crt").toURI())));
        crl = readCrl(new File(getClass().getResource("/certs/ia1.crl").toURI()));
        CRLUtils.check(certs.toArray(new X509Certificate[0]), crl, session);

        // revoked certificate
        certs = new ArrayList<>();
        certs.addAll(readCertificates(new File(getClass().getResource("/certs/client1-revoked.crt").toURI())));
        certs.addAll(readCertificates(new File(getClass().getResource("/certs/ia1.crt").toURI())));
        certs.addAll(readCertificates(new File(getClass().getResource("/certs/ca1.crt").toURI())));
        crl = readCrl(new File(getClass().getResource("/certs/ia1.crl").toURI()));
        try {
            CRLUtils.check(certs.toArray(new X509Certificate[0]), crl, session);
            fail("Certificate is revoked");
        } catch (GeneralSecurityException expected) {
        }

        // CRL issuer not in truststore
        certs = new ArrayList<>();
        certs.addAll(readCertificates(new File(getClass().getResource("/certs/client2-valid.crt").toURI())));
        certs.addAll(readCertificates(new File(getClass().getResource("/certs/ia2.crt").toURI())));
        certs.addAll(readCertificates(new File(getClass().getResource("/certs/ca2.crt").toURI())));
        crl = readCrl(new File(getClass().getResource("/certs/ia2.crl").toURI()));
        CRLUtils.check(certs.toArray(new X509Certificate[0]), crl, session);

        // CRL issuer in truststore but not in cert chain (valid cert)
        certs = new ArrayList<>();
        certs.addAll(readCertificates(new File(getClass().getResource("/certs/client1-valid.crt").toURI())));
        certs.addAll(readCertificates(new File(getClass().getResource("/certs/ia1.crt").toURI())));
        crl = readCrl(new File(getClass().getResource("/certs/ia1.crl").toURI()));
        CRLUtils.check(certs.toArray(new X509Certificate[0]), crl, session);

        // CRL issuer in truststore but not in cert chain (revoked cert)
        certs = new ArrayList<>();
        certs.addAll(readCertificates(new File(getClass().getResource("/certs/client1-revoked.crt").toURI())));
        certs.addAll(readCertificates(new File(getClass().getResource("/certs/ia1.crt").toURI())));
        crl = readCrl(new File(getClass().getResource("/certs/ia1.crl").toURI()));
        try {
            CRLUtils.check(certs.toArray(new X509Certificate[0]), crl, session);
            fail("Certificate is revoked");
        } catch (GeneralSecurityException expected) {
        }

        // Valid certificate
        certs = new ArrayList<>();
        certs.addAll(readCertificates(new File(getClass().getResource("/certs/client2-valid.crt").toURI())));
        certs.addAll(readCertificates(new File(getClass().getResource("/certs/ia2.crt").toURI())));
        crl = readCrl(new File(getClass().getResource("/certs/ia2.crl").toURI()));
        CRLUtils.check(certs.toArray(new X509Certificate[0]), crl, session);

        // Revoked intermediate certificate
        certs = new ArrayList<>();
        certs.addAll(readCertificates(new File(getClass().getResource("/certs/client2-valid.crt").toURI())));
        certs.addAll(readCertificates(new File(getClass().getResource("/certs/ia2.crt").toURI())));
        certs.addAll(readCertificates(new File(getClass().getResource("/certs/ca2.crt").toURI())));
        crl = readCrl(new File(getClass().getResource("/certs/ca2.crl").toURI()));
        try {
            CRLUtils.check(certs.toArray(new X509Certificate[0]), crl, session);
            fail("Revoked intermediate CA - should have been rejected");
        } catch (GeneralSecurityException expected) {
        }

        // certificate and CRL have different issuers
        certs = new ArrayList<>();
        certs.addAll(readCertificates(new File(getClass().getResource("/certs/client1-valid.crt").toURI())));
        certs.addAll(readCertificates(new File(getClass().getResource("/certs/ia1.crt").toURI())));
        certs.addAll(readCertificates(new File(getClass().getResource("/certs/ca1.crt").toURI())));
        crl = readCrl(new File(getClass().getResource("/certs/ia2.crl").toURI()));
        // CRLUtils.check(certs.toArray(new X509Certificate[0]), crl, session);
    }

    private static class MockSession extends DefaultKeycloakSession {

        private static final DefaultKeycloakSessionFactory FACTORY = new DefaultKeycloakSessionFactory();

        private TruststoreProvider truststoreProvider;

        public MockSession() {
            super(FACTORY);
        }

        public void init() {
            MockTruststoreProvider truststoreProvider = new MockTruststoreProvider();
            try {
                truststoreProvider.init();
            } catch (IOException | URISyntaxException e) {
                throw new RuntimeException(e);
            }
            this.truststoreProvider = truststoreProvider;
        }

        @SuppressWarnings("unchecked")
        @Override
        public <T extends Provider> T getProvider(Class<T> clazz) {
            if (TruststoreProvider.class.isAssignableFrom(clazz)) {
                return (T) this.truststoreProvider;
            }
            throw new RuntimeException("Not implemented");
        }

    }

    private static class MockTruststoreProvider implements TruststoreProvider {

        private Map<X500Principal, X509Certificate> rootCertificates;
        private Map<X500Principal, X509Certificate> intermediateCertificates;
        private KeyStore truststore;

        public void init() throws IOException, URISyntaxException {

            List<X509Certificate> certs;

            certs = new ArrayList<>();
            certs.addAll(readCertificates(new File(getClass().getResource("/certs/ca1.crt").toURI())));
            certs.addAll(readCertificates(new File(getClass().getResource("/certs/ca2.crt").toURI())));
            rootCertificates = new HashMap<>();
            certs.stream().forEach(cert -> {
                X500Principal subject = cert.getSubjectX500Principal();
                rootCertificates.put(subject, cert);
            });

            certs = new ArrayList<>();
            certs.addAll(readCertificates(new File(getClass().getResource("/certs/ia1.crt").toURI())));
            certs.addAll(readCertificates(new File(getClass().getResource("/certs/ia2.crt").toURI())));
            intermediateCertificates = new HashMap<>();
            certs.stream().forEach(cert -> {
                X500Principal subject = cert.getSubjectX500Principal();
                intermediateCertificates.put(subject, cert);
            });

            certs = new ArrayList<>();
            certs.addAll(rootCertificates.values());
            certs.addAll(intermediateCertificates.values());
            truststore = createTruststore(certs);
        }

        @Override
        public void close() {
        }

        @Override
        public HostnameVerificationPolicy getPolicy() {
            return HostnameVerificationPolicy.STRICT;
        }

        @Override
        public KeyStore getTruststore() {
            return truststore;
        }

        @Override
        public Map<X500Principal, X509Certificate> getRootCertificates() {
            return rootCertificates;
        }

        @Override
        public Map<X500Principal, X509Certificate> getIntermediateCertificates() {
            return intermediateCertificates;
        }

    }

    private static KeyStore createTruststore(List<X509Certificate> certs) throws IOException {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            throw new IOException(e.getMessage(), e);
        }
        try {
            keyStore.load(null, null);
        } catch (NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new IOException(e.getMessage(), e);
        }

        for (int i = 0; i < certs.size(); i++) {
            X509Certificate cert = certs.get(i);
            String alias = String.format("ca%s", i);
            try {
                keyStore.setCertificateEntry(alias, cert);
            } catch (KeyStoreException e) {
                throw new IOException(e.getMessage(), e);
            }
        }
        return keyStore;
    }

    /**
     * Parse file containing PEM-formatted certificates (public keys)
     *
     * @param file file containing PEM-formatted certificates
     * @return certificates found in the file
     * @throws IOException if certificates can't be loaded from the file
     */
    private static List<X509Certificate> readCertificates(File file) throws IOException {
        try (InputStream in = new FileInputStream(file)) {
            return readCertificates(in);
        }
    }

    /**
     * Read PEM-formatted certificates (public keys)
     *
     * @param in stream of PEM-formatted certificates
     * @return certificates found in the stream
     * @throws IOException if certificates can't be loaded
     */
    private static List<X509Certificate> readCertificates(InputStream in) throws IOException {
        List<X509Certificate> certs = new ArrayList<>();
        BufferedInputStream bis = new BufferedInputStream(in);
        CertificateFactory cf;
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new IOException(e.getMessage(), e);
        }
        while (bis.available() > 0) {
            Certificate cert;
            try {
                cert = cf.generateCertificate(bis);
            } catch (CertificateException e) {
                throw new IOException(e.getMessage(), e);
            }
            certs.add((X509Certificate) cert);
        }
        return certs;
    }

    private static X509CRL readCrl(File file) throws IOException {
        try (InputStream in = new FileInputStream(file)) {
            return readCrl(in);
        }
    }

    private static X509CRL readCrl(InputStream in) throws IOException {
        BufferedInputStream bis = new BufferedInputStream(in);
        CertificateFactory cf;
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new IOException(e.getMessage(), e);
        }
        X509CRL crl;
        try {
            crl = (X509CRL) cf.generateCRL(bis);
        } catch (CRLException e) {
            throw new IOException(e.getMessage(), e);
        }
        return crl;
    }

}
