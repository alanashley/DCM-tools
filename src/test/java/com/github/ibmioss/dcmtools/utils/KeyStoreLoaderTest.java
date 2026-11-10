package com.github.ibmioss.dcmtools.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class KeyStoreLoaderTest {

    @Rule
    public TemporaryFolder m_tmp = new TemporaryFolder();

    private static KeyStore load(final String _pw, final String _label, final boolean _caOnly, final String... _files) throws Exception {
        final String[] paths = new String[_files.length];
        for (int i = 0; i < _files.length; i++) {
            paths[i] = TestFiles.path(_files[i]);
        }
        return new KeyStoreLoader(TestFiles.LOGGER, Arrays.asList(paths), _pw, _label, _caOnly).getKeyStore();
    }

    private static List<String> aliases(final KeyStore _ks) throws Exception {
        final List<String> ret = Collections.list(_ks.aliases());
        Collections.sort(ret);
        return ret;
    }

    private static String subject(final KeyStore _ks, final String _alias) throws Exception {
        return ((X509Certificate) _ks.getCertificate(_alias)).getSubjectX500Principal().getName();
    }

    @Test
    public void pemAndDerCertificatesLoadAsCertificateEntries() throws Exception {
        final KeyStore pem = load(null, null, false, "rootca.pem");
        assertEquals(Arrays.asList("rootca"), aliases(pem));
        assertTrue(pem.isCertificateEntry("rootca"));

        final KeyStore der = load(null, null, false, "rootca.der");
        assertEquals(pem.getCertificate("rootca"), der.getCertificate("rootca"));
    }

    @Test
    public void bundleGetsOneEntryPerCertificate() throws Exception {
        final KeyStore ks = load(null, null, false, "fullchain.pem");
        assertEquals(Arrays.asList("fullchain", "fullchain.2", "fullchain.3"), aliases(ks));
        assertEquals("CN=server.example.test", subject(ks, "fullchain"));
        for (final String alias : aliases(ks)) {
            assertFalse(ks.isKeyEntry(alias));
        }
    }

    @Test
    public void certificateRequestedIdIsUsed() throws Exception {
        final KeyStore ks = load(null, "mycert", false, "server.pem");
        assertEquals(Arrays.asList("mycert"), aliases(ks));
    }

    @Test
    public void pemKeyIsPairedWithItsCertificateAndChain() throws Exception {
        for (final String keyFile : new String[] { "server.pkcs8.key", "server.pkcs1.key" }) {
            final KeyStore ks = load(null, null, false, "fullchain.pem", keyFile);
            assertEquals(Arrays.asList("fullchain", "fullchain.2", "fullchain.3"), aliases(ks));
            assertTrue(keyFile, ks.isKeyEntry("fullchain"));
            assertNotNull(ks.getKey("fullchain", KeyStoreLoader.internalKeyPassword()));
            assertEquals(3, ks.getCertificateChain("fullchain").length);
            // the CA certificates are still there to be imported as CAs
            assertTrue(ks.isCertificateEntry("fullchain.2"));
            assertTrue(ks.isCertificateEntry("fullchain.3"));
        }
    }

    @Test
    public void ecKeyInSec1FormatIsSupported() throws Exception {
        final KeyStore ks = load(null, "ec", false, "ecserver.pem", "ecserver.sec1.key", "inter.pem", "rootca.pem");
        assertTrue(ks.isKeyEntry("ec"));
        assertEquals("EC", ks.getKey("ec", KeyStoreLoader.internalKeyPassword()).getAlgorithm());
        assertEquals(3, ks.getCertificateChain("ec").length);
    }

    @Test
    public void requestedIdGoesToTheCertificateWithThePrivateKey() throws Exception {
        final KeyStore ks = load(null, "mydomain", false, "fullchain.pem", "server.pkcs8.key");
        assertTrue(ks.isKeyEntry("mydomain"));
        assertEquals("CN=server.example.test", subject(ks, "mydomain"));
    }

    @Test
    public void directoryOfAcmeOutputYieldsOneServerCertificate() throws Exception {
        final File dir = m_tmp.newFolder("acme");
        for (final String f : new String[] { "fullchain.pem", "server.pem", "inter.pem", "server.pkcs8.key" }) {
            Files.copy(new File(TestFiles.path(f)).toPath(), new File(dir, f).toPath());
        }
        Files.write(new File(dir, "server.conf").toPath(), "not a certificate".getBytes("UTF-8"));
        final KeyStore ks = new KeyStoreLoader(TestFiles.LOGGER, Arrays.asList(dir.getAbsolutePath()), null, null, false).getKeyStore();
        // the same certificates appear in several files, but each is only loaded once
        assertEquals(3, aliases(ks).size());
        int numKeyEntries = 0;
        for (final String alias : aliases(ks)) {
            if (ks.isKeyEntry(alias)) {
                numKeyEntries++;
                assertEquals("CN=server.example.test", subject(ks, alias));
            }
        }
        assertEquals(1, numKeyEntries);
    }

    @Test
    public void keyWithoutItsCertificateIsIgnored() throws Exception {
        final KeyStore ks = load(null, null, false, "rootca.pem", "server.pkcs8.key");
        assertEquals(Arrays.asList("rootca"), aliases(ks));
        assertFalse(ks.isKeyEntry("rootca"));
    }

    @Test
    public void encryptedPemKeyIsRejectedWithExplanation() throws Exception {
        try {
            load(null, null, false, "server.pem", "server.encrypted.key");
            fail("expected a failure");
        } catch (final IOException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("encrypted"));
        }
    }

    @Test
    public void pkcs12KeepsPrivateKeyAndChain() throws Exception {
        final KeyStore ks = load(TestFiles.PASSWORD, null, false, "server.pfx");
        assertEquals(Arrays.asList("mydomain"), aliases(ks));
        assertTrue(ks.isKeyEntry("mydomain"));
        assertEquals(2, ks.getCertificateChain("mydomain").length);

        final KeyStore relabeled = load(TestFiles.PASSWORD, "newname", false, "server.pfx");
        assertEquals(Arrays.asList("newname"), aliases(relabeled));
        assertTrue(relabeled.isKeyEntry("newname"));
    }

    @Test
    public void pkcs12WithoutPasswordIsNotMistakenForALoadedFile() throws Exception {
        try {
            load(null, null, false, "server.pfx");
            fail("expected a failure");
        } catch (final IOException e) {
            assertEquals("Failure loading certificates", e.getMessage());
        }
        try {
            load("wrong", null, false, "server.pfx");
            fail("expected a failure");
        } catch (final IOException e) {
            assertEquals("Failure loading certificates", e.getMessage());
        }
    }

    @Test
    public void passwordIsPromptedForWhenNeeded() throws Exception {
        final int[] numPrompts = { 0 };
        final KeyStoreLoader.PasswordPrompter prompter = new KeyStoreLoader.PasswordPrompter() {
            @Override
            public String getPasswordFor(final String _fileName) {
                numPrompts[0]++;
                assertEquals("server.pfx", _fileName);
                return TestFiles.PASSWORD;
            }
        };
        final KeyStore ks = new KeyStoreLoader(TestFiles.LOGGER, Arrays.asList(TestFiles.path("server.pfx"), TestFiles.path("rootca.pem")), null, null, false, prompter).getKeyStore();
        assertEquals(1, numPrompts[0]);
        assertTrue(ks.isKeyEntry("mydomain"));
        assertTrue(ks.isCertificateEntry("rootca"));
    }

    @Test
    public void caOnlyLeavesOutServerCertificatesAndKeys() throws Exception {
        final KeyStore ks = load(TestFiles.PASSWORD, null, true, "fullchain.pem", "server.pkcs8.key", "server.pfx");
        assertEquals(2, aliases(ks).size());
        for (final String alias : aliases(ks)) {
            assertFalse(ks.isKeyEntry(alias));
            assertTrue(CertUtils.isCA(ks.getCertificate(alias)));
        }
    }

    @Test
    public void fileHandedToDcmKeepsPrivateKeys() throws Exception {
        final KeyStore ks = load(null, "mydomain", false, "fullchain.pem", "server.pkcs8.key");
        final String file = new KeyStoreLoader(ks).saveToDcmApiFormatFile("handoff-pw");
        try {
            final KeyStore reloaded = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(file)) {
                reloaded.load(fis, "handoff-pw".toCharArray());
            }
            assertEquals(3, aliases(reloaded).size());
            assertTrue(reloaded.isKeyEntry("mydomain"));
            assertNotNull(reloaded.getKey("mydomain", "handoff-pw".toCharArray()));
            assertEquals(3, reloaded.getCertificateChain("mydomain").length);
        } finally {
            new File(file).delete();
        }
    }
}
