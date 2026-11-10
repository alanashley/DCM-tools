package com.github.ibmioss.dcmtools.utils;

import java.beans.PropertyVetoException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import com.github.theprez.jcmdutils.AppLogger;
import com.github.theprez.jcmdutils.StringUtils;
import com.ibm.as400.access.AS400SecurityException;
import com.ibm.as400.access.ErrorCompletingRequestException;
import com.ibm.as400.access.ObjectDoesNotExistException;

public class CertUtils {

    public static boolean areCertsEqual(final AppLogger _logger, final Certificate _cert1, final Certificate _cert2) throws CertificateEncodingException {
        if (!(_cert1 instanceof X509Certificate) || !(_cert2 instanceof X509Certificate)) {
            return _cert1.equals(_cert2);
        }
        final X509Certificate x1 = (X509Certificate) _cert1;
        final X509Certificate x2 = (X509Certificate) _cert2;
        if (Arrays.equals(x1.getTBSCertificate(), x2.getTBSCertificate())) {
            _logger.println_verbose("TBC cert match");
            return true;
        }
        if (Arrays.equals(x1.getSignature(), x2.getSignature())) {
            _logger.println_verbose("signatures match");
            return true;
        }
        if (Arrays.equals(x1.getPublicKey().getEncoded(), x2.getPublicKey().getEncoded())) {
            _logger.println_verbose("public keys match");
            return true;
        }
        if (Arrays.equals(x1.getEncoded(), x2.getEncoded())) {
            _logger.println_verbose("DER-encoded information matches");
            return true;
        }
        if (x1.toString().equals(x2.toString())) {
            return true;
        }
        return x1.equals(x2);
    }
    // here for debugging purposes
    // private static void dumpCertToFile(X509Certificate _cert, String _file) throws IOException {
    // try(FileWriter fw = new FileWriter(_file)) {
    // fw.write(""+_cert);
    // }
    // }

    public static File exportDcmStore(final AppLogger _logger, final boolean _isYesMode, final String _dcmStore, final String _dcmStorePw, final String _dest, char[] _pw) throws IOException, PropertyVetoException, AS400SecurityException, ErrorCompletingRequestException, InterruptedException, ObjectDoesNotExistException {
        final File dest;
        if (null == _dest) {
            dest = TempFileManager.createTempFile();
            dest.delete();
        } else {
            dest = new File(_dest);
        }
        try (DcmApiCaller apiCaller = new DcmApiCaller(_isYesMode)) {
            apiCaller.callQykmExportKeyStore(_logger, _dcmStore, _dcmStorePw, dest.getAbsolutePath(), StringUtils.isEmpty(_pw) ?TempFileManager.TEMP_KEYSTORE_PWD: new String(_pw));
        }
        return dest;
    }

    public static String getCertInfoStr(final Certificate _cert, final String _linePrefix) {
        if (!(_cert instanceof X509Certificate)) {
            return _linePrefix + "NOT AN X.509 CERT!" + _cert;
        }
        String ret = "";
        final SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd @ HH:mm:ssZ");
        final X509Certificate x509 = (X509Certificate) _cert;
        ret += _linePrefix + "Issuer: " + x509.getIssuerX500Principal().getName(X500Principal.RFC1779);
        ret += "\n";
        ret += _linePrefix + "Subject: " + x509.getSubjectX500Principal().getName(X500Principal.RFC1779);
        ret += "\n";
        ret += _linePrefix + "Valid From: " + simpleDateFormat.format(x509.getNotBefore());
        ret += "\n";
        ret += _linePrefix + "Valid Until: " + simpleDateFormat.format(x509.getNotAfter());
        ret += "\n";
        ret += _linePrefix + "Is CA? " + isCA(_cert);
        return ret;
    }

    public static boolean isCA(final Certificate _cert) {
        if (!(_cert instanceof X509Certificate)) {
            return false;
        }
        return -1 != ((X509Certificate) _cert).getBasicConstraints();
    }

    /**
     * Copies one entry between keystores. A certificate-only entry is copied as a trusted certificate. An entry that
     * carries a private key keeps its key and certificate chain, which is what lets DCM treat it as a server/client
     * certificate rather than as a CA certificate.
     *
     * @param _srcPw
     *            password protecting the key in the source keystore (may be <tt>null</tt>)
     * @param _destPw
     *            password to protect the key with in the destination keystore
     */
    public static void copyEntry(final KeyStore _dest, final String _destAlias, final KeyStore _src, final String _srcAlias, final char[] _srcPw, final char[] _destPw) throws KeyStoreException, IOException {
        if (_src.isKeyEntry(_srcAlias)) {
            final Key key;
            try {
                key = _src.getKey(_srcAlias, _srcPw);
            } catch (final GeneralSecurityException e) {
                throw new IOException("Unable to read the private key for '" + _srcAlias + "'. Is the password correct?", e);
            }
            final Certificate[] chain = _src.getCertificateChain(_srcAlias);
            if (null == key || null == chain || 0 == chain.length) {
                throw new IOException("Unable to read the private key and certificate for '" + _srcAlias + "'");
            }
            _dest.setKeyEntry(_destAlias, key, _destPw, chain);
        } else {
            final Certificate cert = _src.getCertificate(_srcAlias);
            if (null != cert) {
                _dest.setCertificateEntry(_destAlias, cert);
            }
        }
    }

    /**
     * @return whether the private key is the counterpart of the certificate's public key
     */
    public static boolean isKeyForCert(final PrivateKey _key, final Certificate _cert) {
        if (null == _key || null == _cert) {
            return false;
        }
        final PublicKey publicKey = _cert.getPublicKey();
        if (!_key.getAlgorithm().equals(publicKey.getAlgorithm())) {
            return false;
        }
        final String signatureAlgorithm;
        if ("RSA".equals(_key.getAlgorithm())) {
            signatureAlgorithm = "SHA256withRSA";
        } else if ("EC".equals(_key.getAlgorithm())) {
            signatureAlgorithm = "SHA256withECDSA";
        } else if ("DSA".equals(_key.getAlgorithm())) {
            signatureAlgorithm = "SHA256withDSA";
        } else {
            return false;
        }
        try {
            // Proof by doing: something signed with the private key must verify with the public key
            final byte[] challenge = "dcmtools".getBytes(StandardCharsets.UTF_8);
            final Signature signer = Signature.getInstance(signatureAlgorithm);
            signer.initSign(_key);
            signer.update(challenge);
            final byte[] signature = signer.sign();
            final Signature verifier = Signature.getInstance(signatureAlgorithm);
            verifier.initVerify(publicKey);
            verifier.update(challenge);
            return verifier.verify(signature);
        } catch (final GeneralSecurityException e) {
            return false;
        }
    }

    /**
     * @return the certificate at the given alias, followed by as many of its issuers as can be found among the
     *         certificate entries of the keystore
     */
    public static Certificate[] buildChain(final KeyStore _ks, final String _leafAlias) throws KeyStoreException {
        final List<Certificate> chain = new LinkedList<Certificate>();
        Certificate current = _ks.getCertificate(_leafAlias);
        chain.add(current);
        while (current instanceof X509Certificate && chain.size() < 10) {
            final X509Certificate x509 = (X509Certificate) current;
            if (x509.getSubjectX500Principal().equals(x509.getIssuerX500Principal())) {
                break; // self-signed. This is the top of the chain
            }
            Certificate issuer = null;
            for (final String alias : Collections.list(_ks.aliases())) {
                final Certificate candidate = _ks.getCertificate(alias);
                if (!(candidate instanceof X509Certificate) || chain.contains(candidate)) {
                    continue;
                }
                if (!((X509Certificate) candidate).getSubjectX500Principal().equals(x509.getIssuerX500Principal())) {
                    continue;
                }
                try {
                    x509.verify(candidate.getPublicKey());
                    issuer = candidate;
                    break;
                } catch (final GeneralSecurityException e) {
                    // same name, but not the issuer. Keep looking
                }
            }
            if (null == issuer) {
                break;
            }
            chain.add(issuer);
            current = issuer;
        }
        return chain.toArray(new Certificate[chain.size()]);
    }

    public static KeyStore exportDcmStoreToKeystoreObj(AppLogger _logger, boolean _yesMode, String _dcmStore, String _dcmPassword) throws IOException, PropertyVetoException, AS400SecurityException, ErrorCompletingRequestException, InterruptedException, ObjectDoesNotExistException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
        final File tmpFile = TempFileManager.createTempFile();
        FileUtils.delete(tmpFile);
        CertUtils.exportDcmStore(_logger,  _yesMode,  _dcmStore,  _dcmPassword,  tmpFile.getAbsolutePath(), null);
        KeyStore fileKs = null;
        try (FileInputStream fis = new FileInputStream(tmpFile)) {
            fileKs = KeyStore.getInstance("pkcs12");
            fileKs.load(fis, TempFileManager.TEMP_KEYSTORE_PWD.toCharArray());
            return fileKs;
        }
    }

}
