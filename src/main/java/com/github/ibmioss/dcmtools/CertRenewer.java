package com.github.ibmioss.dcmtools;

import java.beans.PropertyVetoException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import com.github.ibmioss.dcmtools.utils.CertUtils;
import com.github.ibmioss.dcmtools.utils.DcmApiCaller;
import com.github.ibmioss.dcmtools.utils.KeyStoreLoader;
import com.github.ibmioss.dcmtools.utils.TempFileManager;
import com.github.theprez.jcmdutils.AppLogger;
import com.ibm.as400.access.AS400SecurityException;
import com.ibm.as400.access.ErrorCompletingRequestException;
import com.ibm.as400.access.ObjectDoesNotExistException;

public class CertRenewer {

    private final List<String> m_fileNames;

    public CertRenewer(final AppLogger _logger, final List<String> _fileNames) throws IOException {
        m_fileNames = new LinkedList<String>();
        for (final String fileName : _fileNames) {
            m_fileNames.add(null == fileName ? KeyStoreLoader.extractTrustFromInstalledCerts(_logger) : fileName);
        }
    }

    public void doRenew(final AppLogger _logger, final DcmUserOpts _opts) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, PropertyVetoException, AS400SecurityException, ErrorCompletingRequestException, InterruptedException, ObjectDoesNotExistException {

        // Initialize keystore from file of unknown type
        final KeyStore keyStore = new KeyStoreLoader(_logger, m_fileNames, null, null, false).getKeyStore();

        // A renewal replaces a server/client certificate. When the input is a full chain (as produced by CertBot or
        // acme.sh), the CA certificates in it are not what is being renewed, so leave them out.
        final List<Certificate> all = new LinkedList<Certificate>();
        final List<Certificate> nonCa = new LinkedList<Certificate>();
        for (final String alias : Collections.list(keyStore.aliases())) {
            final Certificate cert = keyStore.getCertificate(alias);
            if (null == cert) {
                continue;
            }
            all.add(cert);
            if (!CertUtils.isCA(cert)) {
                nonCa.add(cert);
            }
        }
        final List<Certificate> toRenew = nonCa.isEmpty() ? all : nonCa;
        if (toRenew.isEmpty()) {
            throw new IOException("No certificates to renew");
        }
        // One connection for the whole operation (and so, at most one prompt for the IBM i password)
        try (DcmApiCaller caller = new DcmApiCaller(_opts.isYesMode())) {
            for (final Certificate cert : toRenew) {
                _logger.println("Renewing certificate:");
                _logger.println(CertUtils.getCertInfoStr(cert, "    "));
                renewCert(_logger, caller, cert);
            }
        }
    }

    private void renewCert(final AppLogger _logger, final DcmApiCaller _caller, final Certificate _cert) throws CertificateEncodingException, FileNotFoundException, IOException, PropertyVetoException, AS400SecurityException, ErrorCompletingRequestException, InterruptedException, ObjectDoesNotExistException {
        final File tmpFile = TempFileManager.createTempFile();
        try (FileOutputStream fos = new FileOutputStream(tmpFile)) {
            fos.write(_cert.getEncoded());
        }
        try {
            _caller.callQycdRenewCertificate_RNWC0300(_logger, tmpFile.getAbsolutePath());
        } finally {
            tmpFile.delete();
        }
    }
}
