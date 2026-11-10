package com.github.ibmioss.dcmtools.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import com.github.theprez.jcmdutils.AppLogger;
import com.github.theprez.jcmdutils.ProcessLauncher;
import com.github.theprez.jcmdutils.ProcessLauncher.ProcessResult;
import com.github.theprez.jcmdutils.StringUtils;

public class KeyStoreLoader {
    private static final String PKCS_12 = "PKCS12";

    public static String extractTrustFromInstalledCerts(final AppLogger _logger) throws IOException {
        final File destFile = TempFileManager.createTempFile(null);
        destFile.delete();
        final ProcessResult cmdResults = ProcessLauncher.exec("/QOpenSys/pkgs/bin/trust extract --format=java-cacerts --purpose=server-auth -v " + destFile.getAbsolutePath());
        if (0 != cmdResults.getExitStatus()) {
            for (final String errLine : cmdResults.getStderr()) {
                _logger.println_err(errLine);
            }
            throw new IOException("Error extracting trusted certificates");
        }
        _logger.println_success("Successfully extracted installed certificates");
        return destFile.getAbsolutePath(); // TODO: delete this file!
    }

    /** Supplies the password of an input file when one turns out to be needed. */
    public interface PasswordPrompter {
        /**
         * @return the password, or <tt>null</tt>/empty if none is available
         */
        String getPasswordFor(String _fileName) throws IOException;
    }

    /** Password protecting the private keys held in the in-memory keystore built by this class. */
    public static char[] internalKeyPassword() {
        return TempFileManager.TEMP_KEYSTORE_PWD.toCharArray();
    }

    static {
        // Newer Java levels write PKCS#12 files with AES/PBES2 by default. Keep producing the long-standing
        // 3DES-based format, which is what the DCM import API ("*PKCS12V3") has always been handed by this tool.
        if (null == System.getProperty("keystore.pkcs12.legacy")) {
            System.setProperty("keystore.pkcs12.legacy", "true");
        }
    }

    private final KeyStore m_keyStore;

    public KeyStoreLoader(final KeyStore _ks) {
        m_keyStore = _ks;
    }

    public KeyStoreLoader(final AppLogger _logger, final List<String> _files, final String _pw, final String _label, final boolean _caOnly) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
        this(_logger, _files, _pw, _label, _caOnly, null);
    }

    public KeyStoreLoader(final AppLogger _logger, final List<String> _files, final String _pw, final String _label, final boolean _caOnly, final PasswordPrompter _prompter) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {

        final List<String> filesToLoad = new LinkedList<String>();
        filesToLoad.addAll(_files);

        for (final String file : _files) {
            final File f = new File(file);
            if (f.isDirectory()) {
                final File[] innerFiles = f.listFiles();
                if (null != innerFiles) {
                    for (final File innerFile : innerFiles) {
                        filesToLoad.add(innerFile.getAbsolutePath());
                    }
                }
            } else if (file.toLowerCase().endsWith(".zip")) {
                for (final File innerFile : TempFileManager.unzip(file)) {
                    filesToLoad.add(innerFile.getAbsolutePath());
                }
            }
        }

        final KeyStore keyStore = KeyStore.getInstance(PKCS_12);
        keyStore.load(null, null);
        boolean isKeyStoreLoaded = false;
        final List<PrivateKey> looseKeys = new LinkedList<PrivateKey>();
        final String label = StringUtils.isEmpty(_label) ? null : _label.trim();

        for (final String file : filesToLoad) {
            final File f = new File(file);
            // skip directories and .zip files (we already added their contents to the main list)
            if (f.isDirectory() || file.toLowerCase().endsWith(".zip")) {
                continue;
            }
            boolean isFileLoaded = false;

            // Try to load as keystore file
            String pw = _pw;
            KeyStore fileKs = loadKeyStoreFile(_logger, file, pw);
            if (null != fileKs && needsPassword(fileKs, pw) && null != _prompter) {
                // The file is a keystore, but its contents can't be read without a password
                final String prompted = _prompter.getPasswordFor(f.getName());
                if (StringUtils.isNonEmpty(prompted)) {
                    pw = prompted;
                    fileKs = loadKeyStoreFile(_logger, file, pw);
                }
            }
            if (null != fileKs && needsPassword(fileKs, pw)) {
                _logger.println_warn("WARNING: File " + f.getName() + " will not be processed. It is password-protected. Use the '--password' option");
                continue;
            }
            if (null != fileKs) {
                addKeyStoreEntries(_logger, keyStore, fileKs, pw, label, _caOnly);
                isFileLoaded = true;
                isKeyStoreLoaded = true;
            }
            // That didn't work! Try to load as a certificate file
            if (!isFileLoaded) {
                try (FileInputStream fis = new FileInputStream(file)) {
                    final Collection<? extends Certificate> certs = CertificateFactory.getInstance("X.509").generateCertificates(fis);
                    final String aliasBase = null == label ? f.getName().replaceFirst("[.][^.]+$", "") : label;
                    for (final Certificate cert : certs) {
                        isFileLoaded = true;
                        if (_caOnly && !isCertCa(cert)) {
                            continue;
                        }
                        if (null != keyStore.getCertificateAlias(cert)) {
                            continue; // the same certificate was already loaded from another file
                        }
                        keyStore.setCertificateEntry(uniqueAlias(keyStore, aliasBase), cert);
                    }
                } catch (final Exception e) {
                    _logger.println_verbose("File " + f.getName() + " is not a certificate file: " + e.getMessage());
                }
            }
            // A PEM file can also hold a private key (alongside the certificates, or all by itself)
            final List<PrivateKey> keys = PemKeyReader.readPrivateKeys(f);
            if (!keys.isEmpty()) {
                isFileLoaded = true;
                if (!_caOnly) {
                    looseKeys.addAll(keys);
                }
            }
            if (!isFileLoaded) {
                String warning = "WARNING: File " + f.getName() + " will not be processed. It is in an unsupported format";
                if (null == pw) {
                    warning += ", or it is password-protected (if so, use the '--password' option)";
                } else {
                    warning += ", or the password is not correct";
                }
                _logger.println_warn(warning);
            }
        }
        attachPrivateKeys(_logger, keyStore, looseKeys, label);

        // Out of ideas
        if (!keyStore.aliases().hasMoreElements() && !isKeyStoreLoaded) {
            throw new IOException("Failure loading certificates");
        }
        _logger.println_verbose("Successfully loaded certificates");
        m_keyStore = keyStore;
    }

    /**
     * @return the loaded keystore, or <tt>null</tt> if the file is not a keystore (or the password is wrong)
     */
    private static KeyStore loadKeyStoreFile(final AppLogger _logger, final String _file, final String _pw) {
        final String[] keystoreTypes = new String[] { KeyStore.getDefaultType(), "JKS", PKCS_12, "JCEKS" };
        for (final String keystoreType : keystoreTypes) {
            try (FileInputStream fis = new FileInputStream(_file)) {
                final KeyStore fileKs = KeyStore.getInstance(keystoreType);
                fileKs.load(fis, null == _pw ? null : _pw.toCharArray());
                return fileKs;
            } catch (final Throwable e) {
                _logger.println_verbose("File " + new File(_file).getName() + " could not be loaded as " + keystoreType + ": " + e.getMessage());
            }
        }
        return null;
    }

    /**
     * A keystore file can load "successfully" without its password, but with its encrypted contents missing. That
     * must not be mistaken for a successful load.
     */
    private static boolean needsPassword(final KeyStore _ks, final String _pw) throws KeyStoreException {
        if (null != _pw) {
            return false;
        }
        for (final String alias : Collections.list(_ks.aliases())) {
            if (_ks.isKeyEntry(alias) || null == _ks.getCertificate(alias)) {
                return true;
            }
        }
        return false;
    }

    private static void addKeyStoreEntries(final AppLogger _logger, final KeyStore _dest, final KeyStore _src, final String _srcPw, final String _label, final boolean _caOnly) throws KeyStoreException, IOException {
        final List<String> aliases = new LinkedList<String>();
        int numKeyEntries = 0;
        for (final String alias : Collections.list(_src.aliases())) {
            final Certificate cert = _src.getCertificate(alias);
            if (null == cert) {
                continue;
            }
            if (_caOnly && (_src.isKeyEntry(alias) || !isCertCa(cert))) {
                continue;
            }
            aliases.add(alias);
            if (_src.isKeyEntry(alias)) {
                numKeyEntries++;
            }
        }
        for (final String alias : aliases) {
            final boolean isKeyEntry = _src.isKeyEntry(alias);
            final String existing = _dest.getCertificateAlias(_src.getCertificate(alias));
            if (null != existing) {
                if (!isKeyEntry || _dest.isKeyEntry(existing)) {
                    continue; // already loaded from another file
                }
                _dest.deleteEntry(existing); // the copy that comes with its private key wins
            }
            // The requested certificate ID applies when it is unambiguous which entry it is meant for
            final boolean isLabelTarget = null != _label && (isKeyEntry ? 1 == numKeyEntries : (0 == numKeyEntries && 1 == aliases.size()));
            final String destAlias = uniqueAlias(_dest, isLabelTarget ? _label : alias);
            CertUtils.copyEntry(_dest, destAlias, _src, alias, null == _srcPw ? null : _srcPw.toCharArray(), internalKeyPassword());
        }
    }

    /**
     * Pairs private keys read from PEM files with the certificates they belong to, turning those certificates into
     * server/client certificate entries, complete with as much of the issuing chain as was loaded.
     */
    private static void attachPrivateKeys(final AppLogger _logger, final KeyStore _ks, final List<PrivateKey> _keys, final String _label) throws KeyStoreException {
        for (final PrivateKey key : _keys) {
            String matchingAlias = null;
            for (final String alias : Collections.list(_ks.aliases())) {
                if (!_ks.isKeyEntry(alias) && CertUtils.isKeyForCert(key, _ks.getCertificate(alias))) {
                    matchingAlias = alias;
                    break;
                }
            }
            if (null == matchingAlias) {
                _logger.println_warn("WARNING: A private key was found, but not the certificate it belongs to. The private key will not be processed");
                continue;
            }
            final Certificate[] chain = CertUtils.buildChain(_ks, matchingAlias);
            _ks.deleteEntry(matchingAlias);
            _ks.setKeyEntry(null == _label ? matchingAlias : _label, key, internalKeyPassword(), chain);
        }
    }

    private static String uniqueAlias(final KeyStore _ks, final String _aliasBase) throws KeyStoreException {
        String alias = _aliasBase;
        for (int counter = 2; _ks.containsAlias(alias); counter++) {
            alias = _aliasBase + "." + counter;
        }
        return alias;
    }

    public KeyStore getKeyStore() {
        return m_keyStore;
    }

    private static boolean isCertCa(final Certificate cert) {
        return CertUtils.isCA(cert);
    }

    public String saveToDcmApiFormatFile(final String _pw) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
        final KeyStore keyStore = getKeyStore();
        final File dcmFile = TempFileManager.createTempFile(null);
        final KeyStore tgt = KeyStore.getInstance(PKCS_12);
        tgt.load(null, _pw.toCharArray());
        for (final String alias : Collections.list(keyStore.aliases())) {
            CertUtils.copyEntry(tgt, alias, keyStore, alias, internalKeyPassword(), _pw.toCharArray());
        }
        try (FileOutputStream fos = new FileOutputStream(dcmFile, true)) {
            tgt.store(fos, _pw.toCharArray());
        }
        return dcmFile.getAbsolutePath();
    }
}
