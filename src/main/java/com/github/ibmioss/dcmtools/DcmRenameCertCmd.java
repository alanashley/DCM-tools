package com.github.ibmioss.dcmtools;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Collections;

import com.github.ibmioss.dcmtools.utils.DcmChangeTracker;
import com.github.ibmioss.dcmtools.utils.DcmStoreEditor;
import com.github.ibmioss.dcmtools.utils.TempFileManager;
import com.github.theprez.jcmdutils.AppLogger;
import com.github.theprez.jcmdutils.ConsoleQuestionAsker;
import com.github.theprez.jcmdutils.StringUtils;
import com.github.theprez.jcmdutils.StringUtils.TerminalColor;

/**
 * Main entry point for the application
 *
 * @author Jesse Gorzinski
 */
public class DcmRenameCertCmd {
    private static class CertRenameOpts extends DcmUserOpts {

        private String m_newLabel;
        private String m_oldLabel;

        public String getNewLabel() throws IOException {

            if (StringUtils.isNonEmpty(m_newLabel)) {
                return m_newLabel;
            }
            if (!isYesMode()) {
                return m_newLabel = ConsoleQuestionAsker.get().askUserOrThrow("Enter new label: ");
            }
            throw new IOException("ERROR: new label is required");
        }

        public String getOldLabel() throws IOException {

            if (StringUtils.isNonEmpty(m_oldLabel)) {
                return m_oldLabel;
            }
            if (!isYesMode()) {
                return m_oldLabel = ConsoleQuestionAsker.get().askUserOrThrow("Enter old label: ");
            }
            throw new IOException("ERROR: old label is required");
        }

        public void setNewLabel(final String _newLabel) {
            m_newLabel = _newLabel;
        }

        public void setOldLabel(final String _oldLabel) {
            m_oldLabel = _oldLabel;
        }
    }

    public static void main(final String... _args) {
//        System.out.println("Using PBEWithSHA1And3KeyTripleDES");
//        Security.setProperty("keystore.pkcs12.keyProtectionAlgorithm", "PBEWithSHA1And3KeyTripleDES");
        final CertRenameOpts opts = new CertRenameOpts();
        for (final String arg : _args) {
            if ("-y".equals(arg)) {
                opts.setYesMode(true);
            } else if ("-v".equals(arg)) {
                opts.setVerbose(true);
            } else if ("-h".equals(arg) || "--help".equals(arg)) {
                printUsageAndExit();
            } else if (arg.startsWith("--old-label=")) {
                opts.setOldLabel(DcmUserOpts.extractValue(arg));
            } else if (arg.startsWith("--new-label=")) {
                opts.setNewLabel(DcmUserOpts.extractValue(arg));
            } else if (arg.startsWith("--dcm-store=")) {
                final String target = DcmUserOpts.extractValue(arg);
                if ("system".equalsIgnoreCase(target) || "*system".equalsIgnoreCase(target)) {
                    opts.setDcmStore(DcmUserOpts.SYSTEM_DCM_STORE);
                } else {
                    opts.setDcmStore(target);
                }
            } else if (arg.startsWith("--dcm-password=")) {
                opts.setDcmPassword(DcmUserOpts.extractValue(arg));
            } else {
                System.err.println(StringUtils.colorizeForTerminal("ERROR: Unknown option '" + arg + "'", TerminalColor.BRIGHT_RED));
                printUsageAndExit();
            }
        }
        final AppLogger logger = AppLogger.getSingleton(opts.isVerbose());
        try {
            final DcmChangeTracker tracker = new DcmChangeTracker(logger, opts);

            final String oldLabel = opts.getOldLabel();
            final String newLabel = opts.getNewLabel();
            final KeyStore before = tracker.getStartingSnapshot().getKeyStore();
            if (!before.containsAlias(oldLabel)) {
                throw new IOException("ERROR: No certificate found with label '" + oldLabel + "'");
            }
            if (before.containsAlias(newLabel)) {
                throw new IOException("ERROR: A certificate with label '" + newLabel + "' already exists");
            }
            DcmStoreEditor.edit(logger, opts, tracker, Collections.singleton(oldLabel), Collections.singleton(newLabel), new DcmStoreEditor.Edit() {
                @Override
                public void apply(final KeyStore _ks, final char[] _storePassword) throws Exception {
                    if (_ks.isKeyEntry(oldLabel)) {
                        // A server/client certificate. Its private key and certificate chain must move with it, or
                        // it would come back as a certificate that can no longer be assigned to anything.
                        final Key key = _ks.getKey(oldLabel, _storePassword);
                        final Certificate[] chain = _ks.getCertificateChain(oldLabel);
                        if (null == key || null == chain || 0 == chain.length) {
                            throw new IOException("ERROR: '" + oldLabel + "' has a private key that cannot be read from the certificate store, so it cannot be renamed by this tool. No change was made");
                        }
                        _ks.deleteEntry(oldLabel);
                        _ks.setKeyEntry(newLabel, key, _storePassword, chain);
                    } else {
                        final Certificate cert = _ks.getCertificate(oldLabel);
                        if (null == cert) {
                            throw new IOException("ERROR: No certificate found with label '" + oldLabel + "'");
                        }
                        _ks.deleteEntry(oldLabel);
                        _ks.setCertificateEntry(newLabel, cert);
                    }
                }
            });
            if (before.isKeyEntry(oldLabel) && !tracker.getLatestSnapshot().getKeyStore().isKeyEntry(newLabel)) {
                logger.println_warn("WARNING: '" + newLabel + "' no longer appears to have its private key. Check the certificate in DCM before relying on it");
            }

            tracker.printChanges(logger, null);
            logger.println_success("SUCCESS!!!");
        } catch (final Exception e) {
            logger.printExceptionStack_verbose(e);
            logger.println_err(e.getLocalizedMessage());
            TempFileManager.cleanup();
            System.exit(-1);
        } finally {
            TempFileManager.cleanup();
        }

    }

    private static void printUsageAndExit() {
        // @formatter:off
        final String usage = "Usage: dcmrenamecert  [options]\n"
                + "\n"
                + "    Valid options include:\n"
                + "        -y:                            Do not ask for confirmation\n"
                + "        --dcm-store=<system/filename>: Specify the target keystore, or specify 'system'\n"
                + "                                       to indicate the *SYSTEM store (default)\n"
                + "        --dcm-password=<password>:     Provide the DCM keystore password (not recommended)\n"
                + "        --old-label=<label>:           Label of the certificate to rename\n"
                + "        --new-label=<label>:           New label for the certificate\n"
                ;
		// @formatter:on
        System.err.println(usage);
        System.exit(-1);
    }
}
