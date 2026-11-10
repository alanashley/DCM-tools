package com.github.ibmioss.dcmtools.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyStore;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.github.ibmioss.dcmtools.DcmUserOpts;
import com.github.ibmioss.dcmtools.utils.DcmChangeTracker.CertAddedhange;
import com.github.ibmioss.dcmtools.utils.DcmChangeTracker.CertRemovedChange;
import com.github.ibmioss.dcmtools.utils.DcmChangeTracker.DcmChange;
import com.github.theprez.jcmdutils.AppLogger;

/**
 * Makes an in-place change to a DCM certificate store, and makes sure that the change that happened is the change that
 * was asked for. The store is backed up first. If the change fails, or if anything other than the expected
 * certificates were added or removed, the store is put back the way it was.
 */
public class DcmStoreEditor {

    /** The change to make to the store */
    public interface Edit {
        void apply(KeyStore _ks, char[] _storePassword) throws Exception;
    }

    private static final String[] COMPANION_EXTENSIONS = { "rdb", "sth", "crl" };

    public static void edit(final AppLogger _logger, final DcmUserOpts _opts, final DcmChangeTracker _tracker, final Collection<String> _expectedRemovals, final Collection<String> _expectedAdditions, final Edit _edit) throws Exception {
        final File store = new File(_opts.getDcmStore());
        final char[] password = _opts.getDcmPassword().toCharArray();
        final Map<File, File> backups = backup(store);
        boolean isBackupStillNeeded = true;
        try {
            try {
                final KeyStore ks = KeyStore.getInstance("IBMi5OSKeyStore");
                try (FileInputStream fis = new FileInputStream(store)) {
                    ks.load(fis, password);
                }
                _edit.apply(ks, password);
                try (FileOutputStream fos = new FileOutputStream(store)) {
                    ks.store(fos, password);
                }
            } catch (final Exception e) {
                restore(_logger, backups);
                isBackupStillNeeded = false;
                throw e;
            }

            final List<DcmChange> changes;
            try {
                changes = _tracker.getChanges(_logger);
            } catch (final Exception e) {
                // The store can no longer be read. That is as unexpected as it gets.
                restore(_logger, backups);
                isBackupStillNeeded = false;
                throw new IOException("The certificate store could not be read back after the change, so it has been restored to its previous contents. (" + e.getMessage() + ")", e);
            }
            final List<String> problems = findUnexpectedChanges(changes, _expectedRemovals, _expectedAdditions);
            if (!problems.isEmpty()) {
                restore(_logger, backups);
                isBackupStillNeeded = false;
                String msg = "The change did not have the expected result, so the certificate store has been restored to its previous contents:";
                for (final String problem : problems) {
                    msg += "\n    " + problem;
                }
                throw new IOException(msg);
            }
            isBackupStillNeeded = false;
        } finally {
            if (isBackupStillNeeded) {
                // We could not put things back. Do not throw away the only good copy.
                for (final File backup : backups.values()) {
                    _logger.println_err("A backup copy was kept at " + backup.getAbsolutePath());
                }
            } else {
                for (final File backup : backups.values()) {
                    backup.delete();
                }
            }
        }
    }

    /**
     * Compares the changes that happened to the changes that were asked for
     *
     * @return a description of each discrepancy. Empty if all is well
     */
    public static List<String> findUnexpectedChanges(final List<DcmChange> _changes, final Collection<String> _expectedRemovals, final Collection<String> _expectedAdditions) {
        final List<String> problems = new LinkedList<String>();
        final List<String> missingRemovals = new LinkedList<String>(_expectedRemovals);
        final List<String> missingAdditions = new LinkedList<String>(_expectedAdditions);
        for (final DcmChange change : _changes) {
            final String label = change.getLabel();
            if (change instanceof CertRemovedChange) {
                if (!removeIgnoreCase(missingRemovals, label)) {
                    problems.add("Certificate '" + label + "' was removed unexpectedly");
                }
            } else if (change instanceof CertAddedhange) {
                if (!removeIgnoreCase(missingAdditions, label)) {
                    problems.add("Certificate '" + label + "' was added unexpectedly");
                }
            } else {
                problems.add("Certificate '" + label + "' was changed unexpectedly");
            }
        }
        for (final String label : missingRemovals) {
            problems.add("Certificate '" + label + "' was not removed");
        }
        for (final String label : missingAdditions) {
            problems.add("Certificate '" + label + "' was not added");
        }
        return problems;
    }

    private static boolean removeIgnoreCase(final List<String> _list, final String _value) {
        for (final String entry : _list) {
            if (entry.equalsIgnoreCase(_value)) {
                _list.remove(entry);
                return true;
            }
        }
        return false;
    }

    /**
     * Copies the store file, and the files that go with it (such as the <tt>.RDB</tt> request database)
     *
     * @return the backups made, keyed by the file each one is a copy of
     */
    static Map<File, File> backup(final File _store) throws IOException {
        if (!_store.isFile()) {
            throw new IOException("Certificate store '" + _store.getAbsolutePath() + "' does not exist");
        }
        final Map<File, File> ret = new LinkedHashMap<File, File>();
        final String suffix = ".dcmtools-backup-" + new SimpleDateFormat("yyyyMMddHHmmssSSS").format(new Date());
        final List<File> toBackup = new LinkedList<File>();
        toBackup.add(_store);
        final String storeName = _store.getName();
        final int dot = storeName.lastIndexOf('.');
        final File[] siblings = _store.getAbsoluteFile().getParentFile().listFiles();
        if (dot > 0 && null != siblings) {
            final String base = storeName.substring(0, dot);
            for (final File sibling : siblings) {
                for (final String ext : COMPANION_EXTENSIONS) {
                    if (sibling.isFile() && sibling.getName().equalsIgnoreCase(base + "." + ext)) {
                        toBackup.add(sibling);
                    }
                }
            }
        }
        try {
            for (final File f : toBackup) {
                final File backup = new File(f.getAbsolutePath() + suffix);
                Files.copy(f.toPath(), backup.toPath());
                ret.put(f, backup);
            }
        } catch (final IOException e) {
            for (final File backup : ret.values()) {
                backup.delete();
            }
            throw new IOException("Unable to back up the certificate store before changing it, so no change was made. (" + e.getMessage() + ")", e);
        }
        return ret;
    }

    /**
     * Puts the backed-up contents back. The contents are written into the existing files, rather than the files being
     * replaced, so that the ownership and authorities of the originals are left as they are.
     */
    static void restore(final AppLogger _logger, final Map<File, File> _backups) throws IOException {
        for (final Map.Entry<File, File> entry : _backups.entrySet()) {
            try (FileOutputStream out = new FileOutputStream(entry.getKey())) {
                Files.copy(entry.getValue().toPath(), out);
            } catch (final IOException e) {
                throw new IOException("Unable to restore the certificate store! A backup copy is at " + entry.getValue().getAbsolutePath() + " (" + e.getMessage() + ")", e);
            }
        }
        _logger.println_warn("The certificate store has been restored to its previous contents");
    }
}
