package com.github.ibmioss.dcmtools.utils;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.github.ibmioss.dcmtools.utils.DcmChangeTracker.CertAddedhange;
import com.github.ibmioss.dcmtools.utils.DcmChangeTracker.CertRemovedChange;
import com.github.ibmioss.dcmtools.utils.DcmChangeTracker.CertUpdatedhange;
import com.github.ibmioss.dcmtools.utils.DcmChangeTracker.DcmChange;

public class DcmStoreEditorTest {

    @Rule
    public TemporaryFolder m_tmp = new TemporaryFolder();

    private static final List<String> NONE = Collections.<String>emptyList();

    @Test
    public void expectedRemovalIsAccepted() {
        final List<DcmChange> changes = Arrays.<DcmChange>asList(new CertRemovedChange("test"));
        assertTrue(DcmStoreEditor.findUnexpectedChanges(changes, Arrays.asList("TEST"), NONE).isEmpty());
    }

    @Test
    public void removalOfOtherCertificatesIsCaught() {
        // the "it wiped every cert" scenario
        final List<DcmChange> changes = Arrays.<DcmChange>asList(new CertRemovedChange("test"), new CertRemovedChange("other1"), new CertRemovedChange("other2"));
        final List<String> problems = DcmStoreEditor.findUnexpectedChanges(changes, Arrays.asList("test"), NONE);
        assertEquals(2, problems.size());
        assertTrue(problems.get(0).contains("other1"));
        assertTrue(problems.get(1).contains("other2"));
    }

    @Test
    public void renameMustRemoveOldAndAddNew() {
        final List<DcmChange> ok = Arrays.<DcmChange>asList(new CertRemovedChange("old"), new CertAddedhange("new", null));
        assertTrue(DcmStoreEditor.findUnexpectedChanges(ok, Arrays.asList("old"), Arrays.asList("new")).isEmpty());

        final List<DcmChange> lost = Arrays.<DcmChange>asList(new CertRemovedChange("old"));
        final List<String> problems = DcmStoreEditor.findUnexpectedChanges(lost, Arrays.asList("old"), Arrays.asList("new"));
        assertEquals(Arrays.asList("Certificate 'new' was not added"), problems);
    }

    @Test
    public void nothingHappeningAndUpdatesAreProblems() {
        assertEquals(1, DcmStoreEditor.findUnexpectedChanges(Collections.<DcmChange>emptyList(), Arrays.asList("test"), NONE).size());
        final List<DcmChange> updated = Arrays.<DcmChange>asList(new CertRemovedChange("test"), new CertUpdatedhange("other", null, null));
        assertEquals(1, DcmStoreEditor.findUnexpectedChanges(updated, Arrays.asList("test"), NONE).size());
    }

    @Test
    public void backupAndRestoreCoverTheStoreAndItsCompanionFiles() throws Exception {
        final File kdb = m_tmp.newFile("DEFAULT.KDB");
        final File rdb = m_tmp.newFile("DEFAULT.RDB");
        final File unrelated = m_tmp.newFile("OTHER.KDB");
        Files.write(kdb.toPath(), new byte[] { 1, 2, 3 });
        Files.write(rdb.toPath(), new byte[] { 4, 5 });
        Files.write(unrelated.toPath(), new byte[] { 6 });

        final Map<File, File> backups = DcmStoreEditor.backup(kdb);
        assertEquals(2, backups.size());

        // simulate the store being wiped
        Files.write(kdb.toPath(), new byte[0]);
        Files.write(rdb.toPath(), new byte[0]);

        DcmStoreEditor.restore(TestFiles.LOGGER, backups);
        assertArrayEquals(new byte[] { 1, 2, 3 }, Files.readAllBytes(kdb.toPath()));
        assertArrayEquals(new byte[] { 4, 5 }, Files.readAllBytes(rdb.toPath()));
        assertArrayEquals(new byte[] { 6 }, Files.readAllBytes(unrelated.toPath()));
    }

    @Test
    public void missingStoreIsReportedBeforeAnythingIsTouched() throws Exception {
        try {
            DcmStoreEditor.backup(new File(m_tmp.getRoot(), "nope.kdb"));
            fail("expected a failure");
        } catch (final IOException e) {
            assertTrue(e.getMessage().contains("does not exist"));
        }
    }
}
