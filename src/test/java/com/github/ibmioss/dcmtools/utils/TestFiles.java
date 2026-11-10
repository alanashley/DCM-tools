package com.github.ibmioss.dcmtools.utils;

import java.io.File;
import java.net.URISyntaxException;
import java.net.URL;

import com.github.theprez.jcmdutils.AppLogger;

final class TestFiles {
    static final AppLogger LOGGER = AppLogger.getSingleton(false);
    static final String PASSWORD = "secret";

    static String path(final String _name) {
        final URL url = TestFiles.class.getResource("/certs/" + _name);
        if (null == url) {
            throw new IllegalArgumentException("No such test file: " + _name);
        }
        try {
            return new File(url.toURI()).getAbsolutePath();
        } catch (final URISyntaxException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private TestFiles() {
    }
}
