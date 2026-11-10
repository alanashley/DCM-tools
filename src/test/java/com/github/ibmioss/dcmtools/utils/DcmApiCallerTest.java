package com.github.ibmioss.dcmtools.utils;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import com.ibm.as400.access.AS400Bin4;
import com.ibm.as400.access.ErrorCodeParameter;
import com.ibm.as400.access.ProgramParameter;

public class DcmApiCallerTest {

    @Test
    public void everyServiceProgramParameterIsPassedByReference() throws Exception {
        // QycdUpdateCertUsage has eight parameters, and JTOpen requires pointers for all of them beyond seven
        final ProgramParameter[] parms = new ProgramParameter[8];
        for (int i = 0; i < 7; i++) {
            parms[i] = new ProgramParameter(new AS400Bin4().toBytes(i));
            assertEquals(ProgramParameter.PASS_BY_VALUE, parms[i].getParameterType());
        }
        parms[7] = new ErrorCodeParameter(true, true);
        DcmApiCaller.passAllByReference(parms);
        for (final ProgramParameter parm : parms) {
            assertEquals(ProgramParameter.PASS_BY_REFERENCE, parm.getParameterType());
        }
    }

    @Test
    public void passwordLengthIsCountedInUtf8Bytes() {
        assertEquals(6, DcmApiCaller.utf8("secret").length);
        // six characters, but eight bytes once encoded for the API
        assertEquals(8, DcmApiCaller.utf8("pässwö").length);
    }
}
