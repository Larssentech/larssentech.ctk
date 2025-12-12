// (c) 2005-2022 AVANZ.IO
// (c) 2008 Jeffrey J Cerasuolo
package org.larssentech.CTK.LOG;

import java.util.Date;

import org.larssentech.lib.basiclib.console.Out;
import org.larssentech.lib.basiclib.io.text.SaveToFile;

public class CTKLogger extends Out {

	private static String LOG_FILE_NAME = "ctk.log";
	private static boolean VERBOSE = false;

	public static void logThis(String s) {

		if (VERBOSE) { Out.pl(new Date() + " - " + s); SaveToFile.saveToFile(LOG_FILE_NAME, new Date() + " - " + s, true); }
	}
}
