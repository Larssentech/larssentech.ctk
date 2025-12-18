// (c) 2015-2026 AVANZ.IO
// (c) 2008 Jeffrey J Cerasuolo

package org.larssentech.CTK.ui.gui;

import java.io.InputStream;

import org.larssentech.lib.basiclib.io.parser.ArrayBuilder;

class NxCTKLangMap {

	private String[][] langData;

	public NxCTKLangMap() {

		InputStream langFile = null;

		try {

			langFile = this.getClass().getResourceAsStream("lang.dat");
		}
		catch (Exception e) {}
		new ArrayBuilder();
		this.langData = ArrayBuilder.makeArrayFromTSVExcludeLines(langFile, 0);

	}

	String getInLang(String what, String lang) {

		int col = 1;
		for (int i = 0; i < this.langData[0].length; i++) if (this.langData[0].length > 0 && this.langData[0][i].equals(lang)) {

			col = i;
			break;
		}
		for (int i = 0; i < this.langData.length; i++) if (this.langData[i][0].equals(what)) return this.langData[i][col];
		return what;
	}
}
