// (c) 2005-2022 AVANZ.IO
// (c) 2008 Jeffrey J Cerasuolo

package org.larssentech.CTK.settings;

public class RSAPathBundle {

	private static String ownPKPath;
	private static String ownPUKPath;
	private static String ownKeyPairPath;
	private static String cipherString;

	public static void setOwnPKPath(String ownPKPath) {

		RSAPathBundle.ownPKPath = ownPKPath;
	}

	public static void setOwnPUKPath(String ownPUKPath) {

		RSAPathBundle.ownPUKPath = ownPUKPath;
	}

	public static void setOwnKeyPairPath(String ownKeyPairPath) {

		RSAPathBundle.ownKeyPairPath = ownKeyPairPath;
	}

	public static String getOwnPKPath() {

		return ownPKPath;
	}

	public static String getOwnPUKPath() {

		return ownPUKPath;
	}

	public static String getOwnKeyPairPath() {

		return ownKeyPairPath;
	}

	public static String getCipherString() {

		return cipherString;
	}

	public static void setCipherString(String string) {

		cipherString = string;

	}
}
