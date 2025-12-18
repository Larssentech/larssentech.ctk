// (c) 2015-2026 AVANZ.IO
// (c) 2008 Jeffrey J Cerasuolo

package org.larssentech.CTK.settings;

public interface CTKSettings {

	public static final String VERSION = "NX CTK v.1.7.0 #20251217";

	public static final String OWN_PRI_K_NAME = "NX_RSA_PRI_KEY";
	public static final String OWN_PUB_K_NAME = "NX_RSA_PUB_KEY";
	public static final String HOME_DIR = System.getProperty("user.home");
	public static final String SEP = System.getProperty("file.separator");

	public static final String OWN_RSA_DIR = ".nxrsa";
	public static final String OWN_KEYPAIR_ABS_PATH = HOME_DIR + SEP + OWN_RSA_DIR + SEP;
	public static final String OWN_PRI_K_ABS_PATH = HOME_DIR + SEP + OWN_RSA_DIR + SEP + OWN_PRI_K_NAME;
	public static final String OWN_PUB_K_ABS_PATH = HOME_DIR + SEP + OWN_RSA_DIR + SEP + OWN_PUB_K_NAME;

	public static final String PUB_KY_LIB = "nxrsa_pub_key_lib";
	public static final String OTHER_USERS_PUB_KEY_LIB = CTKSettings.HOME_DIR + CTKSettings.SEP + PUB_KY_LIB;

	public static final String CTK_HOME = ".nxctk";
	public static final String SETTINGS_PATH = CTKSettings.HOME_DIR + CTKSettings.SEP + CTKSettings.CTK_HOME + CTKSettings.SEP + "nxctk.ini";
	public static final String ENCMSG = "Blowfish file contains secret key encripted with RSA as header block";
	public static final String EXT = ".blowfish";

}