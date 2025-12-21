// (c) 2015-2026 AVANZ.IO
// (c) 2008 Jeffrey J Cerasuolo

package org.larssentech.CTK.rsa;

import java.io.File;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import org.larssentech.CTK.settings.CTKSettings;
import org.larssentech.lib.log.Logg3r;

public class RSAKeyPairInit {

	/**
	 * Method to initialize the application making sure that there is a RSA key pair
	 * stored in the user's home directory inder .nxrsa folder The argument "param"
	 * is passed by the user and can be: -k = The user requests a new key pair
	 * because he wants/needs a new one <anything else> = The user wants to go with
	 * his existing key pair If -k we create a new key pair, then we store it and
	 * tell the user If <anything else> then we load his saved key pair and tell the
	 * user
	 *
	 * @param param String
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @return boolean
	 */
	public static boolean init(String param, String pkPath, String pukPath, String path) {

		// If user requests new key pair
		if (param.equals("-k")) {

			// If key pair exists exit
			if (RSAKeyPairProcessor.rsaKeysExist()) {

				Logg3r.log2(new File("ctk.log"), "USER ERROR");
				Logg3r.log2(new File("ctk.log"), "RSA key pair already exists but new key pair was requested.");
				Logg3r.log2(new File("ctk.log"), "You need to delete previous keys in order to request new ones");
				Logg3r.log2(new File("ctk.log"), "to be generated.");
				return false;
			}

			// Else create, save and tell user
			else {

				KeyPair k = null;
				try {
					k = RSAKeyPairProcessor.createRSAKeyPair(2048);
				} catch (InvalidAlgorithmParameterException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				// Then save the keys to file and tell the user
				if (RSAKeyPairProcessor.savePrivateKeyToFile(k.getPrivate(), pkPath, path) && RSAKeyPairProcessor.savePublicKeyToFile(k.getPublic(), pukPath, path)) {

					Logg3r.log2(new File("ctk.log"), "New RSA key pair created. Saved in home dir under: " + CTKSettings.OWN_RSA_DIR);
				}

				// Or if failed, exit
				else {

					Logg3r.log2(new File("ctk.log"), "PROGRAM ERROR");
					Logg3r.log2(new File("ctk.log"), "User requested RSA keys to be created, but could not save them to file");
					return false;
				}
			}
		}

		// If user did not request key pair creation
		else {

			// And key pair does not exist
			if (!RSAKeyPairProcessor.rsaKeysExist()) {

				Logg3r.log2(new File("ctk.log"), "USER ERROR");
				Logg3r.log2(new File("ctk.log"), "RSA key pair does not exist and new key pair was not requested.");
				Logg3r.log2(new File("ctk.log"), "You need to either have a key pair or request a new one");
				Logg3r.log2(new File("ctk.log"), "to be generated.");
				return false;
			}
		}

		// At this point we are sure we have a key pair so we are INIT-ed
		// this.rSAKeyPairProcessor.loadPrivateKeyFromFile(pkPath);

		return true;
	}
}
