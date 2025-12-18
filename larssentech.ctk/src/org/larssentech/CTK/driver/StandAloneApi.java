// (c) 2015-2026 AVANZ.IO
// (c) 2008 Jeffrey J Cerasuolo

package org.larssentech.CTK.driver;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.EncoderException;
import org.larssentech.CTK.rsa.RSAKeyPairProcessor;
import org.larssentech.CTK.settings.CTKSettings;
import org.larssentech.lib.basiclib.io.Base64ObjectCoder;
import org.larssentech.lib.basiclib.toolkit.StringManipulationToolkit;
import org.larssentech.lib.log.Logg3r;

public class StandAloneApi implements CTKSettings {

	private final CTKDriver driver;
	private PublicKey loadedOtherUserPuk;

	public StandAloneApi() {

		// Start the model
		this.driver = new CTKDriver();

	}

	public boolean loadPublicKeyForUser(String userName, String otherUsersPath) {

		this.loadedOtherUserPuk = RSAKeyPairProcessor.loadPublicKeyForUser(userName, otherUsersPath);
		return null != this.loadedOtherUserPuk;
	}

	/**
	 * Method to request progress from the Blowfish engine (both enc and dec) and
	 * relay it to whoever is asking Progress is measured in bytes hence return is
	 * long
	 * 
	 * @return long
	 */
	public long getBlowfishProgress() {

		return this.driver.getBlowfishEngine().getProcessedBytes();
	}

	/**
	 * Method to request total bytes to be processed from the Blowfish engine and
	 * relay it to whoever is asking
	 * 
	 * @return long
	 */
	public long getBlowfishTotal() {

		return this.driver.getBlowfishEngine() == null ? 0 : this.driver.getBlowfishEngine().getTotalBytes();
	}

	/**
	 * Method to reset the Blowfish engine progress and total counters. This is
	 * invoked whenever a new run is required to "forget" the previous run results
	 * (which otherwise stay put for GUI purposes)
	 */
	public void resetBlowfishCounters() {

		if (this.driver.getBlowfishEngine() != null) this.driver.getBlowfishEngine().resetCounters();
	}

	/**
	 * Method to obtain a BASE64-encoded version of OUR OWN public key for
	 * save-to-file purposes
	 * 
	 * @return String
	 */
	public static String exportMyPublicKey(String ownPUKPath) {

		try {

			return new String(Base64ObjectCoder.encodeBytes(RSAKeyPairProcessor.getPublicKey4(ownPUKPath).getEncoded()));
		} catch (EncoderException e) {

			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Adds new contact and saves his public key in his folder
	 * 
	 * @param userName            String
	 * @param BASE64PubKeyAbsPath String
	 */
	public static void addContact(String userName0, String BASE64PubKeyAbsPath, String otherUsersPath) {

		new StringManipulationToolkit();
		// Clean user name to work with most filesystems
		String userName1 = userName0;

		// Make a dir for user
		String userDir = otherUsersPath + userName1;
		new File(otherUsersPath + userName1).mkdir();

		// Save the key
		RSAKeyPairProcessor.importAndSavePublicKeyFromBASE64File(BASE64PubKeyAbsPath, userDir + SEP + userName1);
	}

	/**
	 * Method to obtain an array with all stored public keys in the pub key lib
	 * directory. Method will return the names (Email, id, whatever) of the users as
	 * saved to file. Will ignore ".hidden" files
	 * 
	 * @return String[]
	 */
	public static String[] getContacts() {

		String[] aList = new File(OTHER_USERS_PUB_KEY_LIB).list();
		ArrayList<String> finalArrayList = new ArrayList<String>();

		// Iterator ite = aList.iterator();
		for (int i = 0; i < aList.length; i++) {

			String thisItem = aList[i].toString();
			if (!thisItem.startsWith(".")) finalArrayList.add(thisItem);
		}
		String[] returnArray = new String[finalArrayList.size()];
		for (int i = 0; i < finalArrayList.size(); i++) returnArray[i] = finalArrayList.get(i).toString();
		return returnArray;
	}

	public String[] decryptBlowfish(String text) {

		try {
			return this.driver.decryptBlowfish(text, this.loadedOtherUserPuk);
		}

		catch (InvalidKeyException e) {

			Logg3r.log("CTK (Standalone) - Message cannot be decrypted: invalid private key (" + e.getClass().toString() + ")");

		} catch (NoSuchAlgorithmException e) {

			Logg3r.log("CTK (Standalone) - Message cannot be decrypted: algorithm not supported (" + e.getClass().toString() + ")");

		} catch (NoSuchPaddingException e) {

			Logg3r.log("CTK (Standalone) - Message cannot be decrypted: padding is not supported (" + e.getClass().toString() + ")");

		} catch (IllegalBlockSizeException e) {

			Logg3r.log("CTK (Standalone) - Message cannot be decrypted: block size is illegal (" + e.getClass().toString() + ")");

		} catch (BadPaddingException e) {

			Logg3r.log("CTK (Standalone) - Message cannot be decrypted: bad padding (" + e.getClass().toString() + ")");

		} catch (IllegalStateException e) {

			Logg3r.log("CTK (Standalone) - Message cannot be decrypted: illegal state (" + e.getClass().toString() + ")");

		} catch (IllegalArgumentException e) {

			Logg3r.log("CTK (Standalone) - Message cannot be decrypted: illegal argument (" + e.getClass().toString() + ")");

		} catch (IOException e) {

			Logg3r.log("CTK (Standalone) - Message cannot be decrypted: IO problem (" + e.getClass().toString() + ")");

		} catch (SignatureException e) {

			Logg3r.log("CTK (Standalone) - Message cannot be encrypted: Signature problem (" + e.getClass().toString() + ")");
		}

		return new String[0];
	}

	public String[] encryptBlowfish(String text) {

		try {
			return this.driver.encryptBlowfish(text, this.loadedOtherUserPuk);
		}

		catch (InvalidKeyException e) {

			Logg3r.log("CTK (Standalone) - Message cannot be encrypted: invalid private key (" + e.getClass().toString() + ")");

		} catch (NoSuchAlgorithmException e) {

			Logg3r.log("CTK (Standalone) - Message cannot be encrypted: algorithm not supported (" + e.getClass().toString() + ")");

		} catch (NoSuchPaddingException e) {

			Logg3r.log("CTK (Standalone) - Message cannot be encrypted: padding is not supported (" + e.getClass().toString() + ")");

		} catch (IllegalBlockSizeException e) {

			Logg3r.log("CTK (Standalone) - Message cannot be encrypted: block size is illegal (" + e.getClass().toString() + ")");

		} catch (BadPaddingException e) {

			Logg3r.log("CTK (Standalone) - Message cannot be encrypted: bad padding (" + e.getClass().toString() + ")");

		} catch (IllegalStateException e) {

			Logg3r.log("CTK (Standalone) - Message cannot be encrypted: illegal state (" + e.getClass().toString() + ")");

		} catch (IllegalArgumentException e) {

			Logg3r.log("CTK (Standalone) - Message cannot be encrypted: illegal argument (" + e.getClass().toString() + ")");

		} catch (IOException e) {

			Logg3r.log("CTK (Standalone) - Message cannot be encrypted: IO problem (" + e.getClass().toString() + ")");

		} catch (SignatureException e) {

			Logg3r.log("CTK (Standalone) - Message cannot be encrypted: Signature problem (" + e.getClass().toString() + ")");
		}

		return new String[0];

	}

}