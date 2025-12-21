// (c) 2015-2026 AVANZ.IO
// (c) 2008 Jeffrey J Cerasuolo

package org.larssentech.CTK.rsa;

import java.io.File;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.larssentech.CTK.settings.RSAPathBundle;
import org.larssentech.lib.CTK.objects.PUK;
import org.larssentech.lib.basiclib.io.Base64ObjectCoder;
import org.larssentech.lib.basiclib.io.file.ReadBytesFromFile;
import org.larssentech.lib.basiclib.io.file.WriteBytesTofile;

public class RSAKeyPairProcessor {

	public static boolean rsaKeysExist() {

		String s0 = RSAPathBundle.getOwnPKPath();
		String s1 = RSAPathBundle.getOwnPUKPath();

		return new File(RSAPathBundle.getOwnPKPath()).exists() && new File(RSAPathBundle.getOwnPUKPath()).exists();
	}

	static KeyPair createRSAKeyPair(int keySize) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {

		return new RSAKeyPairCreator().generateKeys(keySize);
	}

	public static PrivateKey getPrivateKeyFromBytes(byte[] in) {

		try {

			PKCS8EncodedKeySpec pkcs8SpecPriv = new PKCS8EncodedKeySpec(in);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			return keyFactory.generatePrivate(pkcs8SpecPriv);
		} catch (Exception e) {

			e.printStackTrace();
			return null;
		}
	}

	static boolean savePrivateKeyToFile(PrivateKey key, String fileName, String path) {

		new File(path).mkdir();
		return WriteBytesTofile.writeBytesToFile(key.getEncoded(), fileName);
	}

	public static PublicKey receivePublicKeyForUser(PUK puk) {

		return RSAKeyPairProcessor.getPublicKeyFromBytes(puk);
	}

	public static PublicKey getPublicKeyFromBytes(PUK in) {

		try {

			X509EncodedKeySpec x509PublicKeySpec = new X509EncodedKeySpec(in.getByteArray());
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			return keyFactory.generatePublic(x509PublicKeySpec);
		} catch (Exception e) {

			e.printStackTrace();
			return null;
		}
	}

// TODO from UCDetector: Change visibility of Method "RSAKeyPairProcessor.savePublicKeyToFile(PublicKey,String,String)" to default
	public static boolean savePublicKeyToFile(PublicKey key, String fileName, String path) { // NO_UCD
																								// (use
																								// default)

		new File(path).mkdir();
		new WriteBytesTofile();
		return WriteBytesTofile.writeBytesToFile(key.getEncoded(), fileName);
	}

	private static final String SEP = System.getProperty("file.separator");

	/**
	 * Requests the read, import and load of the public key for ANOTHER user This
	 * method allows us to encrypt data for another user with his public key.
	 * Returns true if successful, false otherwise
	 * 
	 * @param userName String
	 */
	public static PublicKey loadPublicKeyForUser(String userName, String otherUsersPath) {

		String fileName = otherUsersPath + SEP + userName + SEP + userName;

		return getPublicKeyFromFile(fileName);
	}

	/**
	 * Opens and loads a public key from a file Returns the pub key object, which
	 * will be null if failed
	 * 
	 * @param fileName String
	 * @return PublicKey
	 */
	private static PublicKey getPublicKeyFromFile(String fileName) {

		return getPublicKeyFromBytes(ReadBytesFromFile.readBytesFromFile(fileName));
	}

	/**
	 * Imports a public key from a byte array and returns the pub key object Returns
	 * null if it fails
	 * 
	 * @param in byte[]
	 * @return PrivateKey
	 */
	public static PublicKey getPublicKeyFromBytes(byte[] in) {

		try {
			X509EncodedKeySpec x509PublicKeySpec = new X509EncodedKeySpec(in);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			return keyFactory.generatePublic(x509PublicKeySpec);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Method to get our own public key for expot purposes (or other purposes :-)
	 * 
	 * @return PublicKey
	 */
	public static PublicKey getPublicKey4(String ownPUKPath) {

		return getPublicKeyFromBytes(ReadBytesFromFile.readBytesFromFile(ownPUKPath));
	}

	/**
	 * Takes a BASE64 encoded string with a user's public key from the given
	 * filename, imports the bytes and finally saves the key to the given filename
	 * in bytes and returns success or failure
	 * 
	 * @return boolean
	 * @param BASE64FileName String
	 * @param fileName       String
	 */
	public static boolean importAndSavePublicKeyFromBASE64File(String BASE64FileName, String fileName) {

		// Import key
		byte[] puKbytes = importPublicKeyBASE64FileToBytes(BASE64FileName);

		// Save to file
		if (fileName.length() > 0) {
			new WriteBytesTofile();
			return WriteBytesTofile.writeBytesToFile(puKbytes, fileName);
		} else return false;
	}

	/**
	 * Takes a BASE64 encoded file with the users public key, decodes it into a
	 * bytes array and returns it
	 * 
	 * @param BASE64FileName String
	 * @return byte[]
	 */
	private static byte[] importPublicKeyBASE64FileToBytes(String BASE64FileName) {

		String textPubKey = new String(ReadBytesFromFile.readBytesFromFile(BASE64FileName));
		return importPublicKeyBASE64StringToBytes(textPubKey);
	}

	/**
	 * Takes a BASE64 encoded string from argument with the users public key,
	 * decodes it into a bytes array and returns it
	 * 
	 * @param BASE64String String
	 * @return byte[]
	 */
	public static byte[] importPublicKeyBASE64StringToBytes(String BASE64String) {

		byte[] puKbytes = null;
		try {
			new Base64ObjectCoder();
			puKbytes = Base64ObjectCoder.decodeBytes(BASE64String.getBytes());
		} catch (Exception e) {
			return null;
		}

		return puKbytes;
	}
}
