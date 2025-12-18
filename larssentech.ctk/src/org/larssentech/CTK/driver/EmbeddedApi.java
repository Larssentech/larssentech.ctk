// (c) 2015-2026 AVANZ.IO
// (c) 2008 Jeffrey J Cerasuolo

package org.larssentech.CTK.driver;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.EncoderException;
import org.larssentech.CTK.rsa.RSAKeyPairProcessor;
import org.larssentech.CTK.settings.CTKSettings;
import org.larssentech.CTK.settings.RSAPathBundle;
import org.larssentech.lib.CTK.objects.PUK;
import org.larssentech.lib.basiclib.io.Base64ObjectCoder;
import org.larssentech.lib.basiclib.io.file.ReadBytesFromFile;
import org.larssentech.lib.log.Logg3r;

public class EmbeddedApi implements CTKSettings {

	private PublicKey loadedOtherUserPuk;
	private CTKDriver driver;

	public EmbeddedApi() {

		// Start the model
		this.driver = new CTKDriver();
	}

	public static String exportPuk2Base64(String pukPath) {

		try {

			return new String(Base64ObjectCoder.encodeBytes(RSAKeyPairProcessor.getPublicKey4(pukPath).getEncoded()));
		} catch (EncoderException e) {

			e.printStackTrace();
		}
		return "";
	}

	public PublicKey getPublicKeyFromFile(String fileName) {

		return getPublicKeyFromBytes(ReadBytesFromFile.readBytesFromFile(fileName));
	}

	/**
	 * Imports a public key from a byte array and returns the pub key object Returns
	 * null if it fails
	 * 
	 * @param in byte[]
	 * @return PrivateKey
	 */
	public PublicKey getPublicKeyFromBytes(byte[] in) {

		try {
			X509EncodedKeySpec x509PublicKeySpec = new X509EncodedKeySpec(in);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			return keyFactory.generatePublic(x509PublicKeySpec);
		} catch (Exception e) {
			Logg3r.log(e.toString());
			return null;
		}
	}

	public boolean loadPublicKeyForUser(String userName, String otherUsersPath) {

		this.loadedOtherUserPuk = RSAKeyPairProcessor.loadPublicKeyForUser(userName, otherUsersPath);
		return null != this.loadedOtherUserPuk;
	}

	public boolean loadPublicKeyForUser(PUK puk) {

		this.loadedOtherUserPuk = this.driver.receivePublicKeyForUser(puk);
		return null != this.loadedOtherUserPuk;
	}

	public byte[] encryptSignMessage(byte[] plainTextBytes, PUK puk) {

		try {

			// Everytime we call the methids, first thing is to tell the API
			// what the other user PUK is
			;

			/**
			 * Now we can encrypt with their puk, sign with our prik and encode the result
			 * into Base64 ready to send.
			 */
			byte[] b = this.driver.encryptSignBytes(plainTextBytes, this.driver.receivePublicKeyForUser(puk));

			return Base64ObjectCoder.encodeBytes(b);

		} catch (InvalidKeyException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be encrypted: invalid private key (" + e.getClass().toString() + ") returning cyphertext as plaintext (IllegalArgumentException)");

		} catch (NoSuchAlgorithmException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be encrypted: algorithm not supported (" + e.getClass().toString() + ") returning cyphertext as plaintext (IllegalArgumentException)");

		} catch (NoSuchPaddingException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be encrypted: padding is not supported (" + e.getClass().toString() + ") returning cyphertext as plaintext (IllegalArgumentException)");

		} catch (IllegalBlockSizeException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be encrypted: block size is illegal (" + e.getClass().toString() + ") returning cyphertext as plaintext (IllegalArgumentException)");

		} catch (BadPaddingException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be encrypted: bad padding (" + e.getClass().toString() + ") returning cyphertext as plaintext (IllegalArgumentException)");

		} catch (IllegalStateException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be encrypted: illegal state (" + e.getClass().toString() + ") returning cyphertext as plaintext (IllegalArgumentException)");

		} catch (IllegalArgumentException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be encrypted: illegal argument (" + e.getClass().toString() + ") returning cyphertext as plaintext (IllegalArgumentException)");

		} catch (IOException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be encrypted: IO problem (" + e.getClass().toString() + ") returning cyphertext as plaintext (IllegalArgumentException)");

		} catch (EncoderException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be encrypted: encoder problem (" + e.getClass().toString() + ") returning cyphertext as plaintext (IllegalArgumentException)");

		} catch (SignatureException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be signed: signature problem (" + e.getClass().toString() + ") returning cyphertext as plaintext (IllegalArgumentException)");
		}

		return plainTextBytes;
	}

	public byte[] decryptVerifyMessage(byte[] cipherText, PUK puk) {

		try {

			/**
			 * Now we can decript with our prik, verify with their puk and decode the result
			 * from Base64 to string ready to read.
			 */
			return this.driver.decryptVerifyBytes(Base64ObjectCoder.decodeBytes(cipherText), this.driver.receivePublicKeyForUser(puk));

		} catch (InvalidKeyException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be decrypted: invalid private key (" + e.getClass().toString() + ") returning cyphertext as plaintext");

		} catch (NoSuchAlgorithmException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be decrypted: algorithm not supported (" + e.getClass().toString() + ") returning cyphertext as plaintext");

		} catch (NoSuchPaddingException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be decrypted: padding is not supported (" + e.getClass().toString() + ") returning cyphertext as plaintext");

		} catch (IllegalBlockSizeException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be decrypted: block size is illegal (" + e.getClass().toString() + ") returning cyphertext as plaintext");

		} catch (BadPaddingException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be decrypted: bad padding (" + e.getClass().toString() + ") returning cyphertext as plaintext");

		} catch (IllegalStateException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be decrypted: illegal state (" + e.getClass().toString() + ") returning cyphertext as plaintext");

		} catch (IllegalArgumentException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be decrypted: illegal argument (" + e.getClass().toString() + ") returning cyphertext as plaintext");

		} catch (IOException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be decrypted: IO problem (" + e.getClass().toString() + ") returning cyphertext as plaintext");

		} catch (DecoderException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be Base64 decoded: Base64 problem (" + e.getClass().toString() + ") returning cyphertext as plaintext");

		} catch (SignatureException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be verified: signature problem (" + e.getClass().toString() + ") returning cyphertext as plaintext");
		}

		return cipherText;
	}

	public boolean init(boolean verbose) {

		Logg3r.log(CTKSettings.VERSION);

		boolean rsaSupported = true;
		boolean rsaKeySupported = true;
		boolean keysExist = true;
		boolean nxCTKInited = true;

		// Initialize it. If keys not found, init requesting new pair & tell
		// user
		boolean toolkitInited = false;

		this.driver.doInit();

		toolkitInited = this.driver.isInited();

		Logg3r.log(new Date() + " >> " + "EmbeddedApi:" + "\t");
		Logg3r.log(new Date() + " >> " + "CTK Initialisation: toolkitInited=" + toolkitInited);

		// If no exception was thrown but keys were not found this means the
		// system is good but we are new so request creation of keys
		if (!toolkitInited) {

			Logg3r.log("RSA_KEY_PAIR_NOT_FOUND");
			Logg3r.log("Requesting the creation of a new KeyPair.");
			Logg3r.log("This may take a minute, please wait...");

			try {

				toolkitInited = this.driver.init("-k");

			} catch (Exception e) {

				nxCTKInited = false;
			}

		} else

			if (!this.driver.keysExist(RSAPathBundle.getOwnPKPath(), RSAPathBundle.getOwnPUKPath())) {

				keysExist = false;
			}

		if (!rsaSupported || !rsaKeySupported || !keysExist || !nxCTKInited) {

			Logg3r.log("There seems to be a problem with your system. This could be:");
			Logg3r.log("- RSA cipher not supported (get Java 1.5 or better)");
			Logg3r.log("- RSA key size not supported (get Java 1.5 or better)");
			Logg3r.log("- Your RSA key pair cannot be found (close and reopen)");
			Logg3r.log("- Filesystem is read only");
			Logg3r.log("- Something else that can't be resolved");

			// System.exit(-1);
		}
		return rsaSupported && rsaKeySupported && keysExist && nxCTKInited;

	}

	public byte[] encryptBlowfish(byte[] plainBytes, long bytesDone, PUK otherUserPuK) {

		try {
			return this.driver.encryptBlowfish(plainBytes, bytesDone, RSAKeyPairProcessor.getPublicKeyFromBytes(otherUserPuK));

		} catch (InvalidKeyException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be decrypted: invalid private key (" + e.getClass().toString() + ")");

		} catch (NoSuchAlgorithmException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be decrypted: algorithm not supported (" + e.getClass().toString() + ")");

		} catch (NoSuchPaddingException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be decrypted: padding is not supported (" + e.getClass().toString() + ")");

		} catch (IllegalBlockSizeException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be decrypted: block size is illegal (" + e.getClass().toString() + ")");

		} catch (BadPaddingException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be decrypted: bad padding (" + e.getClass().toString() + ")");

		} catch (IllegalStateException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be decrypted: illegal state (" + e.getClass().toString() + ")");

		} catch (IllegalArgumentException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be decrypted: illegal argument (" + e.getClass().toString() + ")");

		} catch (IOException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be decrypted: IO problem (" + e.getClass().toString() + ")");

		} catch (SignatureException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be decrypted: Signature problem (" + e.getClass().toString() + ")");
		}

		return new byte[0];
	}

	public byte[] decryptBlowfish(byte[] encryptedBytes, PUK otherUserPuK) {

		try {

			return this.driver.decryptBlowfish(encryptedBytes, RSAKeyPairProcessor.getPublicKeyFromBytes(otherUserPuK));

		} catch (InvalidKeyException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be decrypted: invalid private key (" + e.getClass().toString() + ")");

		} catch (NoSuchAlgorithmException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be decrypted: algorithm not supported (" + e.getClass().toString() + ")");

		} catch (NoSuchPaddingException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be decrypted: padding is not supported (" + e.getClass().toString() + ")");

		} catch (IllegalBlockSizeException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be decrypted: block size is illegal (" + e.getClass().toString() + ")");

		} catch (BadPaddingException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be decrypted: bad padding (" + e.getClass().toString() + ")");

		} catch (IllegalStateException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be decrypted: illegal state (" + e.getClass().toString() + ")");

		} catch (IllegalArgumentException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be decrypted: illegal argument (" + e.getClass().toString() + ")");

		} catch (IOException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be decrypted: IO problem (" + e.getClass().toString() + ")");

		} catch (SignatureException e) {

			Logg3r.log("CTK EmbeddedApi - Message cannot be encrypted: Signature problem (" + e.getClass().toString() + ")");
		}

		return new byte[0];
	}

	public String[] decryptBlowfish(String text) {

		try {
			return this.driver.decryptBlowfish(text, this.loadedOtherUserPuk);
		}

		catch (InvalidKeyException e) {

			Logg3r.log("CTK (Embedded) - Data cannot be decrypted: invalid private key (" + e.getClass().toString() + ")");

		} catch (NoSuchAlgorithmException e) {

			Logg3r.log("CTK (Embedded) - Data cannot be decrypted: algorithm not supported (" + e.getClass().toString() + ")");

		} catch (NoSuchPaddingException e) {

			Logg3r.log("CTK (Embedded) - Data cannot be decrypted: padding is not supported (" + e.getClass().toString() + ")");

		} catch (IllegalBlockSizeException e) {

			Logg3r.log("CTK (Embedded) - Data cannot be decrypted: block size is illegal (" + e.getClass().toString() + ")");

		} catch (BadPaddingException e) {

			Logg3r.log("CTK (Embedded) - Data cannot be decrypted: bad padding (" + e.getClass().toString() + ")");

		} catch (IllegalStateException e) {

			Logg3r.log("CTK (Embedded) - Data cannot be decrypted: illegal state (" + e.getClass().toString() + ")");

		} catch (IllegalArgumentException e) {

			Logg3r.log("CTK (Embedded) - Data cannot be decrypted: illegal argument (" + e.getClass().toString() + ")");

		} catch (IOException e) {

			Logg3r.log("CTK (Embedded) - Data cannot be decrypted: IO problem (" + e.getClass().toString() + ")");

		} catch (SignatureException e) {

			Logg3r.log("CTK (Embedded) - Data cannot be encrypted: Signature problem (" + e.getClass().toString() + ")");
		}

		catch (Exception e) {

			Logg3r.log("CTK (Embedded) - Data cannot be encrypted: Signature problem (" + e.getClass().toString() + ")");
		}

		// If we get to this point, the file might have been only partially de-crypted
		new File(text.substring(0, text.lastIndexOf(EXT))).delete();

		return new String[0];
	}

	public String[] encryptBlowfish(String text) {

		try {
			return this.driver.encryptBlowfish(text, this.loadedOtherUserPuk);
		}

		catch (InvalidKeyException e) {

			Logg3r.log("CTK (Embedded) - Data cannot be encrypted: invalid private key (" + e.getClass().toString() + ")");

		} catch (NoSuchAlgorithmException e) {

			Logg3r.log("CTK (Embedded) - Data cannot be encrypted: algorithm not supported (" + e.getClass().toString() + ")");

		} catch (NoSuchPaddingException e) {

			Logg3r.log("CTK (Embedded) - Data cannot be encrypted: padding is not supported (" + e.getClass().toString() + ")");

		} catch (IllegalBlockSizeException e) {

			Logg3r.log("CTK (Embedded) - Data cannot be encrypted: block size is illegal (" + e.getClass().toString() + ")");

		} catch (BadPaddingException e) {

			Logg3r.log("CTK (Embedded) - Data cannot be encrypted: bad padding (" + e.getClass().toString() + ")");

		} catch (IllegalStateException e) {

			Logg3r.log("CTK (Embedded) - Data cannot be encrypted: illegal state (" + e.getClass().toString() + ")");

		} catch (IllegalArgumentException e) {

			Logg3r.log("CTK (Embedded) - Data cannot be encrypted: illegal argument (" + e.getClass().toString() + ")");

		} catch (IOException e) {

			Logg3r.log("CTK (Embedded) - Data cannot be encrypted: IO problem (" + e.getClass().toString() + ")");

		} catch (SignatureException e) {

			Logg3r.log("CTK (Embedded) - Data cannot be encrypted: Signature problem (" + e.getClass().toString() + ")");
		}

		catch (Exception e) {

			Logg3r.log("CTK (Embedded) - Data cannot be encrypted: Signature problem (" + e.getClass().toString() + ")");
		}

		// If we get to this point, the file might have been only partially encrypted
		new File(text + EXT).delete();
		return new String[0];

	}

}