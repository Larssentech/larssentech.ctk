// (c) 2005-2022 AVANZ.IO
// (c) 2008 Jeffrey J Cerasuolo

package org.larssentech.CTK.driver;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.EncoderException;
import org.larssentech.CTK.LOG.CTKLogger;
import org.larssentech.CTK.rsa.RSAKeyPairProcessor;
import org.larssentech.CTK.settings.CTKSettings;
import org.larssentech.CTK.settings.RSAPathBundle;
import org.larssentech.lib.CTK.objects.PUK;
import org.larssentech.lib.basiclib.console.Out;
import org.larssentech.lib.basiclib.io.Base64ObjectCoder;

public class EmbeddedApi {

	public EmbeddedApi() {

		new CTKDriver();
	}

	public static byte[] encryptSignMessage(byte[] plainTextBytes, PUK puk) {

		try {

			// Everytime we call the methids, first thing is to tell the API
			// what the other user PUK is
			;

			/**
			 * Now we can encrypt with their puk, sign with our prik and encode
			 * the result into Base64 ready to send.
			 */
			byte[] b = CTKDriver.encryptSignBytes(plainTextBytes, CTKDriver.receivePublicKeyForUser(puk));

			return Base64ObjectCoder.encodeBytes(b);

		}
		catch (InvalidKeyException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be encrypted: invalid private key (" + e.getClass().toString() + ") returning cyphertext as plaintext (IllegalArgumentException)");

		}
		catch (NoSuchAlgorithmException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be encrypted: algorithm not supported (" + e.getClass().toString() + ") returning cyphertext as plaintext (IllegalArgumentException)");

		}
		catch (NoSuchPaddingException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be encrypted: padding is not supported (" + e.getClass().toString() + ") returning cyphertext as plaintext (IllegalArgumentException)");

		}
		catch (IllegalBlockSizeException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be encrypted: block size is illegal (" + e.getClass().toString() + ") returning cyphertext as plaintext (IllegalArgumentException)");

		}
		catch (BadPaddingException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be encrypted: bad padding (" + e.getClass().toString() + ") returning cyphertext as plaintext (IllegalArgumentException)");

		}
		catch (IllegalStateException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be encrypted: illegal state (" + e.getClass().toString() + ") returning cyphertext as plaintext (IllegalArgumentException)");

		}
		catch (IllegalArgumentException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be encrypted: illegal argument (" + e.getClass().toString() + ") returning cyphertext as plaintext (IllegalArgumentException)");

		}
		catch (IOException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be encrypted: IO problem (" + e.getClass().toString() + ") returning cyphertext as plaintext (IllegalArgumentException)");

		}
		catch (EncoderException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be encrypted: encoder problem (" + e.getClass().toString() + ") returning cyphertext as plaintext (IllegalArgumentException)");

		}
		catch (SignatureException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be signed: signature problem (" + e.getClass().toString() + ") returning cyphertext as plaintext (IllegalArgumentException)");
		}

		return plainTextBytes;
	}

	public static byte[] decryptVerifyMessage(byte[] cipherText, PUK puk) {

		try {

			/**
			 * Now we can decript with our prik, verify with their puk and
			 * decode the result from Base64 to string ready to read.
			 */
			return CTKDriver.decryptVerifyBytes(Base64ObjectCoder.decodeBytes(cipherText), CTKDriver.receivePublicKeyForUser(puk));

		}
		catch (InvalidKeyException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be decrypted: invalid private key (" + e.getClass().toString() + ") returning cyphertext as plaintext");

		}
		catch (NoSuchAlgorithmException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be decrypted: algorithm not supported (" + e.getClass().toString() + ") returning cyphertext as plaintext");

		}
		catch (NoSuchPaddingException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be decrypted: padding is not supported (" + e.getClass().toString() + ") returning cyphertext as plaintext");

		}
		catch (IllegalBlockSizeException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be decrypted: block size is illegal (" + e.getClass().toString() + ") returning cyphertext as plaintext");

		}
		catch (BadPaddingException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be decrypted: bad padding (" + e.getClass().toString() + ") returning cyphertext as plaintext");

		}
		catch (IllegalStateException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be decrypted: illegal state (" + e.getClass().toString() + ") returning cyphertext as plaintext");

		}
		catch (IllegalArgumentException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be decrypted: illegal argument (" + e.getClass().toString() + ") returning cyphertext as plaintext");

		}
		catch (IOException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be decrypted: IO problem (" + e.getClass().toString() + ") returning cyphertext as plaintext");

		}
		catch (DecoderException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be Base64 decoded: Base64 problem (" + e.getClass().toString() + ") returning cyphertext as plaintext");

		}
		catch (SignatureException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be verified: signature problem (" + e.getClass().toString() + ") returning cyphertext as plaintext");
		}

		return cipherText;
	}

	public static boolean init(boolean verbose) {

		CTKLogger.logThis(CTKSettings.VERSION);

		boolean rsaSupported = true;
		boolean rsaKeySupported = true;
		boolean keysExist = true;
		boolean nxCTKInited = true;

		// Initialize it. If keys not found, init requesting new pair & tell
		// user
		boolean toolkitInited = false;

		CTKDriver.doInit();

		toolkitInited = CTKDriver.isInited();

		Out.pl(new Date() + " >> " + "EmbeddedApi:" + "\t");
		Out.pl(new Date() + " >> " + "CTK Initialisation: toolkitInited=" + toolkitInited);

		// If no exception was thrown but keys were not found this means the
		// system is good but we are new so request creation of keys
		if (!toolkitInited) {

			Out.pl("RSA_KEY_PAIR_NOT_FOUND");
			Out.pl("Requesting the creation of a new KeyPair.");
			Out.pl("This may take a minute, please wait...");

			try {

				toolkitInited = CTKDriver.init("-k");

			}
			catch (Exception e) {

				nxCTKInited = false;
			}

		}
		else

			if (!CTKDriver.keysExist(RSAPathBundle.getOwnPKPath(), RSAPathBundle.getOwnPUKPath())) {

				keysExist = false;
			}

		if (!rsaSupported || !rsaKeySupported || !keysExist || !nxCTKInited) {

			Out.pl("There seems to be a problem with your system. This could be:");
			Out.pl("- RSA cipher not supported (get Java 1.5 or better)");
			Out.pl("- RSA key size not supported (get Java 1.5 or better)");
			Out.pl("- Your RSA key pair cannot be found (close and reopen)");
			Out.pl("- Filesystem is read only");
			Out.pl("- Something else that can't be resolved");

			// System.exit(-1);
		}
		return rsaSupported && rsaKeySupported && keysExist && nxCTKInited;

	}

	public static byte[] encryptBlowfish(byte[] plainBytes, long bytesDone, PUK otherUserPuK) {

		try {
			return CTKDriver.encryptBlowfish(plainBytes, bytesDone, RSAKeyPairProcessor.getPublicKeyFromBytes(otherUserPuK));

		}
		catch (InvalidKeyException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be decrypted: invalid private key (" + e.getClass().toString() + ")");

		}
		catch (NoSuchAlgorithmException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be decrypted: algorithm not supported (" + e.getClass().toString() + ")");

		}
		catch (NoSuchPaddingException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be decrypted: padding is not supported (" + e.getClass().toString() + ")");

		}
		catch (IllegalBlockSizeException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be decrypted: block size is illegal (" + e.getClass().toString() + ")");

		}
		catch (BadPaddingException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be decrypted: bad padding (" + e.getClass().toString() + ")");

		}
		catch (IllegalStateException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be decrypted: illegal state (" + e.getClass().toString() + ")");

		}
		catch (IllegalArgumentException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be decrypted: illegal argument (" + e.getClass().toString() + ")");

		}
		catch (IOException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be decrypted: IO problem (" + e.getClass().toString() + ")");

		}
		catch (SignatureException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be decrypted: Signature problem (" + e.getClass().toString() + ")");
		}

		return new byte[0];
	}

	public static byte[] decryptBlowfish(byte[] encryptedBytes, PUK otherUserPuK) {

		try {

			return CTKDriver.decryptBlowfish(encryptedBytes, RSAKeyPairProcessor.getPublicKeyFromBytes(otherUserPuK));

		}
		catch (InvalidKeyException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be decrypted: invalid private key (" + e.getClass().toString() + ")");

		}
		catch (NoSuchAlgorithmException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be decrypted: algorithm not supported (" + e.getClass().toString() + ")");

		}
		catch (NoSuchPaddingException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be decrypted: padding is not supported (" + e.getClass().toString() + ")");

		}
		catch (IllegalBlockSizeException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be decrypted: block size is illegal (" + e.getClass().toString() + ")");

		}
		catch (BadPaddingException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be decrypted: bad padding (" + e.getClass().toString() + ")");

		}
		catch (IllegalStateException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be decrypted: illegal state (" + e.getClass().toString() + ")");

		}
		catch (IllegalArgumentException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be decrypted: illegal argument (" + e.getClass().toString() + ")");

		}
		catch (IOException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be decrypted: IO problem (" + e.getClass().toString() + ")");

		}
		catch (SignatureException e) {

			Out.pl("CTK EmbeddedApi - Message cannot be encrypted: Signature problem (" + e.getClass().toString() + ")");
		}

		return new byte[0];
	}
}