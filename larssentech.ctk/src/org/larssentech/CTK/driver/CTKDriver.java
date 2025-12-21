// (c) 2015-2026 AVANZ.IO
// (c) 2008 Jeffrey J Cerasuolo

package org.larssentech.CTK.driver;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.larssentech.CTK.engine.BlowfishCryptoEngine;
import org.larssentech.CTK.engine.RSACryptoEngine;
import org.larssentech.CTK.rsa.RSAKeyPairInit;
import org.larssentech.CTK.rsa.RSAKeyPairProcessor;
import org.larssentech.CTK.settings.CTKSettings;
import org.larssentech.CTK.settings.RSAPathBundle;
import org.larssentech.lib.CTK.objects.PUK;
import org.larssentech.lib.basiclib.io.file.ReadBytesFromFile;
import org.larssentech.lib.basiclib.io.parser.XMLParser;
import org.larssentech.lib.log.Logg3r;

class CTKDriver implements CTKSettings {

	private boolean inited;
	private BlowfishCryptoEngine blowfishEngine;

	public BlowfishCryptoEngine getBlowfishEngine() { return this.blowfishEngine; }

	private PrivateKey ownPrK;
	private File log;

	CTKDriver(File log) {
		this.log = log;
		doInit();
	}

	void doInit() {

		if (!RSAKeyPairProcessor.rsaKeysExist()) try {

			this.init("-k");

		} catch (NoSuchAlgorithmException e) {

			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {

			e.printStackTrace();
		}

		this.inited = RSAKeyPairInit.init("", RSAPathBundle.getOwnPKPath(), RSAPathBundle.getOwnPUKPath(), RSAPathBundle.getOwnKeyPairPath());
		this.blowfishEngine = new BlowfishCryptoEngine();
		this.blowfishEngine.setLog(this.log);

		this.ownPrK = RSAKeyPairProcessor.getPrivateKeyFromBytes(ReadBytesFromFile.readBytesFromFile(RSAPathBundle.getOwnPKPath()));

		new RSAKeyPairProcessor();

	}

	boolean keysExist(String ownPKPath, String ownPUKPath) {

		return RSAKeyPairProcessor.rsaKeysExist();
	}

	boolean isInited() {

		return this.inited;
	}

	private void decryptBlowfish(byte[] encryptedBytes, ByteArrayOutputStream out, PublicKey otherUserPuK)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, IllegalStateException, IllegalArgumentException, SignatureException {

		InputStream in = new ByteArrayInputStream(encryptedBytes);

		int hSize = 128;
		byte[] encryptedSecretKey;

		// Read the 128 byte text header to find how many bytes the key is
		byte[] textHeader = new byte[hSize];

		in.read(textHeader);

		String keySizeString = XMLParser.parseValueForTag(new String(textHeader), "<secret_key_size>");

		// Read the rsa encrypted Blowfish secret key
		int keySize = Integer.parseInt(keySizeString);
		encryptedSecretKey = new byte[keySize];
		in.read(encryptedSecretKey);

		long contentLength = encryptedBytes.length - hSize - keySize;

		byte[] secKeyBytes = new RSACryptoEngine().decryptVerifyBytes(otherUserPuK, this.ownPrK, encryptedSecretKey);

		SecretKeySpec keySpec = new SecretKeySpec(secKeyBytes, "Blowfish");

		// Decrypt the Blowfish file (stream)
		this.blowfishEngine.setSecretKey(keySpec);

		this.blowfishEngine.cryptToStream(Cipher.DECRYPT_MODE, in, out, contentLength);

	}

	boolean init(String param) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

		return RSAKeyPairInit.init(param, RSAPathBundle.getOwnPKPath(), RSAPathBundle.getOwnPUKPath(), RSAPathBundle.getOwnKeyPairPath());
	}

	byte[] encryptSignBytes(byte[] plainTextBytes, PublicKey otherUserPuK) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, IllegalStateException, SignatureException {

		return new RSACryptoEngine().encryptSignBytes(otherUserPuK, this.ownPrK, plainTextBytes);
	}

	byte[] decryptVerifyBytes(byte[] cipherTextBytes, PublicKey otherUserPuK) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, IllegalStateException, IllegalArgumentException, SignatureException {

		return new RSACryptoEngine().decryptVerifyBytes(

				otherUserPuK, this.ownPrK, cipherTextBytes);
	}

	PublicKey receivePublicKeyForUser(PUK puk) {

		return RSAKeyPairProcessor.receivePublicKeyForUser(puk);
	}

	String[] encryptBlowfish(String filePath, PublicKey otherUserPuK)
			throws BadPaddingException, IllegalBlockSizeException, IllegalStateException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, IllegalStateException, SignatureException {

		this.encryptBlowfish(new FileInputStream(filePath), new FileOutputStream(filePath + EXT, false), new File(filePath).length(), otherUserPuK);

		return new String[] { filePath + EXT, ENCMSG };
	}

	public boolean encryptBlowfish(InputStream in, OutputStream out, long usedLength, PublicKey otherUserPuK)
			throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, IllegalStateException, SignatureException {

		// Get the Blowfish secret key and encrypt it with RSA
		SecretKey sKey = this.blowfishEngine.generateSecretKey();
		byte[] rsaEncBloSecKey = new RSACryptoEngine().encryptSignBytes(otherUserPuK, this.ownPrK, sKey.getEncoded());

		// Create the header (used at decryption time) and pad to 128 bytes
		byte[] header = new byte[128];
		String keySizeHeader = "<secret_key_size>" + rsaEncBloSecKey.length + "</secret_key_size>";

		keySizeHeader = padHeader(keySizeHeader, " ");

		header = keySizeHeader.getBytes();

		// Store the header and the secret key in the stream first
		out.write(header);
		out.write(rsaEncBloSecKey);
		out.flush();

		Logg3r.log2(this.log, "Starting Crypto Engine");

		// Do the main encryption work
		sKey = this.blowfishEngine.cryptToStream(Cipher.ENCRYPT_MODE, in, out, usedLength);

		return null != sKey;
	}

	private String padHeader(String keySizeHeader, String pad) {

		while (keySizeHeader.length() < 128) {
			keySizeHeader += pad;
		}

		return keySizeHeader;
	}

	byte[] encryptBlowfish(byte[] inB, long bytesDone, PublicKey otherUserPuK) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, IllegalStateException, SignatureException {

		InputStream in = new ByteArrayInputStream(inB);
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		this.encryptBlowfish(in, out, bytesDone, otherUserPuK);

		return out.toByteArray();
	}

	byte[] decryptBlowfish(byte[] encryptedBytes, PublicKey otherUserPuK) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IllegalStateException, IllegalArgumentException, IOException, SignatureException {

		ByteArrayOutputStream out = new ByteArrayOutputStream();

		this.decryptBlowfish(encryptedBytes, out, otherUserPuK);

		return out.toByteArray();
	}

	String[] decryptBlowfish(String filePath, PublicKey otherUserPuK) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, IllegalStateException, IllegalArgumentException, SignatureException {

		int hSize = 128;
		FileInputStream in = null;
		byte[] encryptedSecretKey;
		boolean success = false;

		in = new FileInputStream(filePath);

		// Read the 128 byte text header to find how many bytes the key is
		byte[] textHeader = new byte[hSize];
		in.read(textHeader);
		new XMLParser();
		String keySizeString = XMLParser.parseValueForTag(new String(textHeader), "<secret_key_size>");

		// Read the rsa encrypted Blowfish secret key
		int keySize = Integer.parseInt(keySizeString);
		encryptedSecretKey = new byte[keySize];
		in.read(encryptedSecretKey);

		// Decrypt it and create Blowfish key
		byte[] secKeyBytes = new RSACryptoEngine().decryptVerifyBytes(otherUserPuK, this.ownPrK, encryptedSecretKey);
		SecretKeySpec keySpec = new SecretKeySpec(secKeyBytes, "Blowfish");

		// Decrypt the Blowfish file (stream)
		this.blowfishEngine.setSecretKey(keySpec);
		success = false;

		FileOutputStream out = new FileOutputStream(filePath.substring(0, filePath.lastIndexOf(EXT)), false);
		long contentLength = (long) new File(filePath).length() - hSize - keySize;

		Logg3r.log2(this.log, "Encrypted file details:");
		Logg3r.log2(this.log, "  File length: " + new File(filePath).length());
		Logg3r.log2(this.log, "  Header length: " + hSize);
		Logg3r.log2(this.log, "  Key length: " + keySize);
		Logg3r.log2(this.log, "  Encrypted length: " + contentLength);

		success = this.blowfishEngine.cryptToStream(Cipher.DECRYPT_MODE, in, out, contentLength) != null;

		// In case we fail to write the file to the filesystem
		String plainTextFileName = filePath.substring(0, filePath.lastIndexOf(EXT));
		success = new File(plainTextFileName).exists();

		Logg3r.log2(this.log, "Plain text (decrypted) file details:");
		Logg3r.log2(this.log, "  File path: " + plainTextFileName);
		Logg3r.log2(this.log, "  File length: " + new File(plainTextFileName).length());

		if (success) return new String[] { filePath.substring(0, filePath.lastIndexOf(EXT)) };
		else return new String[0];
	}
}