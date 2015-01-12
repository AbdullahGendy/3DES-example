package com.polytech.security;

import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

public class SqueletonTripleDES {

	static public void main(String[] argv) {

		Provider prov = new org.bouncycastle.jce.provider.BouncyCastleProvider();
		Security.addProvider(prov);

		try {

			if (argv.length > 0) {

				// Create a TripleDES object
				SqueletonTripleDES the3DES = new SqueletonTripleDES();

				if (argv[0].compareTo("-ECB") == 0) {
					// ECB mode
					// encrypt ECB mode
					Vector Parameters = the3DES.encryptECB(new FileInputStream(
							new File(argv[1])), // clear text file
							new FileOutputStream(new File(argv[2])), // file
																		// encrypted
							"DES", // KeyGeneratorName
							"DES/ECB/NoPadding"); // CipherName
					// decrypt ECB mode
					the3DES.decryptECB(Parameters, // the 3 DES keys
							new FileInputStream(new File(argv[2])), // the
																	// encrypted
																	// file
							new FileOutputStream(new File(argv[3])), // the
																		// decrypted
																		// file
							"DES/ECB/NoPadding"); // CipherName
				} else if (argv[0].compareTo("-CBC") == 0) {
					// decryption
					// encrypt CBC mode
					Vector Parameters = the3DES.encryptCBC(new FileInputStream(
							new File(argv[1])), // clear text file
							new FileOutputStream(new File(argv[2])), // file
																		// encrypted
							"DES", // KeyGeneratorName
							"DES/CBC/NoPadding"); // CipherName
					// "DES/CBC/PKCS5Padding"); // CipherName
					// decrypt CBC mode
					the3DES.decryptCBC(Parameters, // the 3 DES keys
							new FileInputStream(new File(argv[2])), // the
																	// encrypted
																	// file
							new FileOutputStream(new File(argv[3])), // the
																		// decrypted
																		// file
							"DES/CBC/NoPadding"); // CipherName
					// "DES/CBC/PKCS5Padding"); // CipherName
				}

			}

			else {
				System.out
						.println("java TripleDES -EBC clearTextFile EncryptedFile DecryptedFile");
				System.out
						.println("java TripleDES -CBC clearTextFile EncryptedFile DecryptedFile");
			}
		} catch (Exception e) {
			e.printStackTrace();
			System.out
					.println("java TripleDES -EBC clearTextFile EncryptedFile DecryptedFile");
			System.out
					.println("java TripleDES -CBC clearTextFile EncryptedFile DecryptedFile");
		}
	}

	/**
	 * 3DES ECB Encryption
	 */
	private Vector encryptECB(FileInputStream in, FileOutputStream out,
			String KeyGeneratorInstanceName, String CipherInstanceName) {
		try {

			// GENERATE 3 DES KEYS AND STORE IT INTO 3 FILES
			KeyGenerator keyGen = KeyGenerator.getInstance(KeyGeneratorInstanceName);
			Vector<SecretKey> secretKeyVector = new Vector<SecretKey>();
			secretKeyVector.add(keyGen.generateKey());
			secretKeyVector.add(keyGen.generateKey());
			secretKeyVector.add(keyGen.generateKey());

			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR ENCRYPTION
			// WITH THE FIRST GENERATED DES KEY
			Cipher cipherDES1 = Cipher.getInstance(CipherInstanceName);
			cipherDES1.init(Cipher.ENCRYPT_MODE, secretKeyVector.get(0));

			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR DECRYPTION
			// WITH THE SECOND GENERATED DES KEY
			Cipher decipherDES2 = Cipher.getInstance(CipherInstanceName);
			decipherDES2.init(Cipher.DECRYPT_MODE, secretKeyVector.get(1));

			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR ENCRYPTION
			// WITH THE THIRD GENERATED DES KEY
			Cipher cipherDES3 = Cipher.getInstance(CipherInstanceName);
			cipherDES3.init(Cipher.ENCRYPT_MODE, secretKeyVector.get(2));

			// GET THE MESSAGE TO BE ENCRYPTED FROM IN
			// CIPHERING
			// CIPHER WITH THE FIRST KEY
			CipherInputStream cipherInputStream1 = new CipherInputStream(in, cipherDES1);
			
			// DECIPHER WITH THE SECOND KEY
			CipherInputStream cipherInputStream2 = new CipherInputStream(cipherInputStream1, decipherDES2);
			
			// CIPHER WITH THE THIRD KEY
			CipherInputStream cipherInputStream3 = new CipherInputStream(cipherInputStream2, cipherDES3);

			// write encrypted file
			// WRITE THE ENCRYPTED DATA IN OUT
			int b = cipherInputStream3.read();
			while (b != -1) {
				out.write(b);
				b = cipherInputStream3.read();
			}
			out.close();
			cipherInputStream1.close();
			cipherInputStream2.close();
			cipherInputStream3.close();
			
			// return the DES keys list generated
			return secretKeyVector;

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}

	}

	/**
	 * 3DES ECB Decryption
	 */
	private void decryptECB(Vector Parameters, FileInputStream in,
			FileOutputStream out, String CipherInstanceName) {
		try {

			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR DECRYPTION
			// WITH THE THIRD GENERATED DES KEY
			Cipher decipherDES1 = Cipher.getInstance(CipherInstanceName);
			decipherDES1.init(Cipher.DECRYPT_MODE, (SecretKey) Parameters.get(2));

			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR DECRYPTION
			// WITH THE SECOND GENERATED DES KEY
			Cipher cipherDES2 = Cipher.getInstance(CipherInstanceName);
			cipherDES2.init(Cipher.ENCRYPT_MODE, (SecretKey) Parameters.get(1));

			// CREATE A DES CIPHER OBJECT WITH DES/EBC/PKCS5PADDING FOR
			// ENCRYPTION
			// WITH CipherInstanceName
			// FOR ENCRYPTION
			// WITH THE FIRST GENERATED DES KEY
			Cipher decipherDES3 = Cipher.getInstance(CipherInstanceName);
			decipherDES3.init(Cipher.DECRYPT_MODE, (SecretKey) Parameters.get(0));
			// GET THE ENCRYPTED DATA FROM IN

			// DECIPHERING
			// DECIPHER WITH THE THIRD KEY
			CipherOutputStream cipherOutputStream1 = new CipherOutputStream(out, decipherDES3);
			// CIPHER WITH THE SECOND KEY
			CipherOutputStream cipherOutputStream2 = new CipherOutputStream(cipherOutputStream1, cipherDES2);
			// DECIPHER WITH THE FIRST KEY
			CipherOutputStream cipherOutputStream3 = new CipherOutputStream(cipherOutputStream2, decipherDES1);

			// WRITE THE DECRYPTED DATA IN OUT
			int b = in.read();
			while (b != -1) {
				cipherOutputStream3.write(b);
				b = in.read();
			}
			cipherOutputStream3.close();
			cipherOutputStream2.close();
			cipherOutputStream1.close();
			in.close();

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/**
	 * 3DES ECB Encryption
	 */
	private Vector encryptCBC(FileInputStream in, FileOutputStream out,
			String KeyGeneratorInstanceName, String CipherInstanceName) {
		try {

			// GENERATE 3 DES KEYS
			KeyGenerator keyGen = KeyGenerator.getInstance(KeyGeneratorInstanceName);
			Vector secretKeyVector = new Vector();
			secretKeyVector.add(keyGen.generateKey());
			secretKeyVector.add(new IvParameterSpec(new byte[8]));
			secretKeyVector.add(keyGen.generateKey());
			secretKeyVector.add(new IvParameterSpec(new byte[8]));
			secretKeyVector.add(keyGen.generateKey());
			secretKeyVector.add(new IvParameterSpec(new byte[8]));
			// GENERATE THE IV

			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR ENCRYPTION
			// WITH THE FIRST GENERATED DES KEY
			Cipher cipherDES1 = Cipher.getInstance(CipherInstanceName);
			cipherDES1.init(Cipher.ENCRYPT_MODE, (SecretKey) secretKeyVector.get(0),
					(IvParameterSpec) secretKeyVector.get(1));

			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR DECRYPTION
			// WITH THE SECOND GENERATED DES KEY
			Cipher decipherDES2 = Cipher.getInstance(CipherInstanceName);
			decipherDES2.init(Cipher.DECRYPT_MODE, (SecretKey) secretKeyVector.get(2),
					(IvParameterSpec) secretKeyVector.get(3));

			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR ENCRYPTION
			// WITH THE THIRD GENERATED DES KEY
			Cipher cipherDES3 = Cipher.getInstance(CipherInstanceName);
			cipherDES3.init(Cipher.ENCRYPT_MODE, (SecretKey) secretKeyVector.get(4),
					(IvParameterSpec) secretKeyVector.get(5));

			// GET THE DATA TO BE ENCRYPTED FROM IN

			// CIPHERING
			// CIPHER WITH THE FIRST KEY
			// DECIPHER WITH THE SECOND KEY
			// CIPHER WITH THE THIRD KEY
			CipherInputStream cipherInputStream1 = new CipherInputStream(in, cipherDES1);
			CipherInputStream cipherInputStream2 = new CipherInputStream(cipherInputStream1, decipherDES2);
			CipherInputStream cipherInputStream3 = new CipherInputStream(cipherInputStream2, cipherDES3);
			
			// WRITE THE ENCRYPTED DATA IN OUT
			int b = cipherInputStream3.read();
			while (b != -1) {
				out.write(b);
				b = cipherInputStream3.read();
			}
			// return the DES keys list generated
			return secretKeyVector;

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * 3DES ECB Decryption
	 */
	private void decryptCBC(Vector Parameters, FileInputStream in,
			FileOutputStream out, String CipherInstanceName) {
		try {

			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR DECRYPTION
			// WITH THE THIRD GENERATED DES KEY
			Cipher decipherDES1 = Cipher.getInstance(CipherInstanceName);
			decipherDES1.init(Cipher.DECRYPT_MODE, (SecretKey) Parameters.get(4),
					(IvParameterSpec) Parameters.get(5));

			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR DECRYPTION
			// WITH THE SECOND GENERATED DES KEY
			Cipher cipherDES2 = Cipher.getInstance(CipherInstanceName);
			cipherDES2.init(Cipher.ENCRYPT_MODE, (SecretKey) Parameters.get(2),
					(IvParameterSpec) Parameters.get(3));

			// CREATE A DES CIPHER OBJECT WITH DES/EBC/PKCS5PADDING FOR
			// ENCRYPTION
			// WITH CipherInstanceName
			// FOR ENCRYPTION
			// WITH THE FIRST GENERATED DES KEY
			Cipher decipherDES3 = Cipher.getInstance(CipherInstanceName);
			decipherDES3.init(Cipher.DECRYPT_MODE, (SecretKey) Parameters.get(0),
					(IvParameterSpec) Parameters.get(1));

			// GET ENCRYPTED DATA FROM IN

			// DECIPHERING

			// DECIPHER WITH THE THIRD KEY
			CipherOutputStream cipherOutputStream1 = new CipherOutputStream(out, decipherDES3);
			// CIPHER WITH THE SECOND KEY
			CipherOutputStream cipherOutputStream2 = new CipherOutputStream(cipherOutputStream1, cipherDES2);
			// DECIPHER WITH THE FIRST KEY
			CipherOutputStream cipherOutputStream3 = new CipherOutputStream(cipherOutputStream2, decipherDES1);

			// WRITE THE DECRYPTED DATA IN OUT
			int b = in.read();
			while (b != -1) {
				cipherOutputStream3.write(b);
				b = in.read();
			}
			cipherOutputStream3.close();
			cipherOutputStream2.close();
			cipherOutputStream1.close();
			in.close();

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}