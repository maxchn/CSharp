using System;
using System.IO;
using System.Security.Cryptography;

namespace AES_Example
{
    public class Rijndael
    {
        public static byte[] Encrypt(string sourceText, byte[] key, int keySize)
        {
            // If the arguments are empty then we generate the corresponding exception.
            if (string.IsNullOrEmpty(sourceText))
                throw new ArgumentNullException("sourceText");

            if (key == null)
                throw new ArgumentNullException("key");

            byte[] IV;
            byte[] tempData;
            
            try
            {
                // Create a Aes object.
                // Aes object used to encrypt the data.
                using (Aes aes = Aes.Create())
                {
                    // Set the size, in bits, of the secret key used by the symmetric algorithm.
                    aes.KeySize = keySize;
                    // Set the key
                    aes.Key = key;
                    // Generate the IV
                    aes.GenerateIV();

                    // Saving IV to use later.
                    IV = aes.IV;

                    // Create a encryptor to perform the stream transform.
                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    // Create the streams used for encryption.
                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                            {
                                //Write all data to the stream.
                                swEncrypt.Write(sourceText);
                            }
                        }

                        // We get a byte array with encrypted data.
                        tempData = msEncrypt.ToArray();
                    }
                }

                byte[] encryptedText = new byte[IV.Length + tempData.Length];
                Array.Copy(IV, 0, encryptedText, 0, IV.Length);
                Array.Copy(tempData, 0, encryptedText, IV.Length, tempData.Length);

                // Return the encrypted byte array from the memory stream.
                return encryptedText;
            }
            catch (Exception exception)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(exception.Message);
                Console.ForegroundColor = ConsoleColor.White;

                return null;
            }
        }

        public static string Decrypt(byte[] enryptedText, byte[] key, int keySize)
        {
            // If the arguments are empty then we generate the corresponding exception.
            if (enryptedText == null)
                throw new ArgumentNullException("enryptedText");

            if (key == null)
                throw new ArgumentNullException("key");

            // Decrypted string to return.
            string sourceText = String.Empty;

            try
            {
                // Create a Aes object with the specified key and IV.
                // Aes object used to encrypt the data.
                using (Aes aes = Aes.Create())
                {
                    // Set the size, in bits, of the secret key used by the symmetric algorithm.
                    aes.KeySize = keySize;
                    // Set the key
                    aes.Key = key;

                    byte[] iv = new byte[aes.BlockSize/8];
                    byte[] cipherText = new byte[enryptedText.Length - iv.Length];

                    Array.Copy(enryptedText, iv, iv.Length);
                    Array.Copy(enryptedText, iv.Length, cipherText, 0, cipherText.Length);

                    // Set the IV
                    aes.IV = iv;

                    // Create a decryptor to perform the stream transform.
                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    // Create the streams used for decryption.
                    using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                // Read the decrypted bytes from the decrypting stream 
                                // and place them in a string.
                                sourceText = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }

                // Return the decrypted string.
                return sourceText;
            }
            catch (Exception exception)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(exception.Message);
                Console.ForegroundColor = ConsoleColor.White;

                return null;
            }
        }

        public static byte[] GenerateKey(int keySize)
        {
            byte[] key = new byte[keySize / 8];

            try
            {
                // We use cryptographic Random Number Generator (RNG).
                using (RNGCryptoServiceProvider provider = new RNGCryptoServiceProvider())
                {
                    // Fill the specified byte array with a cryptographically strong random sequence of values.
                    provider.GetBytes(key);
                }
            }
            catch (Exception exception)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(exception.Message);
                Console.ForegroundColor = ConsoleColor.White;
            }

            return key;
        }
    }
}