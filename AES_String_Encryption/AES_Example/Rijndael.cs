using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AES_Example
{
    public class Rijndael
    {
        // The salt is used when creating the key.
        private static byte[] _salt = Encoding.UTF8.GetBytes("3AF7hDgzdep483Kaex82JGKyZ5j6hp");

        public static string Encrypt(string sourceText, string password)
        {
            // If the arguments are empty then we generate the corresponding exception.
            if (string.IsNullOrEmpty(sourceText))
            {
                throw new ArgumentNullException("sourceText");
            }

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException("password");
            }

            // Encrypted string to return.
            string encryptedText = string.Empty;

            // Create a RijndaelManaged object.
            // RijndaelManaged object used to encrypt the data.
            RijndaelManaged aes = new RijndaelManaged();
            // Set the size, in bits, of the secret key used by the symmetric algorithm.
            aes.KeySize = 256;
            // Set the block size, in bits, of the cryptographic operation.
            aes.BlockSize = 128;

            try
            {
                // Generate the key from the password and the salt
                // and indicates the number of iterations to generate the key.
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, _salt, 1024);
                aes.Key = key.GetBytes(aes.KeySize / 8);
                aes.IV = key.GetBytes(aes.BlockSize / 8);

                // Create a encryptor to perform the stream transform.
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    // Prepend the IV.
                    msEncrypt.Write(BitConverter.GetBytes(aes.IV.Length), 0, sizeof(int));
                    msEncrypt.Write(aes.IV, 0, aes.IV.Length);

                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(sourceText);
                        }
                    }
                    
                    // We get a string with encrypted data.
                    encryptedText = Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
            catch (Exception exception)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(exception.Message);
                Console.ForegroundColor = ConsoleColor.White;
            }
            finally
            {
                // Releases all resources used by the SymmetricAlgorithm class.
                aes.Clear();
            }

            // Return the encrypted string from the stream.
            return encryptedText;
        }

        public static string Decrypt(string encryptedText, string password)
        {
            // If the arguments are empty then we generate the corresponding exception.
            if (string.IsNullOrEmpty(encryptedText))
            {
                throw new ArgumentNullException("encryptedText");
            }

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException("password");
            }

            // Decrypted string to return.
            string sourceText = string.Empty;

            // Create a RijndaelManaged object.
            // RijndaelManaged object used to decrypt the data.
            RijndaelManaged aes = new RijndaelManaged();
            // Set the size, in bits, of the secret key used by the symmetric algorithm.
            aes.KeySize = 256;
            // Set the block size, in bits, of the cryptographic operation.
            aes.BlockSize = 128;

            try
            {
                // Generate the key from the password and the salt
                // and indicates the number of iterations to generate the key.
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, _salt, 1024);
                aes.Key = key.GetBytes(aes.KeySize / 8);

                // Create the streams used for decryption.
                byte[] bytes = Convert.FromBase64String(encryptedText);

                using (MemoryStream msDecrypt = new MemoryStream(bytes))
                {
                    // Get the initialization vector from the encrypted stream
                    aes.IV = ReadByteArray(msDecrypt);

                    // Create a decryptor to perform the stream transform.
                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Read all data to the stream.
                            sourceText = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(exception.Message);
                Console.ForegroundColor = ConsoleColor.White;
            }
            finally
            {
                // Releases all resources used by the SymmetricAlgorithm class.
                aes.Clear();
            }

            // Return the decrypted string from the stream.
            return sourceText;
        }

        private static byte[] ReadByteArray(Stream stream)
        {
            byte[] rawLength = new byte[sizeof(int)];
            if (stream.Read(rawLength, 0, rawLength.Length) != rawLength.Length)
            {
                throw new Exception("Stream did not contain properly formatted byte array");
            }

            byte[] buffer = new byte[BitConverter.ToInt32(rawLength, 0)];
            if (stream.Read(buffer, 0, buffer.Length) != buffer.Length)
            {
                throw new Exception("Did not read byte array properly");
            }

            return buffer;
        }
    }
}