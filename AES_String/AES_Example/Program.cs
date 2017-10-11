using System;

namespace AES_Example
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                string sourceText = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";
                const int keySize = 256;
                byte[] key = Rijndael.GenerateKey(keySize);

                byte[] encryptedTextBytes = Rijndael.Encrypt(sourceText, key, keySize);
                string encryptText = Convert.ToBase64String(encryptedTextBytes);

                string decryptedText = Rijndael.Decrypt(encryptedTextBytes, key, keySize);

                Console.WriteLine($"Source text:\t{sourceText}");
                Console.WriteLine($"Encrypted text:\t{encryptText}");
                Console.WriteLine($"Decrypted text:\t{decryptedText}");

                Console.ReadLine();
            }
            catch (Exception exception)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(exception.Message);
                Console.ForegroundColor = ConsoleColor.White;
            }
        }
    }
}