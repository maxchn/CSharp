using System;

namespace AES_Example
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                string sourceText = "Lorem ipsum!";
                string password = "f5ds6fD7F5dr47f46d7s";

                Console.WriteLine($"Source text:\t{sourceText}");
                
                string encryptedText = Rijndael.Encrypt(sourceText, password);

                if (!string.IsNullOrEmpty(encryptedText))
                {
                    Console.WriteLine($"Encrypted text:\t{encryptedText}");
                }
                else
                {
                    throw new Exception("The encrypted text is null or empty!");
                }

                string decryptedText = Rijndael.Decrypt(encryptedText, password);

                if (!string.IsNullOrEmpty(decryptedText))
                {
                    Console.WriteLine($"Decrypted text:\t{decryptedText}");
                }
                else
                {
                    throw new Exception("The decrypted text is null or empty!");
                }
            }
            catch (Exception exception)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(exception.Message);
                Console.ForegroundColor = ConsoleColor.White;
            }

            Console.ReadKey();
        }
    }
}