using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EncryptionTests
{
    [TestClass]
    public class SymmetricTests
    {
        [TestMethod]
        public void GenerateARandomAESKey()
        {
            SymmetricAlgorithm aes = new AesCryptoServiceProvider();
            aes.KeySize = 256;

            Assert.AreEqual(aes.Key.Length, 32); // 256 / 8
            Assert.AreEqual(aes.IV.Length, 16); // 128 / 8
        }

		[TestMethod]
		public void EncryptAMessageWithAES()
		{
            string message = "Alice knows Bob's secret.";
            SymmetricAlgorithm aes = new AesCryptoServiceProvider();
            aes.KeySize = 256;

            byte[] key = aes.Key;
            byte[] iv = aes.IV;

            byte[] encryptedMessage = EncryptWithAes(message, aes);

            string decryptedMessage = DecryptMessageWithAes(key, iv, encryptedMessage);

            Assert.AreEqual(decryptedMessage, message);
        }

        [TestMethod]
        public void UsingTheSameInitializationVector()
        {
            string message1 = "Alice knows Bob's secret.";
            string message2 = "Alice knows Bob's favorite color.";
            SymmetricAlgorithm aes = new AesCryptoServiceProvider();
            aes.KeySize = 256;

            byte[] encryptedMessage1 = EncryptWithAes(message1, aes);
            byte[] encryptedMessage2 = EncryptWithAes(message2, aes);

            Assert.IsTrue(Enumerable.SequenceEqual(encryptedMessage1.Take(16), encryptedMessage2.Take(16)));
        }

        private static byte[] EncryptWithAes(string message, SymmetricAlgorithm aes)
        {
            MemoryStream memoryStream = new MemoryStream();

            var cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
            using (var writer = new StreamWriter(cryptoStream))
            {
                writer.Write(message);
            }
            return memoryStream.ToArray();
        }

        private static string DecryptMessageWithAes(byte[] key, byte[] iv, byte[] encryptedMessage)
        {
            SymmetricAlgorithm provider = new AesCryptoServiceProvider();
            MemoryStream memoryStream = new MemoryStream(encryptedMessage);

            var cryptoStream = new CryptoStream(memoryStream, provider.CreateDecryptor(key, iv), CryptoStreamMode.Read);
            using (var reader = new StreamReader(cryptoStream))
            {
                return reader.ReadToEnd();
            }
        }
    }
}
