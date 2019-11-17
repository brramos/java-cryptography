using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EncryptionTests
{
    [TestClass]
    public class AsymmetricTests
    {
        [TestMethod]
        public void GenerateRsaKeyPair()
        {
            AsymmetricAlgorithm rsa = new RSACryptoServiceProvider(2048);

            string encodedKey = rsa.ToXmlString(true);

            Assert.IsTrue(encodedKey.Contains("<Modulus>"));
            Assert.IsTrue(encodedKey.Contains("<Exponent>AQAB</Exponent>"));
            Assert.IsTrue(encodedKey.Contains("<D>"));
        }

        [TestMethod]
        public void SharePublicKey()
        {
            AsymmetricAlgorithm rsa = new RSACryptoServiceProvider(2048);

            string encodedKey = rsa.ToXmlString(false);

            Assert.IsTrue(encodedKey.Contains("<Modulus>"));
            Assert.IsTrue(encodedKey.Contains("<Exponent>AQAB</Exponent>"));
            Assert.IsFalse(encodedKey.Contains("<D>"));
        }

        [TestMethod]
        public void ExponentIsAlways65537()
        {
            byte[] exponent = Convert.FromBase64String("AQAB");

            Assert.AreEqual(exponent.Length, 3);

            long number = ((long)exponent[2] << 16) +
                ((long)exponent[1] << 8) +
                ((long)exponent[0]);

            Assert.AreEqual(number, 65537);
        }

        [TestMethod]
        public void EncryptSymmetricKey()
        {
            var rsa = new RSACryptoServiceProvider(2048);

            byte[] blob = rsa.ExportCspBlob(false);
            var publicKey = new RSACryptoServiceProvider();
            publicKey.ImportCspBlob(blob);

            var aes = new AesCryptoServiceProvider();
            aes.KeySize = 256;
            byte[] encryptedKey = publicKey.Encrypt(aes.Key, true);
            byte[] decryptedKey = rsa.Decrypt(encryptedKey, true);

            Assert.IsTrue(Enumerable.SequenceEqual(decryptedKey, aes.Key));
        }

        [TestMethod]
        public void SignMessage()
        {
            var rsa = new RSACryptoServiceProvider(2048);

            byte[] blob = rsa.ExportCspBlob(false);
            var publicKey = new RSACryptoServiceProvider();
            publicKey.ImportCspBlob(blob);

            string message = "Alice knows Bob's secret.";
            var memory = new MemoryStream();
            using (var writer = new StreamWriter(memory))
            {
                writer.Write(message);
            }

            var hashFunction = new SHA256CryptoServiceProvider();
            byte[] signature = rsa.SignData(memory.ToArray(), hashFunction);

            bool verified = publicKey.VerifyData(memory.ToArray(), hashFunction, signature);
            Assert.IsTrue(verified);
        }
    }
}
