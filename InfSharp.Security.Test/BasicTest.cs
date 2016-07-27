using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security;

namespace InfSharp.Security.Test
{
    [TestClass]
    public class BasicTest
    {
        [TestMethod]
        public void EncryptDecrpytTest()
        {
            string plaintText = "PLAIN?TEXT";
            AesHmac aeshmac = new AesHmac("Infxios?1245");

            string encryptedText = aeshmac.Encrypt(plaintText);
            string decrpytedText = aeshmac.Decrypt(encryptedText);

            Assert.AreEqual<string>(plaintText, decrpytedText);
        }

        [TestMethod]
        public void DisposalTest()
        {
            string plaintText = "PLAIN?TEXT";
            AesHmac aeshmac = new AesHmac("Infxios?1245");
            string encryptedText = aeshmac.Encrypt(plaintText);
            aeshmac.Dispose();

            bool result = false;

            try
            {
                aeshmac.Decrypt(encryptedText);
            }
            catch (Exception)
            {
                result = true;
            }

            Assert.IsTrue(result);
        }

        [TestMethod]
        public void XmlTest()
        {
            string plaintText = "PLAIN?TEXT";
            AesHmac aeshmac = new AesHmac("Infxios?1245");
            string encryptedText = aeshmac.Encrypt(plaintText);
            string decryptedText = aeshmac.Decrypt(encryptedText);
            SecurityElement securityElement = aeshmac.ToXml();

            AesHmac xmlAesHmac = new AesHmac();
            xmlAesHmac.FromXml(securityElement);
            string xmlEncryptedText = xmlAesHmac.Encrypt(plaintText);
            string xmlDecryptedText = aeshmac.Decrypt(xmlEncryptedText);
            Assert.AreEqual<string>(decryptedText, xmlDecryptedText);
        }
    }
}
