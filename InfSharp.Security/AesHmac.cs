using System;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace InfSharp.Security
{
    public sealed class AesHmac : IDisposable, IEquatable<AesHmac>,ISecurityEncodable
    {

        private SHA256Cng sha = null;
        private string hashedSecret;
        private string authKeyInitiator;
        private bool isDisposed = false;

        private const int DENOMINATOR = 8;
        private const int BLOCK_BIT_SIZE = 128;
        private const int KEY_BIT_SIZE = 256;
        private const int MIN_PASS_LEN = 12;
        private const int DEFAULT_ITERATION = 1000;
        private const int DEFAULT_STATIC_ITERATION = 100;
        private const int SALT_BIT_SIZE = 64;
        private const string OBJ_DISPOSED_MESSAGE = "Object is disposed.";

        private int iterations;

        #region Constructors

        public AesHmac()
        {
            iterations = DEFAULT_ITERATION;
        }

        public AesHmac(int iterations)
        {
            this.iterations = iterations;
        }

        public AesHmac(string secretKey)
        {
            Initialize(secretKey);
            iterations = DEFAULT_ITERATION;
        }

        public AesHmac(string secretKey, int iterations)
        {
            Initialize(secretKey);
            this.iterations = iterations;
        }

        #endregion Constructors


        #region Encrypt
        public static string EncryptString(string secretMessage, string password)
        {
            using (AesHmac aes = new AesHmac(password, DEFAULT_STATIC_ITERATION))
            {
                return aes.Encrypt(secretMessage);
            }
        }

        public string Encrypt(string secretMessage)
        {
            if (isDisposed)
            {
                throw new ObjectDisposedException(OBJ_DISPOSED_MESSAGE);
            }

            if (secretMessage == null || secretMessage.Length == 0)
            {
                throw new ArgumentNullException("Secret message can not be null or empty");
            }

            byte[] secretData = Encoding.UTF8.GetBytes(secretMessage);
            byte[] cipheredMessage = Encrypt(secretData);
            return Convert.ToBase64String(cipheredMessage);
        }

        public byte[] Encrypt(byte[] secretData)
        {
            if (isDisposed)
            {
                throw new ObjectDisposedException(OBJ_DISPOSED_MESSAGE);
            }

            if (secretData == null || secretData.Length == 0)
            {
                throw new ArgumentNullException("Secret message can not be null or empty");
            }


            return Encrypt(secretData, hashedSecret, authKeyInitiator, iterations);
        }

        private static byte[] Encrypt(byte[] secretData, string hashedSecret, string authKeyInitiator, int iterations)
        {
            int totalDataIndex = 0;
            byte[] extraData = new byte[(SALT_BIT_SIZE / DENOMINATOR) * 2], secretKey, authKey;

            using (Rfc2898DeriveBytes byteDeriver = new Rfc2898DeriveBytes(hashedSecret, SALT_BIT_SIZE / DENOMINATOR, iterations))
            {
                byte[] salt = byteDeriver.Salt;
                secretKey = byteDeriver.GetBytes(KEY_BIT_SIZE / DENOMINATOR);
                Array.Copy(salt, 0, extraData, totalDataIndex, salt.Length);
                totalDataIndex += salt.Length;
            }

            using (Rfc2898DeriveBytes byteDeriver = new Rfc2898DeriveBytes(authKeyInitiator, SALT_BIT_SIZE / DENOMINATOR, iterations))
            {
                byte[] salt = byteDeriver.Salt;
                authKey = byteDeriver.GetBytes(KEY_BIT_SIZE / DENOMINATOR);
                Array.Copy(salt, 0, extraData, totalDataIndex, salt.Length);
            }

            return Encrypt(secretData, secretKey, authKey, extraData);
        }

        private static byte[] Encrypt(byte[] secretMessage, byte[] secretKey, byte[] authKey, byte[] extraData)
        {
            byte[] cipherText;
            byte[] iv;

            using (AesManaged managedAes = new AesManaged()
            {
                KeySize = KEY_BIT_SIZE,
                BlockSize = BLOCK_BIT_SIZE,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            })
            {
                managedAes.GenerateIV();
                iv = managedAes.IV;

                using (var encryptor = managedAes.CreateEncryptor(secretKey, iv))
                using (var cipherStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(cipherStream, encryptor, CryptoStreamMode.Write))
                    using (var binaryWriter = new BinaryWriter(cryptoStream))
                    {
                        binaryWriter.Write(secretMessage);
                    }

                    cipherText = cipherStream.ToArray();
                }


                using (var hmac = new HMACSHA256(authKey))
                using (var encryptedStream = new MemoryStream())
                {
                    using (var binaryWriter = new BinaryWriter(encryptedStream))
                    {
                        binaryWriter.Write(extraData);
                        binaryWriter.Write(iv);
                        binaryWriter.Write(cipherText);
                        binaryWriter.Flush();

                        var tag = hmac.ComputeHash(encryptedStream.ToArray());

                        binaryWriter.Write(tag);
                    }

                    return encryptedStream.ToArray();
                }

            }
        }
        #endregion

        #region Decrypt
        public static string DecryptString(string cipheredMessage, string password)
        {
            using (AesHmac aes = new AesHmac(password, DEFAULT_STATIC_ITERATION))
            {
                return aes.Decrypt(cipheredMessage);
            }
        }

        public string Decrypt(string cipheredBase64String)
        {
            if (isDisposed)
            {
                throw new ObjectDisposedException(OBJ_DISPOSED_MESSAGE);
            }

            if (cipheredBase64String == null || cipheredBase64String.Length == 0)
            {
                throw new ArgumentNullException("Ciphered message can not be null or empty");
            }

            byte[] cipheredMessage = Convert.FromBase64String(cipheredBase64String);
            byte[] plainBytes = Decrypt(cipheredMessage);
            return SecurityUtility.Encoding.GetString(plainBytes);
        }

        public byte[] Decrypt(byte[] cipheredData)
        {
            if (isDisposed)
            {
                throw new ObjectDisposedException(OBJ_DISPOSED_MESSAGE);
            }

            if (cipheredData == null || cipheredData.Length == 0)
            {
                throw new ArgumentNullException("Ciphered data can not be null or empty");
            }

            return Decrypt(cipheredData, hashedSecret, authKeyInitiator, iterations);
        }

        private static byte[] Decrypt(byte[] cipheredData, string hashedSecret, string authKeyInitiator, int iterations)
        {
            byte[] secretSalt = new byte[SALT_BIT_SIZE / DENOMINATOR];
            byte[] authSalt = new byte[SALT_BIT_SIZE / DENOMINATOR];

            Array.Copy(cipheredData, 0, secretSalt, 0, secretSalt.Length);
            Array.Copy(cipheredData, secretSalt.Length, authSalt, 0, authSalt.Length);

            byte[] secretKey;
            byte[] authKey;

            using (Rfc2898DeriveBytes byteDerivetor = new Rfc2898DeriveBytes(hashedSecret, secretSalt, iterations))
            {
                secretKey = byteDerivetor.GetBytes(KEY_BIT_SIZE / DENOMINATOR);
            }

            using (Rfc2898DeriveBytes byteDerivetor = new Rfc2898DeriveBytes(authKeyInitiator, authSalt, iterations))
            {
                authKey = byteDerivetor.GetBytes(KEY_BIT_SIZE / DENOMINATOR);
            }

            return Decrypt(cipheredData, secretKey, authKey, secretSalt.Concat(authSalt).ToArray());
        }

        private static byte[] Decrypt(byte[] cipheredMessage, byte[] secretKey, byte[] authKey, byte[] nonSecretMessage)
        {
            byte[] sentExtra, calcExtra;

            using (var hmac = new HMACSHA256(authKey))
            {
                sentExtra = new byte[hmac.HashSize / DENOMINATOR];
                calcExtra = hmac.ComputeHash(cipheredMessage, 0, cipheredMessage.Length - sentExtra.Length);
            }
            var ivLength = (BLOCK_BIT_SIZE / DENOMINATOR);

            if (cipheredMessage.Length < sentExtra.Length + ivLength + nonSecretMessage.Length)
            {
                throw new SecurityException("Ciphered message is invalid");
            }

            var nonSecretFromMessage = new byte[nonSecretMessage.Length];

            Array.Copy(cipheredMessage, cipheredMessage.Length - sentExtra.Length, sentExtra, 0, sentExtra.Length);
            Array.Copy(cipheredMessage, nonSecretFromMessage, nonSecretFromMessage.Length);

            int comparison = 0;
            for (int i = 0; i < sentExtra.Length; i++)
            {
                comparison |= sentExtra[i] ^ calcExtra[i];
            }

            for (int i = 0; i < nonSecretFromMessage.Length; i++)
            {
                comparison |= nonSecretFromMessage[i] ^ nonSecretMessage[i];
            }

            if (comparison != 0)
            {
                throw new SecurityException("Ciphered message is invalid");
            }

            using (AesManaged aesManaged = new AesManaged
            {
                KeySize = KEY_BIT_SIZE,
                BlockSize = BLOCK_BIT_SIZE,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            })
            {
                var iv = new byte[ivLength];
                Array.Copy(cipheredMessage, nonSecretMessage.Length, iv, 0, iv.Length);

                using (var decrypter = aesManaged.CreateDecryptor(secretKey, iv))
                using (var plainTextStream = new MemoryStream())
                {
                    using (var decrypterStream = new CryptoStream(plainTextStream, decrypter, CryptoStreamMode.Write))
                    using (var binaryWriter = new BinaryWriter(decrypterStream))
                    {
                        binaryWriter.Write(cipheredMessage, nonSecretMessage.Length + iv.Length, cipheredMessage.Length - nonSecretMessage.Length - iv.Length - sentExtra.Length);
                    }

                    return plainTextStream.ToArray();
                }
            }

        }
        #endregion

        #region Helpers

        private static byte[] CreateNewKey()
        {
            var key = new byte[KEY_BIT_SIZE / DENOMINATOR];
            using (RandomNumberGenerator randomGenerator = RandomNumberGenerator.Create())
            {
                randomGenerator.GetBytes(key);
            }
            return key;
        }

        private byte[] PulseNewArray(byte[] array)
        {
            byte[] newArray = new byte[array.Length];
            Array.Copy(array, newArray, array.Length);
            byte[] hashedArray = sha.ComputeHash(newArray);
            for (int i = 0; i < hashedArray.Length; i++)
            {
                byte indexByte = hashedArray[i];
                int targetIndex = indexByte % hashedArray.Length;
                hashedArray[i] = hashedArray[targetIndex];
                hashedArray[targetIndex] = indexByte;
            }

            return hashedArray;
        }

        private void Initialize(string secretKey)
        {
            if (string.IsNullOrEmpty(secretKey))
            {
                throw new ArgumentNullException("Secret key can not be null or empty");
            }
            sha = sha ?? new SHA256Cng();
            byte[] secretBytes = SecurityUtility.Encoding.GetBytes(secretKey);
            secretBytes = sha.ComputeHash(secretBytes);
            byte[] authKeyInitiatorBytes = PulseNewArray(secretBytes);
            hashedSecret = Convert.ToBase64String(secretBytes);
            authKeyInitiator = Convert.ToBase64String(authKeyInitiatorBytes);
        }

        #endregion Helpers


        public void PutSecretKey(string secretKey)
        {
            if (isDisposed)
            {
                throw new ObjectDisposedException(OBJ_DISPOSED_MESSAGE);
            }

            Initialize(secretKey);
        }

        public void Dispose()
        {
            sha.Clear();
            sha.Dispose();
            Clear();
            isDisposed = true;
        }

        public void Clear()
        {
            if (isDisposed)
            {
                throw new ObjectDisposedException(OBJ_DISPOSED_MESSAGE);
            }

            hashedSecret = null;
            authKeyInitiator = null;
        }

        public bool Equals(AesHmac other)
        {
            if (other == null)
            {
                return false;
            }

            return (this.hashedSecret == other.hashedSecret) && (this.authKeyInitiator == other.authKeyInitiator) && (this.iterations == other.iterations);
        }

        public void FromXml(SecurityElement e)
        {
            if (e == null)
            {
                throw new ArgumentNullException("Security element can not be null");
            }

            var childs = e.Children;

            if (e.Tag != "AesHmac_InfSharp" || childs == null || childs.Count != 3)
            {
                throw new SecurityException("Security element is in wrong format");
            }

            int index = 0;

            for (int i = 0; i < childs.Count; i++)
            {
                SecurityElement child = (SecurityElement)childs[i];

                if (child != null)
                {
                    if (child.Tag == "Iteration")
                    {
                        string value = child.Text;

                        int intValue;

                        if (int.TryParse(value, out intValue))
                        {
                            iterations = intValue;
                            index++;
                        }
                    }

                    if (child.Tag == "Secret")
                    {
                        hashedSecret = child.Text;
                        index++;
                    }

                    if (child.Tag == "AuthKey")
                    {
                        authKeyInitiator = child.Text;
                        index++;
                    }
                }
            }

            if (index != 3)
            {
                Clear();
                iterations = DEFAULT_ITERATION;
                throw new SecurityException("Security element couldn't be parsed");
            }

            sha = new SHA256Cng();
        }

        public SecurityElement ToXml()
        {
            SecurityElement mainNode = new SecurityElement("AesHmac_InfSharp"),
                IterationNode = new SecurityElement("Iteration", iterations.ToString()),
                SecretNode = new SecurityElement("Secret", hashedSecret),
                AuthKeyNode = new SecurityElement("AuthKey", authKeyInitiator);

            mainNode.AddChild(IterationNode);
            mainNode.AddChild(SecretNode);
            mainNode.AddChild(AuthKeyNode);

            return mainNode;
        }


    }
}
