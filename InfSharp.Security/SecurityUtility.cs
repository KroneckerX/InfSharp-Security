using System;
using System.Security.Cryptography;
using System.Text;

namespace InfSharp.Security
{
    internal class SecurityUtility
    {
        private const int RANDOM_STRLEN_LIMIT = 256;
        private const int RANDOM_STR_PADDING = 20;


        internal static Encoding Encoding
        {
            get
            {
                return Encoding.UTF8;
            }
        }

        internal static string ComposeSecret(string username, string password)
        {
            byte[] usernameBytes = Encoding.GetBytes(username);
            byte[] passwordBytes = Encoding.GetBytes(password);

            byte[] changeSet;

            int min, max, total;

            if (usernameBytes.Length > passwordBytes.Length)
            {
                changeSet = passwordBytes;
                min = passwordBytes.Length;
                max = usernameBytes.Length;
            }
            else
            {
                changeSet = usernameBytes;
                min = usernameBytes.Length;
                max = passwordBytes.Length;
            }

            total = min + max;

            byte[] overall = new byte[usernameBytes.Length + passwordBytes.Length];
            Array.Copy(usernameBytes, overall, usernameBytes.Length);
            Array.Copy(passwordBytes, 0, overall, usernameBytes.Length, passwordBytes.Length);

            for (int i = 0; i < changeSet.Length; i++)
            {
                int changeIndex = changeSet[i] % min;
                byte tmpByte = overall[changeIndex];
                overall[changeIndex] = overall[changeIndex + min];
                overall[changeIndex + min] = tmpByte;
            }

            using (SHA256 sha256 = SHA256.Create())
            {
                overall = sha256.ComputeHash(overall);
            }

            return Convert.ToBase64String(overall);
        }

        internal static string ComposeRandomString()
        {
            return Convert.ToBase64String(ComposeRandomBytes());
        }

        internal static byte[] ComposeRandomBytes()
        {
            using (var randomNumberGenerator = RandomNumberGenerator.Create())
            {
                byte[] len = new byte[1];
                randomNumberGenerator.GetBytes(len);
                int length = len[0] % RANDOM_STRLEN_LIMIT + RANDOM_STR_PADDING;

                byte[] randomData = new byte[length];
                randomNumberGenerator.GetBytes(randomData);

                using (SHA256 sha = SHA256.Create())
                {
                    randomData = sha.ComputeHash(randomData);
                }

                return randomData;
            }
        }
    }
}
