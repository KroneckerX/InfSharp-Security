using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace InfSharp.Security
{
    public static class Utility
    {
        public static string ComposeSecret(string username, string password)
        {
            return SecurityUtility.ComposeSecret(username, password);
        }
    }
}
