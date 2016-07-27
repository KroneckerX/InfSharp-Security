# InfSharp-Security

CSharp Encryption Library

## Example
```cs
string cipheredText = AesHmac.EncryptString(plaintText, passwordText);
string plaintText = AesHmac.DecryptString(cipheredText, passwordText);
```

or

```cs
AesHmac aesHmac = new AesHmac(passwordText);
string cipheredText = aesHmac.Encrypt(plainText);
string plainText = aesHmac.Decrypt(cipheredText);
```



