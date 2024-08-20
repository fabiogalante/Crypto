using System.Security.Cryptography;

namespace Crypto;

public static class CryptographyHelper
{
    private static readonly byte[] Key;
    private static readonly byte[] IV;

    static CryptographyHelper()
    {
        // Generate key and IV or load from a secure location
        Key = GenerateKey(32); // AES-256 requires a 32-byte key
        IV = GenerateKey(16);  // AES requires a 16-byte IV
    }

    public static string Encrypt(string plainText)
    {
        if (plainText == null)
            throw new ArgumentNullException(nameof(plainText));

        using Aes aesAlg = Aes.Create();
        aesAlg.Key = Key;
        aesAlg.IV = IV;

        ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

        using MemoryStream msEncrypt = new MemoryStream();
        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
        {
            swEncrypt.Write(plainText);
        }
        return Convert.ToBase64String(msEncrypt.ToArray());
    }

    public static string Decrypt(string cipherText)
    {
        if (cipherText == null)
            throw new ArgumentNullException(nameof(cipherText));

        using Aes aesAlg = Aes.Create();
        aesAlg.Key = Key;
        aesAlg.IV = IV;

        ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

        using var msDecrypt = new MemoryStream(Convert.FromBase64String(cipherText));
        using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
        using var srDecrypt = new StreamReader(csDecrypt);
        return srDecrypt.ReadToEnd();
    }

    // Generates a random key of the specified size in bytes
    public static byte[] GenerateKey(int size)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(size);

        using var rng = new RNGCryptoServiceProvider();
        byte[] key = new byte[size];
        rng.GetBytes(key);
        return key;
    }
}