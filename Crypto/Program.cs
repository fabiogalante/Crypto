// See https://aka.ms/new-console-template for more information

using Crypto;

byte[] key = CryptographyHelper.GenerateKey(32);
Console.WriteLine($"Generated Key (Base64): {Convert.ToBase64String(key)}");

// Example encryption and decryption
string plainText = "Hello, World!";
string encryptedText = CryptographyHelper.Encrypt(plainText);
string decryptedText = CryptographyHelper.Decrypt(encryptedText);

Console.WriteLine($"PlainText: {plainText}");
Console.WriteLine($"Encrypted: {encryptedText}");
Console.WriteLine($"Decrypted: {decryptedText}");