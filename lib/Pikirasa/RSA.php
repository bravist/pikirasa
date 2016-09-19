<?php
namespace Pikirasa;

class RSA
{
    protected $publicKeyFile;
    protected $privateKeyFile;
    protected $password;

    public function __construct($publicKeyFile, $privateKeyFile = null, $password = null)
    {
        $this->publicKeyFile =  $this->fixKeyArgument($publicKeyFile);
        $this->privateKeyFile = $this->fixKeyArgument($privateKeyFile);
        $this->password = $password;
    }

    public function fixKeyArgument($keyFile)
    {
        if (strpos($keyFile, '/') === 0) {
            // This looks like a path, let us prepend the file scheme
            return 'file://' . $keyFile;
        }

        return $keyFile;
    }


    /**
     * Set password to be used during encryption and decryption
     *
     * @param string $password Certificate password
     */
    public function setPassword($password)
    {
        $this->password = $password;
    }

    /**
     * Encrypt data with provided public certificate
     *
     * @param string $data Data to encrypt
     * @return string Encrypted data
     *
     * @throws Pikirasa\Exception
     */
    public function encrypt($data)
    {
        // Load public key
        $publicKey = openssl_pkey_get_public($this->publicKeyFile);

        if (!$publicKey) {
            throw new Exception("OpenSSL: Unable to get public key for encryption. Is the location correct? Does this key require a password?");
        }

        $success = openssl_public_encrypt($data, $encryptedData, $publicKey);
        openssl_free_key($publicKey);
        if (!$success) {
            throw new Exception("Encryption failed. Ensure you are using a PUBLIC key.");
        }

        return $encryptedData;
    }

    /**
     * Encrypt data and then base64_encode it
     *
     * @param string $data Data to encrypt
     * @return string Base64-encrypted data
     */
    public function base64Encrypt($data)
    {
        return base64_encode($this->encrypt($data));
    }

    /**
     * Decrypt data with provided private certificate
     *
     * @param string $data Data to encrypt
     * @return string Decrypted data
     *
     * @throws Pikirasa\Exception
     */
    public function decrypt($data)
    {
        if ($this->privateKeyFile === null) {
            throw new Exception("Unable to decrypt: No private key provided.");
        }

        $privateKey = openssl_pkey_get_private($this->privateKeyFile, $this->password);
        if (!$privateKey) {
            throw new Exception("OpenSSL: Unable to get private key for decryption");
        }

        $success = openssl_private_decrypt($data, $decryptedData, $privateKey);
        openssl_free_key($privateKey);
        if (!$success) {
            throw new Exception("Decryption failed. Ensure you are using (1) A PRIVATE key, and (2) the correct one.");
        }

        return $decryptedData;
    }

    /**
     * base64_decode data and then decrypt it
     *
     * @param string $data Base64-encoded data to decrypt
     * @return string Decrypted data
     */
    public function base64Decrypt($data)
    {
        return $this->decrypt(base64_decode($data));
    }

    /**
     * Encrypt data and then base64_encode it for long chars
     * http://php.net/manual/zh/function.openssl-private-encrypt.php
     *
     * @param string $data Data to encrypt
     * @param int    $length split length
     * @return string Base64-encrypted data
     */
    public function base64EncryptForLongChars($data, $length = 117)
    {
        if (strlen($data) < $length ) {
            return $this->base64Encrypt($data);
        }

        $split = str_split($data, $length);

        $encryptedData = '';
        
        foreach ($split as $part) {
            $encryptedData .= $this->encrypt($part);
        }
        return base64_encode($encryptedData);
    }


    /**
     * base64_decode data and then decrypt it
     *
     * @param string $data Base64-encoded data to decrypt
     * @return string Decrypted data
     */
    public function base64DecryptForLongChars($data, $length = 172) {

        if (strlen($data) < $length ) {
            return $this->base64Decrypt($data);
        }

        $split = str_split(base64_decode($data), $length);

        $originalData = '';

        foreach ($split as $part) {
            $originalData .= $this->decrypt($part);
        }

        return $originalData;
    }
}
