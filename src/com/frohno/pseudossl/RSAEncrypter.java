/*
 * The MIT License
 *
 * Copyright 2019 Frohno.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.frohno.pseudossl;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;

/**
 *
 * @author Oliver
 */
public class RSAEncrypter
{

    private KeyPair keyPair;
    private PublicKey pubKey;
    private PrivateKey privateKey;

    public RSAEncrypter()
    {
        try
        {
            keyPair = buildKeyPair();
            pubKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
        } catch (NoSuchAlgorithmException ex)
        {
           ex.printStackTrace();
        }
        
    }

    public KeyPair buildKeyPair() throws NoSuchAlgorithmException
    {
        final int keySize = 2048;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.genKeyPair();
    }

    public static byte[] encrypt(PrivateKey privateKey, byte[] data)
    {
        byte[] output = null;
        try
        {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            output = cipher.doFinal(data);
        } catch (Exception ex)
        {
            ex.printStackTrace();
        }
        return output;
    }
    
    public static byte[] encrypt(PublicKey publicKey, byte[] data)
    {
        byte[] output = null;
        try
        {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            output = cipher.doFinal(data);
        } catch (Exception ex)
        {
            ex.printStackTrace();
        }
        return output;
    }

    public static byte[] decrypt(PublicKey publicKey, byte[] encrypted)
    {
        byte[] output = null;
        try
        {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            output = cipher.doFinal(encrypted);
        } catch (Exception ex)
        {
            ex.printStackTrace();
        }
        return output;
    }
    
    public static byte[] decrypt(PrivateKey privateKey, byte[] encrypted)
    {
        byte[] output = null;
        try
        {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            output = cipher.doFinal(encrypted);
        } catch (Exception ex)
        {
            ex.printStackTrace();
        }
        return output;
    }


    public PublicKey getPubKey()
    {
        return pubKey;
    }

    public PrivateKey getPrivateKey()
    {
        return privateKey;
    }

}
