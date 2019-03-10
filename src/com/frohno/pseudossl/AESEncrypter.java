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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 *
 * @author Oliver
 */
public class AESEncrypter
{

    private SecretKey secretKey;
    static byte[] iv;

    public AESEncrypter()
    {
        try
        {
            secretKey = buildKey();
            generateIV();
        } catch (NoSuchAlgorithmException ex)
        {
            Logger.getLogger(AESEncrypter.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public SecretKey buildKey() throws NoSuchAlgorithmException
    {
        final int keySize = 256;
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    public static SealedObject encrypt(SecretKey secretKey, byte[] data, byte[] iv)
    {
        SealedObject output = null;
        try
        {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            output = new SealedObject(data, cipher);
        } catch (Exception ex)
        {
            ex.printStackTrace();
        }
        return output;
    }

    public static byte[] decrypt(SecretKey secretKey, SealedObject encrypted, byte[] iv)
    {
        byte[] output = null;
        try
        {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            output = (byte[]) encrypted.getObject(cipher);
        } catch (Exception ex)
        {
            ex.printStackTrace();
        }
        return output;
    }

    public static byte[] toByteArray(Object o)
    {
        // Reference for stream of bytes
        byte[] stream = null;
        // ObjectOutputStream is used to convert a Java object into OutputStream
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ObjectOutputStream oos = new ObjectOutputStream(baos);)
        {
            oos.writeObject(o);
            stream = baos.toByteArray();
        } catch (IOException e)
        {
            // Error in serialization
            e.printStackTrace();
        }
        return stream;
    }

    public static Object toObject(byte[] data)
    {
        Object obj = null;

        try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
                ObjectInputStream ois = new ObjectInputStream(bais);)
        {
            obj = ois.readObject();
        } catch (Exception e)
        {
            // Error in de-serialization
            e.printStackTrace();
        }
        return obj;
    }

    public SecretKey getKey()
    {
        return secretKey;
    }

    public static void generateIV()
    {
        // generate IV
        SecureRandom random = new SecureRandom();
        iv = new byte[16];
        random.nextBytes(iv);
    }
    
    public byte[] getIV()
    {
        return iv;
    }

}
