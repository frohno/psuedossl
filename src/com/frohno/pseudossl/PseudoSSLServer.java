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

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

/**
 *
 * @author Oliver
 */
public class PseudoSSLServer
{

    private ObjectOutputStream outputStream = null;
    private ObjectInputStream inputStream = null;
    private final RSAEncrypter rSAEncrypter = new RSAEncrypter();
    private Socket socket = null;
    private SecretKey aESecretKey = null;
    private byte[] iv = null;

    public PseudoSSLServer(Socket socket)
    {
        try
        {
            this.socket = socket;
            System.out.println("Connection established");
            inputStream = new ObjectInputStream(socket.getInputStream());
            outputStream = new ObjectOutputStream(socket.getOutputStream());
        } catch (IOException ex)
        {
            Logger.getLogger(PseudoSSLServer.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        initialize();
    }

    private boolean initialize()
    {
        try
        {
            //Recieve Client Public Key
            PublicKey clientPublicKey = (PublicKey) inputStream.readObject();
            System.out.println("Client's public key has been recieved");
            //Send Responce
            outputStream.writeObject(rSAEncrypter.encrypt(clientPublicKey, ObjectParser.toByteArray(java.net.InetAddress.getLocalHost().getHostAddress())));
            outputStream.flush();

            //Sending Public Key
            outputStream.writeObject(rSAEncrypter.getPubKey());
            outputStream.flush();
            System.out.println("Public key has been sent");
            //Recieve Response
            String ip = (String) ObjectParser.toObject(rSAEncrypter.decrypt(rSAEncrypter.getPrivateKey(), (byte[]) inputStream.readObject()));
            System.out.println("IP: " + ip);

            //Recieve AES Secret Key
            aESecretKey = (SecretKey) ObjectParser.toObject(rSAEncrypter.decrypt(rSAEncrypter.getPrivateKey(), (byte[]) inputStream.readObject()));
            iv = (byte[]) ObjectParser.toObject(rSAEncrypter.decrypt(rSAEncrypter.getPrivateKey(), (byte[]) inputStream.readObject()));
            //Send Responce
            outputStream.writeObject(AESEncrypter.encrypt(aESecretKey, ObjectParser.toByteArray(java.net.InetAddress.getLocalHost().getHostAddress()), iv));
            System.out.println("Encrypted communication initialized");
            return true;
        } catch (Exception e)
        {
            e.printStackTrace();
            return false;
        }
    }

    public void close()
    {
        try
        {
            inputStream.close();
            outputStream.close();
        } catch (IOException ex)
        {
            Logger.getLogger(PseudoSSLClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
        public void sendObject(Object o)
    {
        try
        {
            outputStream.writeObject(AESEncrypter.encrypt(aESecretKey, ObjectParser.toByteArray(o), iv));
        } catch (IOException ex)
        {
            Logger.getLogger(PseudoSSLClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public Object recieveObject()
    {
        try
        {
            return ObjectParser.toObject(AESEncrypter.decrypt(aESecretKey, (SealedObject) inputStream.readObject(), iv));
        } catch (IOException | ClassNotFoundException ex)
        {
            Logger.getLogger(PseudoSSLClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return null;
    }
}
