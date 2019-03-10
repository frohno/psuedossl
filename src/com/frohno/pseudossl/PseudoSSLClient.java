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
import java.net.Socket;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SealedObject;

/**
 *
 * @author Oliver
 */
public class PseudoSSLClient
{

    private ObjectOutputStream outputStream = null;
    private ObjectInputStream inputStream = null;
    private final RSAEncrypter rSAEncrypter = new RSAEncrypter();
    private final AESEncrypter aESEncrypter = new AESEncrypter();
    private Socket clientSocket = null;

    public PseudoSSLClient(Socket clientSocket)
    {
        try
        {
            this.clientSocket = clientSocket;
            outputStream = new ObjectOutputStream(clientSocket.getOutputStream());
            inputStream = new ObjectInputStream(clientSocket.getInputStream());
        } catch (IOException ex)
        {
            Logger.getLogger(PseudoSSLClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        initialize();
    }

    private boolean initialize()
    {
        try
        {
            //Sending Public Key
            outputStream.writeObject(rSAEncrypter.getPubKey());
            outputStream.flush();
            System.out.println("Public key has been sent");
            //Recieve Response

            String ip = (String) ObjectParser.toObject(rSAEncrypter.decrypt(rSAEncrypter.getPrivateKey(), (byte[]) inputStream.readObject()));
            System.out.println("IP: " + ip);
            System.out.println("Expected IP: " + clientSocket.getInetAddress());

            //Recieve Server Public Key
            PublicKey serverPublicKey = (PublicKey) inputStream.readObject();
            System.out.println("Server's public key has been recieved");
            //Send Responce
            outputStream.writeObject(rSAEncrypter.encrypt(serverPublicKey, ObjectParser.toByteArray(java.net.InetAddress.getLocalHost().getHostAddress())));
            outputStream.flush();

            //Send AES Secret Key
            outputStream.writeObject(rSAEncrypter.encrypt(serverPublicKey, ObjectParser.toByteArray(aESEncrypter.getKey())));
            outputStream.writeObject(rSAEncrypter.encrypt(serverPublicKey, ObjectParser.toByteArray(aESEncrypter.getIV())));
            System.out.println("AES key sent");
            //Recieve Responce
            String ip2 = (String) ObjectParser.toObject(aESEncrypter.decrypt(aESEncrypter.getKey(), (SealedObject) inputStream.readObject(), aESEncrypter.getIV()));
            System.out.println("IP: " + ip2);

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
            outputStream.writeObject(AESEncrypter.encrypt(aESEncrypter.getKey(), ObjectParser.toByteArray(o), aESEncrypter.getIV()));
        } catch (IOException ex)
        {
            Logger.getLogger(PseudoSSLClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public Object recieveObject()
    {
        try
        {
            return ObjectParser.toObject(aESEncrypter.decrypt(aESEncrypter.getKey(), (SealedObject) inputStream.readObject(), aESEncrypter.getIV()));
        } catch (IOException | ClassNotFoundException ex)
        {
            Logger.getLogger(PseudoSSLClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return null;
    }
    
    
}
