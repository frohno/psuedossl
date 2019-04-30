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

import static com.frohno.pseudossl.NetworkUtils.isInternal;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.security.PublicKey;
import javax.crypto.SealedObject;

/**
 * Clientside for PseudoSSL
 * @author Frohno
 */
public class PseudoSSLClient {
    
    private ObjectOutputStream outputStream = null;
    private ObjectInputStream inputStream = null;
    private final RSAEncrypter rSAEncrypter = new RSAEncrypter();
    private final AESEncrypter aESEncrypter = new AESEncrypter();
    private Socket clientSocket = null;
    private InetAddress ip;
    
    /**
     * Constructor
     * @param clientSocket the socket to which all communication is directed and expected from
     */
    public PseudoSSLClient(Socket clientSocket) {
        try {
            this.clientSocket = clientSocket;
            outputStream = new ObjectOutputStream(clientSocket.getOutputStream());
            inputStream = new ObjectInputStream(clientSocket.getInputStream());
            ip = isInternal(clientSocket.getInetAddress()) ? clientSocket.getInetAddress() : InetAddress.getByName(new BufferedReader(new InputStreamReader(new URL("http://checkip.amazonaws.com").openStream())).readLine());
        } catch (IOException ex) {
            ex.printStackTrace();
        }

        initialize();
    }
    
    /**
     * Initializes the connection, setting up an AES key, by way of a similar-to SSL protocol
     * @return false upon error
     */
    private boolean initialize() {
        try {
            //Sending Public Key
            outputStream.writeObject(rSAEncrypter.getPubKey());
            outputStream.flush();
            //Recieve Response
            InetAddress ipServer = (InetAddress) ObjectParser.toObject(rSAEncrypter.decrypt(rSAEncrypter.getPrivateKey(), (byte[]) inputStream.readObject()));
            if (ipServer.getAddress() != clientSocket.getInetAddress().getAddress()) {
                System.out.println(ipServer.getAddress());
                System.out.println(clientSocket.getInetAddress().getAddress());
                throw new IllegalAccessException();
            }

            //Recieve Server Public Key
            PublicKey serverPublicKey = (PublicKey) inputStream.readObject();
            //Send Responce
            outputStream.writeObject(rSAEncrypter.encrypt(serverPublicKey, ObjectParser.toByteArray(ip)));
            outputStream.flush();

            //Send AES Secret Key
            outputStream.writeObject(rSAEncrypter.encrypt(serverPublicKey, ObjectParser.toByteArray(aESEncrypter.getKey())));
            outputStream.writeObject(rSAEncrypter.encrypt(serverPublicKey, ObjectParser.toByteArray(aESEncrypter.getIV())));
            //Recieve Responce
            InetAddress ipServer2 = (InetAddress) ObjectParser.toObject(aESEncrypter.decrypt(aESEncrypter.getKey(), (SealedObject) inputStream.readObject(), aESEncrypter.getIV()));
            if (ipServer2.getAddress() != clientSocket.getInetAddress().getAddress()) {
                System.out.println(ipServer2.getAddress());
                System.out.println(clientSocket.getInetAddress().getAddress());
                throw new IllegalAccessException();
            }
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Close both the input and output stream created with the socket
     */
    public void close() {
        try {
            inputStream.close();
            outputStream.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    /**
     * Sends and encrypts an object
     * @param o the object to be sent
     */
    public void sendObject(Object o) {
        try {
            outputStream.writeObject(AESEncrypter.encrypt(aESEncrypter.getKey(), ObjectParser.toByteArray(o), aESEncrypter.getIV()));
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    /**
     * Waits for an object, which is then decrypted on arrival
     * @return the decrypted object, which has to be cast by the user to the original type
     */
    public Object recieveObject() {
        try {
            return ObjectParser.toObject(aESEncrypter.decrypt(aESEncrypter.getKey(), (SealedObject) inputStream.readObject(), aESEncrypter.getIV()));
        } catch (IOException | ClassNotFoundException ex) {
            ex.printStackTrace();
        }

        return null;
    }

}
