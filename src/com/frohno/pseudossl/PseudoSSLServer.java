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
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.URL;
import java.security.PublicKey;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

/**
 * Serverside for PseudoSSL
 * @author Frohno
 */
public class PseudoSSLServer {

    private ObjectOutputStream outputStream = null;
    private ObjectInputStream inputStream = null;
    private final RSAEncrypter rSAEncrypter = new RSAEncrypter();
    private Socket socket = null;
    private SecretKey aESecretKey = null;
    private byte[] iv = null;
    private InetAddress ip;

    /**
     * Constructor
     * @param socket the socket to which a specific client is connect
     */
    public PseudoSSLServer(Socket socket) {
        try {
            this.socket = socket;
            inputStream = new ObjectInputStream(socket.getInputStream());
            outputStream = new ObjectOutputStream(socket.getOutputStream());
            ip = isInternal(socket.getInetAddress()) ? socket.getInetAddress() : InetAddress.getByName(new BufferedReader(new InputStreamReader(new URL("http://checkip.amazonaws.com").openStream())).readLine());
        } catch (SocketException ex) {
        } catch (IOException ex) {
            //ex.printStackTrace();
        }

        initialize();
    }
    
    /**
     * Initializes the connection, setting up an AES key, by way of a similar-to SSL protocol
     * @return false upon error
     */
    private boolean initialize() {
        try {
            //Recieve Client Public Key
            PublicKey clientPublicKey = (PublicKey) inputStream.readObject();
            //Send Responce
            outputStream.writeObject(rSAEncrypter.encrypt(clientPublicKey, ObjectParser.toByteArray(ip)));
            //outputStream.flush();

            //Sending Public Key
            outputStream.writeObject(rSAEncrypter.getPubKey());
            outputStream.flush();
            
            //Recieve Response
            InetAddress ipClient = (InetAddress) ObjectParser.toObject(rSAEncrypter.decrypt(rSAEncrypter.getPrivateKey(), (byte[]) inputStream.readObject()));
            if (!ipClient.getHostAddress().equals(socket.getInetAddress().getHostAddress())) {
                System.out.println(ipClient.getHostAddress());
                System.out.println(socket.getInetAddress().getHostAddress());
                throw new IllegalAccessException();
            }

            //Recieve AES Secret Key
            aESecretKey = (SecretKey) ObjectParser.toObject(rSAEncrypter.decrypt(rSAEncrypter.getPrivateKey(), (byte[]) inputStream.readObject()));
            iv = (byte[]) ObjectParser.toObject(rSAEncrypter.decrypt(rSAEncrypter.getPrivateKey(), (byte[]) inputStream.readObject()));
            //Send Responce
            outputStream.writeObject(AESEncrypter.encrypt(aESecretKey, ObjectParser.toByteArray(ip), iv));
            return true;
        } catch (Exception e) {
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
        } catch (SocketException ex) {
            System.out.println("Connection reset");
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
            outputStream.writeObject(AESEncrypter.encrypt(aESecretKey, ObjectParser.toByteArray(o), iv));
        } catch (SocketException | EOFException ex) {
            System.out.println("Connection reset");
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
            return ObjectParser.toObject(AESEncrypter.decrypt(aESecretKey, (SealedObject) inputStream.readObject(), iv));
        } catch (SocketException | EOFException ex) {
            System.out.println("Connection reset");
        } catch (IOException | ClassNotFoundException ex) {
            ex.printStackTrace();
        }

        return null;
    }
}
