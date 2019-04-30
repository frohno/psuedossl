/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.frohno.pseudossl;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;

/**
 *
 * @author Oliver
 */
public class NetworkUtils {

    /**
     *
     * @param addr
     * @return
     */
    public static boolean isInternal(InetAddress addr) {

        if (addr.isAnyLocalAddress() || addr.isLoopbackAddress()) {
            return true;
        }

        // Check if the address is defined on any interface
        try {
            return NetworkInterface.getByInetAddress(addr) != null;
        } catch (SocketException e) {
            return false;
        }

    }
}
