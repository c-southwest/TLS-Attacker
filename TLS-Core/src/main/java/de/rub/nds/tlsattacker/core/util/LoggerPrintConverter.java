package de.rub.nds.tlsattacker.core.util;

public class LoggerPrintConverter {
    public static String bytesToHexWithSpaces(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02X", bytes[i] & 0xFF));
            if (i < bytes.length - 1) {
                sb.append(" ");
            }
        }
        return sb.toString();
    }
}
