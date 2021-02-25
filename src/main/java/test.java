public class test {
    public static void main(String[] args) {
        byte[] b = {(byte) 0x3b, (byte) 0x9a, (byte) 0xca, (byte) 0x00};

        int stationId = ((b[0] & 0xff) << 24) | ((b[1] & 0xff) << 16) | ((b[2] & 0xff) << 8) | (b[3] & 0xff);

        System.out.println(stationId);
    }
}
