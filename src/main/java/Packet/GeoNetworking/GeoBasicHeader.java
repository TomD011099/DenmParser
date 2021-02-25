package Packet.GeoNetworking;

import Packet.Header;

public class GeoBasicHeader extends Header {
    enum NextHeader {
        ANY,
        COMMON,
        SECURED
    }

    private final int version;
    private final NextHeader nextHeader;
    private final int lt;
    private final int rhl;

    private static final int[] GEO_BASIC_LT = {50, 1000, 10000, 100000};

    public GeoBasicHeader(byte[] packet, int offset) throws Exception {
        super(4);
        assert packet.length - offset >= this.size;

        this.version = (packet[offset] >> 4);
        this.lt = ((packet[offset + 2] >> 2) * GEO_BASIC_LT[(packet[offset + 2]) & 0b00000011]);
        this.rhl = (packet[offset + 3] & 0xff);

        switch (packet[offset] & 0b00001111) {
            case 0:
                this.nextHeader = NextHeader.ANY;
                break;
            case 1:
                this.nextHeader = NextHeader.COMMON;
                break;
            case 2:
                this.nextHeader = NextHeader.SECURED;
                break;
            default:
                throw new Exception("Invalid next header");
        }
    }

    public void print() {
        System.out.println("===========================");
        System.out.println("GeoNetworking Basic Header");
        System.out.println("---------------------------");
        System.out.printf("Version: %d\n", this.version);
        System.out.printf("Next header: %s\n", this.nextHeader);
        System.out.printf("LT: %d\n", this.lt);
        System.out.printf("RHL: %d\n", this.rhl);
    }

    public int getVersion() {
        return version;
    }

    public NextHeader getNextHeader() {
        return nextHeader;
    }

    public int getLt() {
        return lt;
    }

    public int getRhl() {
        return rhl;
    }
}
