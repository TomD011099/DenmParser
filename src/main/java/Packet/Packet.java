package Packet;

import Packet.GeoNetworking.GeoBasicHeader;

import java.util.List;

public class Packet {
    private GeoBasicHeader geoBasicHeader;
    private List<Header> headers;

    public Packet(byte[] packet, int offset) {
        try {
            this.geoBasicHeader = new GeoBasicHeader(packet, offset);
            offset += this.geoBasicHeader.size;

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
