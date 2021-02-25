package Packet.GeoNetworking;

import Packet.Header;

public class GeoCommonHeader extends Header {
    enum NextHeader {
        ANY,
        BTPA,
        BTPB,
        IPv6
    }

    enum HeaderType {
        ANY,
        BEACON,
        GEOUNICAST,
        GEOANYCAST,
        GEOBROADCAST,
        TSB,
        LS
    }

    private class TrafficClass {
        private final boolean scf;
        private final boolean channelOffload;
        private final int id;

        public TrafficClass(byte[] packet, int offset) {
            this.scf = ((packet[offset] >> 7) & 1) == 1;
            this.channelOffload = ((packet[offset] & 0b01000000) >> 6) == 1;
            this.id = (packet[offset] & 0b00111111);
        }

        public void print() {
            System.out.println("Traffic Class");
            System.out.format("\tSCF: %s\n", this.scf);
            System.out.printf("\tChannel Offload: %s\n", this.channelOffload);
            System.out.printf("\tTC ID: %d\n", this.id);
        }

        public boolean isScf() {
            return scf;
        }

        public boolean isChannelOffload() {
            return channelOffload;
        }

        public int getId() {
            return id;
        }
    }

    private final NextHeader nextHeader;
    private final HeaderType headerType;
    private final String headerSubtype;
    private final TrafficClass trafficClass;
    private final boolean itsGnIsMobile;
    private final int payloadLength;
    private final int maxHopLimit;

    private static final String[][] GEO_COMMON_HST = {
            {"UNSPECIFIED", "UNSPECIFIED", "UNSPECIFIED"},
            {"UNSPECIFIED", "UNSPECIFIED", "UNSPECIFIED"},
            {"UNSPECIFIED", "UNSPECIFIED", "UNSPECIFIED"},
            {"GEOANYCAST_CIRCLE", "GEOANYCAST_RECT", "GEOANYCAST_ELIP"},
            {"GEOBROADCAST_CIRCLE", "GEOBROADCAST_RECT", "GEOBROADCAST_ELIP"},
            {"SINGLE_HOP", "MULTI_HOP", "UNSPECIFIED"},
            {"LS_REQUEST", "LS_REPLY", "UNSPECIFIED"}
    };

    public GeoCommonHeader(byte[] packet, int offset) throws Exception {
        super(8);
        assert packet.length - offset >= super.size;

        this.trafficClass = new TrafficClass(packet, offset + 2);
        this.itsGnIsMobile = ((packet[offset + 3] >> 7) & 1) == 1;
        this.payloadLength = ((packet[offset + 4] & 0xff) << 8) | (packet[offset + 5] & 0xff);
        this.maxHopLimit = packet[offset + 6];

        switch (packet[offset] >> 4) {
            case 0:
                this.nextHeader = NextHeader.ANY;
                break;
            case 1:
                this.nextHeader = NextHeader.BTPA;
                break;
            case 2:
                this.nextHeader = NextHeader.BTPB;
                break;
            case 3:
                this.nextHeader = NextHeader.IPv6;
                break;
            default:
                throw new Exception("Invalid next header");
        }

        switch (packet[offset + 1] >> 4) {
            case 0:
                this.headerType = HeaderType.ANY;
                break;
            case 1:
                this.headerType = HeaderType.BEACON;
                break;
            case 2:
                this.headerType = HeaderType.GEOUNICAST;
                break;
            case 3:
                this.headerType = HeaderType.GEOANYCAST;
                break;
            case 4:
                this.headerType = HeaderType.GEOBROADCAST;
                break;
            case 5:
                this.headerType = HeaderType.TSB;
                break;
            case 6:
                this.headerType = HeaderType.LS;
                break;
            default:
                throw new Exception("Invalid next header");
        }

        this.headerSubtype = GEO_COMMON_HST[(packet[offset + 1] >> 4)][(packet[offset + 1] & 0b00001111)];
    }

    public void print() {
        System.out.println("===========================");
        System.out.println("GeoNetworking Common Header");
        System.out.println("---------------------------");
        System.out.printf("Next header: %s\n", this.nextHeader);
        System.out.printf("Header type: %s\n", this.headerType);
        System.out.printf("Header subtype: %s\n", this.headerSubtype);
        this.trafficClass.print();
        System.out.printf("GnIsMoile: %s\n", this.itsGnIsMobile);
        System.out.printf("Playload length: %d\n", this.payloadLength);
        System.out.printf("Max hoplimit: %d\n", this.maxHopLimit);
    }

    public NextHeader getNextHeader() {
        return nextHeader;
    }

    public HeaderType getHeaderType() {
        return headerType;
    }

    public String getHeaderSubtype() {
        return headerSubtype;
    }

    public TrafficClass getTrafficClass() {
        return trafficClass;
    }

    public boolean isItsGnIsMobile() {
        return itsGnIsMobile;
    }

    public int getPayloadLength() {
        return payloadLength;
    }

    public int getMaxHopLimit() {
        return maxHopLimit;
    }
}
