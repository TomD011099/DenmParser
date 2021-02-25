import org.json.JSONObject;
import org.pcap4j.core.*;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.util.ByteArrays;

import java.util.AbstractMap;
import java.util.HashMap;
import java.util.Map;

public class LoopRaw {

    private static final String COUNT_KEY = LoopRaw.class.getName() + ".count";
    private static final int COUNT = Integer.getInteger(COUNT_KEY, -1);

    private static final String READ_TIMEOUT_KEY = LoopRaw.class.getName() + ".readTimeout";
    private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

    private static final String SNAPLEN_KEY = LoopRaw.class.getName() + ".snaplen";
    private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

    private static final int[] GEO_BASIC_LT = {50, 1000, 10000, 100000};
    private static final String[] GEO_BASIC_NH = {"ANY", "COMMON", "SECURED"};

    private static final String[] GEO_COMMON_NH = {"ANY", "BTP-A", "BTP-B", "IPv6"};
    private static final String[] GEO_COMMON_HT = {"ANY", "BEACON", "GEOUNICAST", "GEOANYCAST", "GEOBROADCAST", "TSB", "LS"};
    private static final String[][] GEO_COMMON_HST = {
            {"UNSPECIFIED", "UNSPECIFIED", "UNSPECIFIED"},
            {"UNSPECIFIED", "UNSPECIFIED", "UNSPECIFIED"},
            {"UNSPECIFIED", "UNSPECIFIED", "UNSPECIFIED"},
            {"GEOANYCAST_CIRCLE", "GEOANYCAST_RECT", "GEOANYCAST_ELIP"},
            {"GEOBROADCAST_CIRCLE", "GEOBROADCAST_RECT", "GEOBROADCAST_ELIP"},
            {"SINGLE_HOP", "MULTI_HOP", "UNSPECIFIED"},
            {"LS_REQUEST", "LS_REPLY", "UNSPECIFIED"}
    };

    private static final Map<Integer, String> BTP_PORT = Map.ofEntries(
            new AbstractMap.SimpleEntry<>(2001, "CAM"),
            new AbstractMap.SimpleEntry<>(2002, "DENM"),
            new AbstractMap.SimpleEntry<>(2003, "RLT"),
            new AbstractMap.SimpleEntry<>(2004, "TLM"),
            new AbstractMap.SimpleEntry<>(2005, "SA"),
            new AbstractMap.SimpleEntry<>(2006, "IVI"),
            new AbstractMap.SimpleEntry<>(2007, "SREM"),
            new AbstractMap.SimpleEntry<>(2008, "SSEM"),
            new AbstractMap.SimpleEntry<>(2010, "EVCSN POI"),
            new AbstractMap.SimpleEntry<>(2011, "TPG"),
            new AbstractMap.SimpleEntry<>(2012, "Charging"),
            new AbstractMap.SimpleEntry<>(2013, "GPC"),
            new AbstractMap.SimpleEntry<>(2014, "CTL"),
            new AbstractMap.SimpleEntry<>(2015, "CRL"),
            new AbstractMap.SimpleEntry<>(2016, "Certificate request service")
    );

    private static final String[] ITS_MESSAGE_ID = {"", "DENM", "CAM", "POI", "SPAT", "MAP", "IVI", "EV-RSR"};

    private LoopRaw() {
    }

    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        PcapNetworkInterface nif;
        try {
            nif = Pcaps.findAllDevs().get(1);
            //nif = new NifSelector().selectNetworkInterface();
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        if (nif == null) {
            return;
        }

        System.out.println(nif.getName() + " (" + nif.getDescription() + ")");

        final PcapHandle handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

        String filter = "ether proto 0x8947";
        handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

        RawPacketListener listener = new RawPacketListener() {
            @Override
            public void gotPacket(byte[] packet) {
                System.out.println(handle.getTimestamp());
                JSONObject json = ParseGeoNetworking(packet, new JSONObject(), 16);

                if (json != null) {
                    System.out.println(json.toString());
                }
            }
        };

        try {
            handle.loop(COUNT, listener);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        PcapStat ps = handle.getStats();
        System.out.println("ps_recv: " + ps.getNumPacketsReceived());
        System.out.println("ps_drop: " + ps.getNumPacketsDropped());
        System.out.println("ps_ifdrop: " + ps.getNumPacketsDroppedByIf());

        handle.close();
    }

    private static JSONObject ParseGeoNetworking(byte[] packet, JSONObject json, int offset) {
        assert packet.length - offset >= 4;

        //System.out.println(ByteArrays.toHexString(packet, " ", offset, 4));

        int nh = (packet[offset] & 0x0f);

        json.put("GeoNetworking", new JSONObject()
                .put("Basic", new JSONObject()
                    .put("Version", ((packet[offset] >> 4) & 0x0f))
                    .put("NextHeader", GEO_BASIC_NH[nh])
                    .put("LT", (((packet[offset + 2] >> 2) & 0x3f) * GEO_BASIC_LT[((packet[offset + 2]) & 0x03)]))
                    .put("RHL", ((packet[offset + 3]) & 0xff))));

        offset += 4;
        switch (nh) {
            case 0:
                return json;
            case 1:
                return ParseGeoCommonHeader(packet, json, offset);
            case 2:
                return json;
            default:
                return null;
        }
    }

    private static JSONObject ParseGeoCommonHeader(byte[] packet, JSONObject json, int offset) {
        assert packet.length - offset >= 8;

        //System.out.println(ByteArrays.toHexString(packet, " ", offset, 8));

        String nh = GEO_COMMON_NH[((packet[offset] >> 4) & 0x0f)];
        String ht = GEO_COMMON_HT[((packet[offset + 1] >> 4) & 0x0f)];
        String hst = GEO_COMMON_HST[((packet[offset + 1] >> 4) & 0x0f)][(packet[offset + 1] & 0x0f)];

        JSONObject geoJson = (JSONObject) json.get("GeoNetworking");
        geoJson.put("Common", new JSONObject()
                .put("NextHeader", nh)
                .put("HeaderType", ht)
                .put("HeaderSubtype", hst)
                .put("TrafficClass", new JSONObject()
                        .put("SCF", (((packet[offset + 2] >> 7) & 0xff)))
                        .put("CO", ((packet[offset + 2] >> 6) & 0b00000001))
                        .put("ID", (packet[offset + 2] & 0b00111111)))      //TODO lookuptable
                .put("Flags", new JSONObject()
                        .put("Mobile", (((packet[offset + 3] >> 7) & 1) == 1)))
                .put("PayloadLength", ((packet[offset + 4] & 0xff) << 8) | (packet[offset + 5] & 0xff))
                .put("HopLimit", (packet[offset + 6] & 0xff)));

        offset += 8;
        json = new JSONObject().put("GeoNetworking", geoJson);

        switch (ht) {
            case "GEOUNICAST":
                return json; //TODO implement
            case "TSB":
                if (hst.equals("MULTI_HOP")) {
                    return json; //TODO implement
                } else {
                    return json; //TODO implement
                }
            case "GEOBROADCAST":
            case "GEOANYCAST":
                return ParseGeoGBACHeader(packet, json, offset, nh);
            case "BEACON":
                return json; //TODO implement
            case "LS":
                return json; //TODO implement
            default:
                return null;
        }
    }

    private static JSONObject ParseGeoGBACHeader(byte[] packet, JSONObject json, int offset, String nh) {
        assert packet.length - offset >= 44;

        //System.out.println(ByteArrays.toHexString(packet, " ", offset, 44));

        JSONObject geoJson = (JSONObject) json.get("GeoNetworking");
        geoJson.put("GeoBroadAnyCast", new JSONObject()
                .put("SequenceNumber", ((packet[offset] & 0xff) << 8) | (packet[offset + 1] & 0xff))
                .put("PositionVector", new JSONObject()
                        .put("GN_ADDR", ByteArrays.toHexString(packet, ":", offset + 4, 8))
                        .put("TST", ByteArrays.toHexString(packet, " ", offset + 12, 4))
                        .put("Lat", ByteArrays.toHexString(packet, " ", offset + 16, 4))
                        .put("Lon", ByteArrays.toHexString(packet, " ", offset + 20, 4))
                        .put("PAI", ((packet[offset + 23] >> 7) & 1))
                        .put("Speed", ((packet[offset + 24] & 0x7f) << 8) | (packet[offset + 25] & 0xff))
                        .put("Heading", ((packet[offset + 26] & 0xff) << 8) | (packet[offset + 27] & 0xff)))
                .put("DistA", ((packet[offset + 36] & 0xff) << 8) | (packet[offset + 37] & 0xff))
                .put("DistB", ((packet[offset + 38] & 0xff) << 8) | (packet[offset + 39] & 0xff))
                .put("Angle", ((packet[offset + 40] & 0xff) << 8) | (packet[offset + 41] & 0xff)));

        offset += 44;
        json = new JSONObject().put("GeoNetworking", geoJson);

        switch (nh) {
            case "ANY":
                return json;
            case "BTP-A":
                return json;
            case "BTP-B":
                return ParseBTPBHeader(packet, json, offset);
            case "IPv6":
                return json;
            default:
                return null;
        }
    }

    private static JSONObject ParseBTPBHeader(byte[] packet, JSONObject json, int offset) {
        assert packet.length - offset >= 4;

        //System.out.println(ByteArrays.toHexString(packet, " ", offset, 4));

        int i = ((packet[offset] & 0xff) << 8) | (packet[offset + 1] & 0xff);
        boolean wellKnown;

        if (BTP_PORT.containsKey(i)) {
            json.put("BTP-B", new JSONObject()
                    .put("Port", BTP_PORT.get(i))
                    .put("PortInfo", ByteArrays.toHexString(packet, " ", offset+2, 2)));
            wellKnown = true;
        } else {
            json.put("BTP-B", new JSONObject()
                    .put("Port", i)
                    .put("PortInfo", ByteArrays.toHexString(packet, " ", offset+2, 2)));
            wellKnown = false;
        }

        offset += 4;

        if (wellKnown) {
            switch (BTP_PORT.get(i)) {
                case "DENM":
                    return ParseItsPdu(packet, json, offset);
                default:
                    return null;
            }
        }
        return null;
    }

    private static JSONObject ParseItsPdu(byte[] packet, JSONObject json, int offset) {
        assert packet.length - offset >= 6;

        //System.out.println(ByteArrays.toHexString(packet, " ", offset, 6));

        int msgId = (packet[offset + 1] & 0xff);
        int stationId = ((packet[offset + 2] & 0xff) << 24) | ((packet[offset + 3] & 0xff) << 16) | ((packet[offset + 4] & 0xff) << 8) | (packet[offset + 5] & 0xff);

        if (msgId <= 0 || msgId > 7) {
            return null;
        }

        json.put("ITS", new JSONObject()
                .put("ItsPdu", new JSONObject()
                        .put("Version", (packet[offset] & 0xff))
                        .put("MessageID", ITS_MESSAGE_ID[msgId])
                        .put("StationID", stationId)));

        offset += 6;
        switch (ITS_MESSAGE_ID[msgId]) {
            case "DENM":
                //return ParseDenm(packet, json, offset);
            default:
                return null;
        }
    }
}