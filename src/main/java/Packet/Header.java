package Packet;

public class Header {
    protected final int size;

    public Header(int size) {
        this.size = size;
    }

    public int getSize() {
        return size;
    }
}
