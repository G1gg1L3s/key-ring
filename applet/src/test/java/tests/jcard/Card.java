package tests.jcard;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public abstract class Card {
    abstract public void connect() throws Exception;
    abstract public void disconnect() throws Exception;

    abstract public ResponseAPDU transmit(CommandAPDU apdu) throws Exception;
}
