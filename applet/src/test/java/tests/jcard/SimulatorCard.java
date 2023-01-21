package tests.jcard;

import com.licel.jcardsim.smartcardio.CardSimulator;
import javacard.framework.Applet;
import javacard.framework.AID;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class SimulatorCard extends Card{

    AID aid;
    CardSimulator card;


    public SimulatorCard(AID aid, Class<? extends Applet> appletClass) {
        this.aid = aid;
        card = new CardSimulator();
        card.installApplet(aid, appletClass);
    }

    @Override
    public void connect() {
        card.selectApplet(aid);
    }

    @Override
    public void disconnect() {
        card.reset();
    }

    public ResponseAPDU transmit(CommandAPDU apdu) {
        return card.transmitCommand(apdu);
    }
}
