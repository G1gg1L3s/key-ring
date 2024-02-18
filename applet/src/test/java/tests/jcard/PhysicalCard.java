package tests.jcard;

import javacard.framework.AID;
import org.junit.Assert;

import javax.smartcardio.CardChannel;
import javax.smartcardio.TerminalFactory;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;

import java.util.List;

import static tests.CryptoBase.SW_SUCCESS;

public class PhysicalCard extends Card {

    javax.smartcardio.Card card;
    byte[] aid;

    public PhysicalCard(byte[] aid) {
        this.aid = aid;
    }


    @Override
    public void connect() throws Exception {
        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();
        System.out.println("Terminals: " + terminals);
        CardTerminal terminal = terminals.get(0);
        card = terminal.connect("T=0");
        select();
    }

    void select() throws  Exception {
        CommandAPDU apdu = new CommandAPDU(0x00, 0xa4, 0x04, 0x00, this.aid);
        ResponseAPDU res = transmit(apdu);
        Assert.assertEquals(SW_SUCCESS, res.getSW());
    }

    @Override
    public void disconnect() throws Exception {
        card.disconnect(false);
        card = null;
    }

    @Override
    public ResponseAPDU transmit(CommandAPDU apdu) throws Exception {
        CardChannel channel = card.getBasicChannel();
        return channel.transmit(apdu);
    }
}
