package tests.jcard;

import javax.smartcardio.CardChannel;
import javax.smartcardio.TerminalFactory;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;

import java.util.List;

public class PhysicalCard extends Card {

    javax.smartcardio.Card card;

    @Override
    public void connect() throws Exception {
        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();
        System.out.println("Terminals: " + terminals);
        CardTerminal terminal = terminals.get(0);
        card = terminal.connect("T=0");
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
