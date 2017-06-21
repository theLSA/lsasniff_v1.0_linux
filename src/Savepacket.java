import java.io.IOException;

import javax.swing.JOptionPane;

import jpcap.JpcapWriter;

public class Savepacket {
	public void saveFile(String fileName) {
		JpcapWriter writer;
		int count = 0;

		try {

		writer = JpcapWriter.openDumpFile(Netcaptor.jpcap, fileName);

		while (Netcaptor.pt.length != 0) {
		count++;
		writer.writePacket(Netcaptor.pt[count]);

		}

		writer.close();
		//writer = null;

		} catch (IOException e) {

		// TODO Auto-generated catch block

		e.printStackTrace();

		}

		}

		
}
