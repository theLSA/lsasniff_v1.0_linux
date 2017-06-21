import java.io.IOException;
import java.util.Vector;

import jpcap.JpcapCaptor;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;

public class Openpacket {
	
	public void openfile() {
		
		//Netcaptor nc = new Netcaptor();
		
		//CipePackageMain cm = new CipePackageMain();
		try {
			
			JpcapCaptor captor = JpcapCaptor.openFile("mypacket.pcap");
			while(true) {
				Packet packet = captor.getPacket();
				if(packet==null || packet==Packet.EOF) break;
				
				String data = new String(packet.data);
				try
		           {
		                  Vector r = new Vector();
		                  String strtmp;
		                  String packetprocol;
		                  
		                  //-----------------------------------------------------------------------------------
		                  long timestamp = (packet.sec * 1000) + (packet.usec / 1000);
		                 
		                  r.addElement(Long.toString(timestamp));   //time
		                  
		                  if(packet instanceof jpcap.packet.ARPPacket) {
		                	  packetprocol = "ARP";
		                	  r.addElement(packetprocol);
		                  }
		                  else if(packet instanceof jpcap.packet.ICMPPacket) {
		                	  packetprocol = "ICMP";
		                	  r.addElement(packetprocol);
		                  }
		                  else if(packet instanceof jpcap.packet.TCPPacket) {
		                	  TCPPacket tcppacket = (TCPPacket)packet;
		                	  //String data = new String(packet.data);
		                	  if((tcppacket.src_port==80||tcppacket.dst_port==80) && data.contains("HTTP")) {
		                		  packetprocol = "HTTP";
		                    	  r.addElement(packetprocol);
		                	  }else if(tcppacket.src_port==443||tcppacket.dst_port==443) {
		                		  packetprocol = "TLS";
		                    	  r.addElement(packetprocol);
		                	  }
		                	  else {
		                		  packetprocol = "TCP";
		                    	  r.addElement(packetprocol);
		                	  }
		                	  
		                  }
		                  else if(packet instanceof jpcap.packet.UDPPacket) {
		                	  UDPPacket udppacket = (UDPPacket)packet;
		                	  if(udppacket.src_port==53||udppacket.dst_port==53) {
		                		  packetprocol = "DNS";
		                    	  r.addElement(packetprocol);
		                	  }
		                	  else {
		                		  packetprocol = "UDP";
		                    	  r.addElement(packetprocol);
		                	  }
		                	 
		                  }
		                  else if(packet instanceof jpcap.packet.IPPacket) {
		                	  packetprocol = "IP";
		                	  r.addElement(packetprocol);
		                  }
		                  else {
		                	  packetprocol = "unknow";
		                	  r.addElement(packetprocol);
		                  }
		                 
		                  
		                  r.addElement(((IPPacket)packet).src_ip.toString());   //src ip
		                  r.addElement(((IPPacket)packet).dst_ip.toString());   //dst ip
		                  r.addElement(Integer.toString(packet.header.length));   //header length
		                  r.addElement(Integer.toString(packet.data.length));    //data length
		                  r.addElement(((IPPacket)packet).dont_frag == true ? "y" : "n" );   //dont frag
		                  r.addElement(Integer.toString(((IPPacket)packet).offset));   //offset
		                  
		   
		                  strtmp = "";
		                  for(int i=0;i<packet.header.length;i++){   
		                         strtmp += Byte.toString(packet.header[i]);
		                  }
		                  r.addElement(strtmp);
		                  
		   
		                  strtmp = "";
		                  for(int i=0;i<packet.data.length;i++){   
		                         strtmp += Byte.toString(packet.data[i]);
		                  }
		                  r.addElement(strtmp);
		                  //--------------------------------------------------------------------------------------------------------
		                  
		                  CipePackageMain.rows.addElement(r);   
		                  CipePackageMain.tabledisplay.addNotify(); 
		                  Netcaptor.packetnum++;
		                  CipePackageMain.statusLabel.setText("capturing......[no filter"+"]                                                                                                                                                                     "+"total: "+Netcaptor.packetnum);
		           }
		           catch( Exception e)
		           {
		                 
		           }
		    }
				
//				CipePackageMain cm = new CipePackageMain();
//				System.out.print("---------");
//				cm.dealPacket(packet);
				
				//System.out.println(packet);
				//nc.startCaptureThread();
			
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
}
