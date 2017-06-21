import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.util.Vector;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;

import com.sun.jmx.snmp.Timestamp;

import jpcap.JpcapCaptor;
import jpcap.JpcapWriter;
import jpcap.NetworkInterface;
import jpcap.packet.*;

public class CipePackageMain extends javax.swing.JFrame implements ActionListener{
	 
    
    private static final JpcapCaptor jpcap = null;
	public JSeparator jSeparator2;   
    
    //-----------------------------------
    public JMenuItem exitMenuItem;
    public JMenuItem saveAsMenuItem;
    public JMenuItem saveMenuItem;
    public JMenuItem stopMenuItem;
    public JMenuItem startMenuItem;
    public JMenuItem openMenuItem;
    public JMenu Menu;
    public JMenuBar jMenuBar1;
    //---------------------------------------
   
    public static JTable tabledisplay = null;
    
    public static Vector rows,columns;
    
    DefaultTableModel tabModel;
    
    JScrollPane scrollPane;
    public static JLabel statusLabel;
    
    public static JTextField filtertext = new JTextField("no filter......"); 
    public static int isfilter = 0;
   
    Netcaptor captor = new Netcaptor();

    /**
    * Auto-generated main method to display this JFrame
    */
    public static void main(String[] args) {
      CipePackageMain inst = new CipePackageMain();
      inst.setVisible(true);
    }
   

	CipePackageMain() {
           super();
           initGUI();
    }
   
    private void initGUI() {
           try {
        	   	  this.setTitle("lsasniff_v1.0");
                  setSize(1200, 600);
                  {
                         jMenuBar1 = new JMenuBar();   
                         setJMenuBar(jMenuBar1);
                         {
                                Menu = new JMenu();
                                jMenuBar1.add(Menu);
                                Menu.setText("menu");
                                Menu.setPreferredSize(new java.awt.Dimension(50, 20));
                                {
                                       startMenuItem = new JMenuItem();
                                       Menu.add(startMenuItem);
                                       startMenuItem.setText("start");
                                       startMenuItem.setActionCommand("start");
                                       startMenuItem.addActionListener(this);
                                }
                                {
                                       stopMenuItem = new JMenuItem();
                                       Menu.add(stopMenuItem);
                                       stopMenuItem.setText("pause");
                                       stopMenuItem.setActionCommand("pause");
                                       stopMenuItem.addActionListener(this);
                                }
                                
                                {
                              	    openMenuItem = new JMenuItem();
                                    Menu.add(openMenuItem);
                                    openMenuItem.setText("open");
                                    openMenuItem.setActionCommand("open");
                                    openMenuItem.addActionListener(this);
                                    
                                }
                                
                                {
                                       saveMenuItem = new JMenuItem();
                                       Menu.add(saveMenuItem);
                                       saveMenuItem.setText("save");
                                       saveMenuItem.setActionCommand("save");
                                       saveMenuItem.addActionListener(this);
                                       
                                }
                                
                             
                                {
                                       saveAsMenuItem = new JMenuItem();
                                       Menu.add(saveAsMenuItem);
                                       saveAsMenuItem.setText("save as ...");
                                }
                                {
                                       jSeparator2 = new JSeparator();
                                       Menu.add(jSeparator2);
                                }
                                {
                                       exitMenuItem = new JMenuItem();
                                       Menu.add(exitMenuItem);
                                       exitMenuItem.setText("Exit");
                                       exitMenuItem.setActionCommand("exit");
                                       exitMenuItem.addActionListener(this);
                                }
                         }
                  }   //---------------------------------------------------------------------------
                 
                  this.getContentPane().add(filtertext,BorderLayout.NORTH);
                  //filtertext.setActionCommand("filter");
                  filtertext.addActionListener(this);
                  
                  
                  
                  rows = new Vector();
                  columns = new Vector();
                 
                  //--------------------------------------
                  columns.addElement("package time");
                  columns.add("procol");
                  columns.addElement("src");
                  columns.addElement("dest");
                  columns.addElement("head length");
                  columns.addElement("data length");
                  columns.addElement("piecewise ");
                  columns.addElement("piecewise offset");
                  columns.addElement("head data");
                  columns.addElement("data");
                  //----------------------------------------------------
                 
                  tabModel = new DefaultTableModel();  
                  tabModel.setDataVector(rows,columns);
                  tabledisplay = new JTable(tabModel);
                  scrollPane = new JScrollPane(tabledisplay);  
                  this.getContentPane().add(scrollPane,BorderLayout.CENTER);
                 
                  statusLabel = new JLabel("waitting......");
                  
                  this.getContentPane().add(statusLabel,BorderLayout.SOUTH);
           } catch (Exception e) {
                  e.printStackTrace();
           }
    }
  
   
    public void actionPerformed(ActionEvent event){
           String cmd = event.getActionCommand();
           
           if(event.getSource()==filtertext)
           {
        	   try {
        		if(filtertext.getText().length()!=0){
        			System.out.println(filtertext.getText().length()+"not empty");
        			Netcaptor.jpcap.setFilter(filtertext.getText(),true);
    				filtertext.setBackground(Color.green);
    				statusLabel.setText("capturing......["+CipePackageMain.filtertext.getText()+"]                                                                                                                                                                     "+"total: "+Netcaptor.packetnum);
    				isfilter = 1;
        		}
      
        		else {
        			System.out.println(filtertext.getText().length()+"empty");
        			Netcaptor.jpcap.setFilter(filtertext.getText(),true);
        			filtertext.setBackground(Color.white);
        			statusLabel.setText("capturing......[no filter"+"]                                                                                                                                                                     "+"total: "+Netcaptor.packetnum);
        			isfilter = 0;
        		}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
           }
          
           if(cmd.equals("start")){
                  captor.capturePacketsFromDevice();
                  captor.setJFrame(this);
           }
           else if(cmd.equals("pause")){
                  captor.stopCapture();
           }
           else if(cmd.equals("exit")){
                  System.exit(0);
           }
           
           else if(cmd.equals("save")){
        	  Savepacket sp = new Savepacket();
        	  sp.saveFile("mypacket.pcap");
           }
           
           else if(cmd.equals("open")) {
        	   Openpacket op = new Openpacket();
        	   op.openfile();
           }
    }

    public void dealPacket(Packet packet)
    {
    	String data = new String(packet.data);
    	//System.out.println(data);
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
                	  if((tcppacket.src_port==80||tcppacket.dst_port==80)&&data.contains("HTTP")) {
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
                  
                  rows.addElement(r);   
                  tabledisplay.addNotify();   
           }
           catch( Exception e)
           {
                 
           }
    }
}