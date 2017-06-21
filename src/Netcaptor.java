import java.awt.Color;

import jpcap.JpcapCaptor;
import jpcap.JpcapWriter;
import jpcap.PacketReceiver;
import jpcap.packet.Packet;

public class Netcaptor {
	
	public static JpcapCaptor jpcap = null;  
    CipePackageMain CipePackageframe;
    
   
    public void setJFrame(CipePackageMain frame){  
           this.CipePackageframe = frame;
    }
   
    public void capturePacketsFromDevice() {

           if(jpcap!=null)
        	   
               jpcap.close();
                 
           jpcap = Jcapturedialog.getJpcap(CipePackageframe);
          
           if (jpcap != null) {
                  startCaptureThread();
           }

    }
   
    private Thread captureThread;
    public static int packetnum = 0;
    public static Packet pt[] = new Packet[99999];

   
    public void startCaptureThread(){
          
           if(captureThread != null)
                  return;
           captureThread = new Thread(new Runnable(){
                  public void run(){
                         while(captureThread != null){
                                jpcap.processPacket(1, handler);   
                         }
                  }
           });
           captureThread.setPriority(Thread.MIN_PRIORITY);
           captureThread.start();
           
         
    }
   
    void stopcaptureThread(){
           captureThread = null;
    }
   
    public void stopCapture(){
          
           stopcaptureThread();
           CipePackageMain.statusLabel.setText("stopping......"+"                                                                                                                                                                             "+"total: "+packetnum);
    }
   
    private PacketReceiver handler = new PacketReceiver(){   
           public void receivePacket(Packet packet) {   
                  //System.out.println(packet);
        	
               //System.out.println(packetnum);
              
              packetnum++;
              pt[packetnum] = packet;
              
              if(CipePackageMain.isfilter == 1) {
            	  CipePackageMain.statusLabel.setText("capturing......["+CipePackageMain.filtertext.getText()+"]                                                                                                                                                                     "+"total: "+packetnum);
              }
              
              else {
            	  CipePackageMain.statusLabel.setText("capturing......[no filter"+"]                                                                                                                                                                     "+"total: "+packetnum);
              }
               
              CipePackageframe.dealPacket(packet);
                  
           }
          
    };
}
