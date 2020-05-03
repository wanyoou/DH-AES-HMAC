import java.io.*;
import java.awt.*;
import javax.swing.*;
import java.awt.event.*;
import java.net.Socket;
import java.util.Base64;
import java.util.Map;
 
public class Client extends JFrame implements ActionListener
{
   /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	Socket fclient;
	Socket sclient;
	Socket client;
	boolean done;

	JButton sent;
	JTextArea chatContent;
	JTextField sentence;
	DataInputStream in = null;
	DataOutputStream out = null;
	DataInputStream fin = null;
	DataOutputStream sout = null;
	byte[] AESKey;
    final Base64.Encoder encoder = Base64.getEncoder();	// 将字节数组转化为base64编码
    final Base64.Decoder decoder = Base64.getDecoder();	// 将base64编码字符串转化回字节数组
   
	public Client()
	{
		buildGUI("Client");  // 客户机端
		try
		{
			fclient = new Socket("localhost",8124);
			fin = new DataInputStream(fclient.getInputStream());
			done = false;
			String line;
			String check;
			chatContent.append("成功连接到服务端...\n连接端口号：8124\n");
		
			new DH_AES_HMAC();
			// 接收服务端公钥
			byte[] serverPublicKey = fin.readAllBytes();
			// 由服务端公钥产生的客户端密钥对
	        Map<String,Object> keyMap2=DH_AES_HMAC.initKey(serverPublicKey);
	        // 客户端公钥
	        byte[] publicKey2=DH_AES_HMAC.getPublicKey(keyMap2);
	        // 客户端私钥
	        byte[] privateKey2=DH_AES_HMAC.getPrivateKey(keyMap2);
	        chatContent.append("****************************************************\n");
	        chatContent.append("接收到服务端发送的公钥：\n"+encoder.encodeToString(serverPublicKey));
	        chatContent.append("\n客户端公钥：\n"+encoder.encodeToString(publicKey2));
	        chatContent.append("\n客户端私钥：\n"+encoder.encodeToString(privateKey2));
	
	        // 将客户端公钥发送给服务端
			sclient = new Socket("localhost",8124);
			sout = new DataOutputStream(sclient.getOutputStream());
	        sout.write(publicKey2);
	        sout.close();
	                
	        // 组装客户端本地密钥，由服务端公钥和客户端私钥组合而成
	        // 此密钥即为服务端与客户端经由 DH 协议协商出的共享密钥
			AESKey = DH_AES_HMAC.getSecretKey(serverPublicKey, privateKey2);
			chatContent.append("\n由服务端公钥和客户端私钥生成的共享密钥（DH协议）：\n"+encoder.encodeToString(AESKey)+"\n");
			
			
			client = new Socket("localhost",8124);
			out = new DataOutputStream(client.getOutputStream());
			in = new DataInputStream(client.getInputStream());
			
			while(!done)
			{
				while((line = in.readUTF())!=null)
				{
					chatContent.append("\n****************************************************\n");
					chatContent.append("接收到服务端发来的密文："+line+"\n");
					byte[] ci = decoder.decode(line);
					if((check = in.readUTF())!=null)
					{
						chatContent.append("接收到服务端发来的消息认证码："+check+"\n");
						String checksum = encoder.encodeToString(DH_AES_HMAC.HMACEncode(ci, AESKey));
						chatContent.append("经 HMAC 计算出消息认证码："+checksum+"\n");
						boolean same = check.equals(checksum);
						chatContent.append("消息认证码是否一致："+same+"\n");
						if(same) {
							chatContent.append("此条消息完整且来源可靠...\n经 AES 解密出明文："+new String(DH_AES_HMAC.AESDecrypt(ci, AESKey))+"\n");
						}
						else {
							chatContent.append("此条消息完整性或来源不可靠！\n");
						}
					}
					
					if(line.equals("bte"))
					{
						String msg = "\n服务器发来结束通信命令！\n";
						msg += "连接将在您确认此对话框的10秒钟后关闭!\n";
						JOptionPane.showMessageDialog(this, msg);
						Thread.sleep(10000);
						done = true;
						break;
					}
				}
				in.close();
				out.close();			
				System.exit(0);
			}
		}
		catch (Exception e)
		{
			chatContent.append("\n服务器已关闭...\n");
		}
  }
   
	public void buildGUI(String title)
	{
		this.setTitle(title);
		this.setSize(650,800);
		Container container = this.getContentPane();
		container.setLayout(new BorderLayout());
		JScrollPane centerPane = new JScrollPane();
		chatContent = new JTextArea();
		centerPane.setViewportView(chatContent);
		container.add(centerPane,BorderLayout.CENTER);
		chatContent.setEditable(false);
		JPanel bottomPanel = new JPanel();
		sentence = new JTextField(20);
		sent = new JButton("Send");  // 发送
		bottomPanel.add(new JLabel("Message")); // 聊天信息
		bottomPanel.add(sentence);
		bottomPanel.add(sent);
		container.add(bottomPanel,BorderLayout.SOUTH);
		sent.addActionListener(this);
		sentence.addActionListener(this);
		this.setVisible(true);
		this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	}
	
	// 注释参见 Server.java
	public void actionPerformed(ActionEvent e)
	{
		String str = sentence.getText();
		if(str!=null&&!str.equals(""))
		{
			chatContent.append("\n****************************************************\n");
			chatContent.append("明文："+str+"\n");
			try
			{
				byte[] code = DH_AES_HMAC.AESEncrypt(str.getBytes(), AESKey);
				String ciph = encoder.encodeToString(code);
				String check1 = encoder.encodeToString(DH_AES_HMAC.HMACEncode(code, AESKey));
				chatContent.append("经 AES 加密出密文："+ciph+"\n");
				chatContent.append("经 HMAC 计算出消息认证码："+check1+"\n");
				out.writeUTF(ciph);
				out.writeUTF(check1);
			}
			catch (Exception e3)
			{
				chatContent.append("服务器未启动...\n");
			}
		}
		else
		{
			chatContent.append("聊天信息不能为空...\n");
		}
		sentence.setText("");
	}
   
	public static void main(String[] args)
	{
		new Client();
	}
}