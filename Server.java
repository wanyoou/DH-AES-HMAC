import java.io.*;
import java.awt.*;
import javax.swing.*;
import java.awt.event.*;
import java.net.Socket;
import java.util.Base64;
import java.util.Map;
import java.net.ServerSocket;


public class Server extends JFrame implements ActionListener
{
   /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	ServerSocket server;//服务器端套接字
	Socket theClient;//与客户端通信的套接字
	Socket ftheClient;
	Socket stheClient;
	boolean done;//通信是否结束
	JButton sent;//发送按钮
	JTextArea chatContent;//聊天内容区
	JTextField sentence;//聊天信息栏
	DataOutputStream fout = null;
	DataInputStream sin = null;
	DataInputStream in = null;//来自客户端的输入流
	DataOutputStream out = null;//发送到客户端的输出流
	byte[] AESKey;
    final Base64.Encoder encoder = Base64.getEncoder();	// 将字节数组转化为base64编码
    final Base64.Decoder decoder = Base64.getDecoder();	// 将base64编码字符串转化回字节数组
   
	public Server() throws Exception
	{
		buildGUI("Server");  // 服务器端
		try
		{
			chatContent.append("监听端口号：8124\n");
			server = new ServerSocket(8124);	//创建服务器套接字对象
		}
		catch (IOException e)
		{
			chatContent.append("请确认端口号 8124 未被占用后重新运行程序！\n");
			chatContent.append("PS：也可自行更改源代码中指定的端口号\n");
			System.out.println(e);
		}   
	
		new DH_AES_HMAC();
	    try
	    {
	    	chatContent.append("等待客户端连接...\n");
	    	ftheClient = server.accept();
	    	chatContent.append("客户端已成功连接...\n");
			fout = new DataOutputStream(ftheClient.getOutputStream());
			done = true;
			
			// 生成服务端密钥对
		    Map<String,Object> keyMap1=DH_AES_HMAC.initKey();
		    // 服务端公钥
		    byte[] publicKey1=DH_AES_HMAC.getPublicKey(keyMap1);  
		    // 服务端私钥
		    byte[] privateKey1=DH_AES_HMAC.getPrivateKey(keyMap1);
		    chatContent.append("\n****************************************************\n");
		    chatContent.append("服务端公钥：\n"+encoder.encodeToString(publicKey1));
		    chatContent.append("\n服务端私钥：\n"+encoder.encodeToString(privateKey1));
			
			// 将服务端公钥发送给客户端
		    fout.write(publicKey1);
		    fout.close();
		    
		    // 接收客户端公钥
		    stheClient = server.accept();
			sin = new DataInputStream(stheClient.getInputStream());
		    byte[] clientPublicKey = sin.readAllBytes();
		    
		    // 组装服务端本地密钥，由客户端公钥和服务端私钥组合而成
		    // 此密钥即为服务端与客户端经由 DH 协议协商出的共享密钥
		    AESKey = DH_AES_HMAC.getSecretKey(clientPublicKey, privateKey1);

		    chatContent.append("\n接收到客户端发送的公钥：\n"+encoder.encodeToString(clientPublicKey));
			chatContent.append("\n由客户端公钥和服务端私钥生成的共享密钥（DH协议）：\n"+encoder.encodeToString(AESKey)+"\n");
			
	    }
	    catch(Exception rand){}
    

		while(true)
		{
			try
			{
				theClient = server.accept();
				out = new DataOutputStream(theClient.getOutputStream());
				in = new DataInputStream(theClient.getInputStream());
				done = true;
				String line;
				String check2;

				while(done)
				{
					while((line = in.readUTF())!=null)
					{
						chatContent.append("\n****************************************************\n");
						chatContent.append("接收到客户端发来的密文："+line+"\n");
						byte[] cdata = decoder.decode(line);
						if((check2 = in.readUTF())!=null)
						{
							chatContent.append("接收到客户端发来的消息认证码："+check2+"\n");
							String csum = encoder.encodeToString(DH_AES_HMAC.HMACEncode(cdata, AESKey));
							chatContent.append("经 HMAC 计算出消息认证码："+csum+"\n");
							boolean isSame = csum.equals(check2);
							chatContent.append("消息认证码是否一致："+isSame+"\n");
							if(isSame) {
								chatContent.append("此条消息完整且来源可靠...\n经 AES 解密出明文："+new String(DH_AES_HMAC.AESDecrypt(cdata, AESKey))+"\n");
							}
							else {
								chatContent.append("此条消息完整性或来源不可靠！\n");
							}
						}
					}
					in.close();
					out.close();
					theClient.close();
				}
			}
			catch (Exception e1)
			{
				chatContent.append("\n客户端关闭连接!\n");
			}	
		}
	}
	
	
	//构造图形界面
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
		this.addWindowListener(new WindowAdapter()	//匿名内部监听窗口关闭操作
	    {
			public void windowClosing(WindowEvent e)
			{
				try
				{
					out.writeUTF("\nGoodbye!");
				}
				catch (IOException e2)
				{
					System.out.println("\n服务器窗口关闭...");
				}
				finally
				{
					System.exit(0);
				}
			}
	    });
	}
   
	public void actionPerformed(ActionEvent e)
	{
		String str = sentence.getText();	//获取聊天信息栏的聊天内容
		if(str!=null&&!str.equals(""))	//如果聊天内容不为空，则发送信息
		{
			chatContent.append("\n****************************************************\n");
			chatContent.append("明文："+str+"\n");
			try
			{
				byte[] ciph = DH_AES_HMAC.AESEncrypt(str.getBytes(), AESKey);	// AES加密出密文
				String ciph64 = encoder.encodeToString(ciph);	// 将密文转换为base64
				String check64 = encoder.encodeToString(DH_AES_HMAC.HMACEncode(ciph, AESKey));
				chatContent.append("经 AES 加密出密文："+ciph64+"\n");
				chatContent.append("经 HMAC 计算出消息认证码："+check64+"\n");
				out.writeUTF(ciph64);	// 将base64编码的密文发送给客户端
				out.writeUTF(check64);	// 将base64编码的校验码发送给客户端，用作消息完整性和可靠性检验
			}
			catch (Exception e3)
			{
				chatContent.append("\n未发现客户端...\n");
			}
		}
		else
		{
			chatContent.append("\n聊天信息不能为空...\n");
		}
		sentence.setText("");	//清空聊天信息栏的内容
	}
   
	public static void main(String[] args) throws Exception
	{
		new Server();
	}
}