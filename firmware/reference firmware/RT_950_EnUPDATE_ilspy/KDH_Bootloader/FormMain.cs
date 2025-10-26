using System;
using System.ComponentModel;
using System.Configuration;
using System.Drawing;
using System.IO;
using System.IO.Ports;
using System.Threading;
using System.Windows.Forms;
using KDH_Bootloader.Properties;

namespace KDH_Bootloader;

public class FormMain : Form
{
	private delegate void delFlashBtnDownState(bool state);

	private delegate void delPrintMessage(string message);

	private string filePath = "";

	private SerialPort sP;

	private bool flagPTTPress = false;

	private Thread ThreadBooting = null;

	private BootHelper bootHelper;

	private IContainer components = null;

	private OpenFileDialog openFileDialog;

	private TextBox tBFilePath;

	private Button btnOpenFile;

	private TextBox tBMessage;

	private Button btnDownload;

	private ComboBox cbBComPort;

	private Button btnAutoUpdate;

	private TextBox textBox1;

	private TextBox textBox2;

	public FormMain()
	{
		InitializeComponent();
		if (Settings.Default.dirpath != "" && Settings.Default.dirpath != null)
		{
			((FileDialog)openFileDialog).InitialDirectory = Settings.Default.dirpath;
		}
	}

	private void btnOpenFile_Click(object sender, EventArgs e)
	{
		//IL_0007: Unknown result type (might be due to invalid IL or missing references)
		//IL_000d: Invalid comparison between Unknown and I4
		if ((int)((CommonDialog)openFileDialog).ShowDialog() == 1)
		{
			filePath = ((FileDialog)openFileDialog).FileName;
			((Control)tBFilePath).Text = filePath;
			((FileDialog)openFileDialog).InitialDirectory = filePath;
			Settings.Default.dirpath = Path.GetDirectoryName(filePath);
			((SettingsBase)Settings.Default).Save();
		}
	}

	private void btnDownload_Click(object sender, EventArgs e)
	{
		//IL_0002: Unknown result type (might be due to invalid IL or missing references)
		//IL_000c: Expected O, but got Unknown
		//IL_00c1: Unknown result type (might be due to invalid IL or missing references)
		sP = new SerialPort();
		((Control)btnDownload).Enabled = false;
		((Control)btnAutoUpdate).Enabled = false;
		flagPTTPress = true;
		try
		{
			sP.PortName = ((Control)cbBComPort).Text;
			sP.BaudRate = 115200;
			sP.DataBits = 8;
			sP.StopBits = (StopBits)1;
			sP.Parity = (Parity)0;
			sP.DtrEnable = true;
			sP.RtsEnable = true;
			sP.Open();
		}
		catch
		{
			sP.Close();
			MessageBox.Show("Serial port opening failed!", "Error", (MessageBoxButtons)0, (MessageBoxIcon)16);
			((Control)btnDownload).Enabled = true;
			((Control)btnAutoUpdate).Enabled = true;
			return;
		}
		ThreadBooting = new Thread(TaskBooting);
		ThreadBooting.Start();
	}

	private void btn_AutoUpdate_Click(object sender, EventArgs e)
	{
		//IL_0002: Unknown result type (might be due to invalid IL or missing references)
		//IL_000c: Expected O, but got Unknown
		//IL_00c1: Unknown result type (might be due to invalid IL or missing references)
		sP = new SerialPort();
		((Control)btnDownload).Enabled = false;
		((Control)btnAutoUpdate).Enabled = false;
		flagPTTPress = false;
		try
		{
			sP.PortName = ((Control)cbBComPort).Text;
			sP.BaudRate = 115200;
			sP.DataBits = 8;
			sP.StopBits = (StopBits)1;
			sP.Parity = (Parity)0;
			sP.DtrEnable = true;
			sP.RtsEnable = true;
			sP.Open();
		}
		catch
		{
			sP.Close();
			MessageBox.Show("Serial port opening failed!", "Error", (MessageBoxButtons)0, (MessageBoxIcon)16);
			((Control)btnDownload).Enabled = true;
			((Control)btnAutoUpdate).Enabled = true;
			return;
		}
		ThreadBooting = new Thread(TaskBooting);
		ThreadBooting.Start();
	}

	private void FlashBtnDownState(bool state)
	{
		((Control)btnDownload).Enabled = state;
		((Control)btnAutoUpdate).Enabled = state;
	}

	private void PrintMessage(string msg)
	{
		((Control)tBMessage).Text = msg;
	}

	private void cbBComPort_Click(object sender, EventArgs e)
	{
		string[] portNames = SerialPort.GetPortNames();
		cbBComPort.Items.Clear();
		ObjectCollection items = cbBComPort.Items;
		object[] array = portNames;
		items.AddRange(array);
	}

	private void TaskBooting()
	{
		bootHelper = new BootHelper(sP, filePath, flagPTTPress);
		Thread thread = new Thread(TaskPrintMsg);
		thread.Start();
		bootHelper.BootLoading(sP, filePath);
		((Control)this).Invoke((Delegate)new delFlashBtnDownState(FlashBtnDownState), new object[1] { true });
		sP.Close();
		thread.Abort();
		ThreadBooting.Abort();
	}

	private void TaskPrintMsg()
	{
		while (true)
		{
			((Control)this).Invoke((Delegate)new delPrintMessage(PrintMessage), new object[1] { bootHelper.stateMsg });
		}
	}

	private void FormMain_Load(object sender, EventArgs e)
	{
		((Control)btnDownload).ForeColor = Color.Red;
		((Control)btnAutoUpdate).ForeColor = Color.Green;
		((Control)textBox1).BackColor = Color.Red;
		((Control)textBox1).Text = "Flashing mode:\r\nTurn off the power, while holding down side keys 3 and 4, turn on the power, enter the Update interface, click the [Flashing Mode] button, and wait for completion.";
		((Control)textBox2).BackColor = Color.Green;
		((Control)textBox2).Text = "Upgrade mode:\r\nTurn on the power, click the [Upgrade Mode] button, and wait for completion.";
	}

	protected override void Dispose(bool disposing)
	{
		if (disposing && components != null)
		{
			components.Dispose();
		}
		((Form)this).Dispose(disposing);
	}

	private void InitializeComponent()
	{
		//IL_0012: Unknown result type (might be due to invalid IL or missing references)
		//IL_001c: Expected O, but got Unknown
		//IL_001d: Unknown result type (might be due to invalid IL or missing references)
		//IL_0027: Expected O, but got Unknown
		//IL_0028: Unknown result type (might be due to invalid IL or missing references)
		//IL_0032: Expected O, but got Unknown
		//IL_0033: Unknown result type (might be due to invalid IL or missing references)
		//IL_003d: Expected O, but got Unknown
		//IL_003e: Unknown result type (might be due to invalid IL or missing references)
		//IL_0048: Expected O, but got Unknown
		//IL_0049: Unknown result type (might be due to invalid IL or missing references)
		//IL_0053: Expected O, but got Unknown
		//IL_0054: Unknown result type (might be due to invalid IL or missing references)
		//IL_005e: Expected O, but got Unknown
		//IL_005f: Unknown result type (might be due to invalid IL or missing references)
		//IL_0069: Expected O, but got Unknown
		//IL_006a: Unknown result type (might be due to invalid IL or missing references)
		//IL_0074: Expected O, but got Unknown
		//IL_00a8: Unknown result type (might be due to invalid IL or missing references)
		//IL_0100: Unknown result type (might be due to invalid IL or missing references)
		//IL_010a: Expected O, but got Unknown
		//IL_012a: Unknown result type (might be due to invalid IL or missing references)
		//IL_01c8: Unknown result type (might be due to invalid IL or missing references)
		//IL_023b: Unknown result type (might be due to invalid IL or missing references)
		//IL_02e8: Unknown result type (might be due to invalid IL or missing references)
		//IL_0360: Unknown result type (might be due to invalid IL or missing references)
		//IL_05aa: Unknown result type (might be due to invalid IL or missing references)
		//IL_05b4: Expected O, but got Unknown
		//IL_05b7: Unknown result type (might be due to invalid IL or missing references)
		ComponentResourceManager componentResourceManager = new ComponentResourceManager(typeof(FormMain));
		openFileDialog = new OpenFileDialog();
		tBFilePath = new TextBox();
		btnOpenFile = new Button();
		tBMessage = new TextBox();
		btnDownload = new Button();
		cbBComPort = new ComboBox();
		btnAutoUpdate = new Button();
		textBox1 = new TextBox();
		textBox2 = new TextBox();
		((Control)this).SuspendLayout();
		((FileDialog)openFileDialog).Filter = "BTF 文件|*.BTF";
		((Control)tBFilePath).Location = new Point(9, 10);
		((Control)tBFilePath).Margin = new Padding(2);
		((Control)tBFilePath).Name = "tBFilePath";
		((Control)tBFilePath).Size = new Size(312, 21);
		((Control)tBFilePath).TabIndex = 0;
		((Control)btnOpenFile).Font = new Font("宋体", 9f, (FontStyle)0, (GraphicsUnit)3, (byte)134);
		((Control)btnOpenFile).Location = new Point(322, 10);
		((Control)btnOpenFile).Margin = new Padding(2);
		((Control)btnOpenFile).Name = "btnOpenFile";
		((Control)btnOpenFile).Size = new Size(35, 20);
		((Control)btnOpenFile).TabIndex = 1;
		((Control)btnOpenFile).Text = "...";
		((ButtonBase)btnOpenFile).TextAlign = (ContentAlignment)16;
		((ButtonBase)btnOpenFile).UseVisualStyleBackColor = true;
		((Control)btnOpenFile).Click += btnOpenFile_Click;
		((Control)tBMessage).Location = new Point(9, 73);
		((Control)tBMessage).Margin = new Padding(2);
		((TextBoxBase)tBMessage).Multiline = true;
		((Control)tBMessage).Name = "tBMessage";
		((Control)tBMessage).Size = new Size(340, 187);
		((Control)tBMessage).TabIndex = 2;
		((Control)btnDownload).Location = new Point(201, 264);
		((Control)btnDownload).Margin = new Padding(2);
		((Control)btnDownload).Name = "btnDownload";
		((Control)btnDownload).Size = new Size(148, 38);
		((Control)btnDownload).TabIndex = 3;
		((Control)btnDownload).Text = "Flashing Mode";
		((ButtonBase)btnDownload).UseVisualStyleBackColor = true;
		((Control)btnDownload).Click += btnDownload_Click;
		cbBComPort.DropDownStyle = (ComboBoxStyle)2;
		((ListControl)cbBComPort).FormattingEnabled = true;
		((Control)cbBComPort).Location = new Point(9, 43);
		((Control)cbBComPort).Margin = new Padding(2);
		((Control)cbBComPort).Name = "cbBComPort";
		((Control)cbBComPort).Size = new Size(340, 20);
		((Control)cbBComPort).TabIndex = 4;
		((Control)cbBComPort).Click += cbBComPort_Click;
		((Control)btnAutoUpdate).Location = new Point(9, 264);
		((Control)btnAutoUpdate).Margin = new Padding(2);
		((Control)btnAutoUpdate).Name = "btnAutoUpdate";
		((Control)btnAutoUpdate).Size = new Size(148, 38);
		((Control)btnAutoUpdate).TabIndex = 5;
		((Control)btnAutoUpdate).Text = "Upgrade Mode";
		((ButtonBase)btnAutoUpdate).UseVisualStyleBackColor = true;
		((Control)btnAutoUpdate).Click += btn_AutoUpdate_Click;
		((Control)textBox1).ForeColor = SystemColors.WindowText;
		((Control)textBox1).Location = new Point(9, 358);
		((TextBoxBase)textBox1).Multiline = true;
		((Control)textBox1).Name = "textBox1";
		((TextBoxBase)textBox1).ReadOnly = true;
		((Control)textBox1).Size = new Size(340, 60);
		((Control)textBox1).TabIndex = 6;
		((Control)textBox1).Text = "Flashing Mode";
		((Control)textBox2).Location = new Point(9, 307);
		((TextBoxBase)textBox2).Multiline = true;
		((Control)textBox2).Name = "textBox2";
		((TextBoxBase)textBox2).ReadOnly = true;
		((Control)textBox2).Size = new Size(340, 45);
		((Control)textBox2).TabIndex = 7;
		((Control)textBox2).Text = "Upgrade Mode";
		((ContainerControl)this).AutoScaleDimensions = new SizeF(6f, 12f);
		((ContainerControl)this).AutoScaleMode = (AutoScaleMode)1;
		((Form)this).ClientSize = new Size(369, 428);
		((Control)this).Controls.Add((Control)(object)textBox2);
		((Control)this).Controls.Add((Control)(object)textBox1);
		((Control)this).Controls.Add((Control)(object)btnAutoUpdate);
		((Control)this).Controls.Add((Control)(object)cbBComPort);
		((Control)this).Controls.Add((Control)(object)btnDownload);
		((Control)this).Controls.Add((Control)(object)tBMessage);
		((Control)this).Controls.Add((Control)(object)btnOpenFile);
		((Control)this).Controls.Add((Control)(object)tBFilePath);
		((Form)this).Icon = (Icon)componentResourceManager.GetObject("$this.Icon");
		((Form)this).Margin = new Padding(2);
		((Form)this).MaximizeBox = false;
		((Control)this).Name = "FormMain";
		((Form)this).StartPosition = (FormStartPosition)1;
		((Control)this).Text = "RT-950_UPDATE_V02";
		((Form)this).Load += FormMain_Load;
		((Control)this).ResumeLayout(false);
		((Control)this).PerformLayout();
	}
}
