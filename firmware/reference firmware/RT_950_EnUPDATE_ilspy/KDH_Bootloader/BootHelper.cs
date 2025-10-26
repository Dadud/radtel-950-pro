using System.IO;
using System.IO.Ports;
using System.Text;
using System.Threading;
using System.Timers;

namespace KDH_Bootloader;

internal class BootHelper
{
	private SerialPort sPInstance;

	private System.Timers.Timer baseTimer;

	private const byte PACKAGE_HEADER = 170;

	private const byte PACKAGE_END = 85;

	private const byte CMD_HANDSHAKE = 10;

	private const byte CMD_CHECKMODELTYPE = 2;

	private const byte CMD_UPDATE = 3;

	private const byte CMD_UPDATE_DATA_PACKAGES = 4;

	private const byte CMD_UPDATE_END = 69;

	private const byte CMD_INTO_BOOT = 66;

	private const byte CMD_INTO_ERASE_MODE = 238;

	private STATE bootProcessState = STATE.HandShakeStep0_0;

	private bool flagTransmitting = false;

	private bool flagRetry = false;

	private int cntRetry = 5;

	private int cntError = 3;

	private byte[] bufferTx = new byte[2048];

	private byte[] bufferRx = new byte[128];

	private int addr = 0;

	private int dataLen = 0;

	private int seed = 0;

	private long byteOfFile = 0L;

	private long cntDataByte = 0L;

	private double pecent = 0.0;

	private bool flagPTTPress = false;

	private int totalPackage = 0;

	private byte lastCmd = 0;

	private byte[] buffer = null;

	public string stateMsg = "Handshake...\r\n";

	private bool flagFileEnd = false;

	private PackageFmt packageHelper;

	public BootHelper(SerialPort sPHelper, string filePath, bool flagPTTPress)
	{
		sPInstance = sPHelper;
		baseTimer = new System.Timers.Timer();
		baseTimer.Interval = 2000.0;
		baseTimer.Elapsed += BaseTimer_Elapsed;
		baseTimer.AutoReset = true;
		baseTimer.Enabled = true;
		flagTransmitting = true;
		FileInfo fileInfo = new FileInfo(filePath);
		byteOfFile = fileInfo.Length;
		this.flagPTTPress = flagPTTPress;
		packageHelper = new PackageFmt();
		ErrorCntClr();
		STATE sTATE = STATE.HandShakeStep0_0;
	}

	public void BootLoading(SerialPort sPHelper, string filePath)
	{
		if (HandShake_0())
		{
			try
			{
				Stream stream = new FileStream(filePath, FileMode.Open);
				stream.Seek(0L, SeekOrigin.Current);
				addr = 0;
				BootLoading(stream);
			}
			catch
			{
			}
		}
	}

	private bool HandShake_0()
	{
		byte[] array = new byte[1];
		if (flagPTTPress)
		{
			bootProcessState = STATE.HandShake1;
			return true;
		}
		while (flagTransmitting)
		{
			if (!flagRetry)
			{
				switch (bootProcessState)
				{
				case STATE.HandShakeStep0_0:
					array = Encoding.ASCII.GetBytes("PROGRAMBT9000U");
					sPInstance.Write(array, 0, array.Length);
					ErrorCntClr();
					baseTimer.Start();
					bootProcessState = STATE.HandShakeStep0_1;
					break;
				case STATE.HandShakeStep0_1:
					if (sPInstance.BytesToRead >= 1)
					{
						sPInstance.Read(bufferRx, 0, 1);
						if (bufferRx[0] == 6)
						{
							ErrorCntClr();
							baseTimer.Stop();
							baseTimer.Start();
							array = Encoding.ASCII.GetBytes("UPDATE");
							sPInstance.Write(array, 0, array.Length);
							bootProcessState = STATE.HandShakeStep0_2;
						}
					}
					break;
				case STATE.HandShakeStep0_2:
					if (sPInstance.BytesToRead >= 1)
					{
						sPInstance.Read(bufferRx, 0, 1);
						if (bufferRx[0] == 6)
						{
							ErrorCntClr();
							baseTimer.Stop();
							baseTimer.Start();
							Thread.Sleep(80);
							bootProcessState = STATE.Booting_IntoBootMode;
							return true;
						}
					}
					break;
				}
			}
			else
			{
				if (cntRetry <= 0)
				{
					baseTimer.Stop();
					stateMsg += " Handshake Failed!\r\n";
					flagTransmitting = false;
					return false;
				}
				cntRetry--;
				flagRetry = false;
				stateMsg = stateMsg + " " + (5 - cntRetry) + "th Resend...\r\n";
				STATE sTATE = bootProcessState;
				STATE sTATE2 = sTATE;
				if (sTATE2 == STATE.HandShakeStep0_1)
				{
					sPInstance.Write(array, 0, array.Length);
				}
			}
		}
		return false;
	}

	private bool BootLoading(Stream s)
	{
		ushort num = 0;
		while (flagTransmitting)
		{
			switch (bootProcessState)
			{
			case STATE.Booting_IntoBootMode:
				buffer = packageHelper.Packing(66, 0, 0, null);
				sPInstance.Write(buffer, 0, buffer.Length);
				bootProcessState = STATE.Booting_WaitResponse1;
				baseTimer.Start();
				lastCmd = 66;
				seed = 0;
				dataLen = 0;
				break;
			case STATE.HandShake1:
				buffer = Encoding.ASCII.GetBytes("BOOTLOADER_V3");
				buffer = packageHelper.Packing(10, 0, (ushort)buffer.Length, buffer);
				sPInstance.Write(buffer, 0, buffer.Length);
				bootProcessState = STATE.Booting_WaitResponse1;
				baseTimer.Start();
				lastCmd = 10;
				seed = 0;
				dataLen = 0;
				break;
			case STATE.Booting_CheckModelType:
				buffer = new byte[32];
				s.Seek(992L, SeekOrigin.Begin);
				s.Read(buffer, 0, 32);
				buffer = packageHelper.Packing(2, 0, (ushort)buffer.Length, buffer);
				sPInstance.Write(buffer, 0, buffer.Length);
				bootProcessState = STATE.Booting_WaitResponse1;
				baseTimer.Start();
				lastCmd = 2;
				seed = 0;
				dataLen = 0;
				break;
			case STATE.Booting_SendPackages:
			{
				long length = s.Length;
				totalPackage = (int)(length / 1024);
				if (length % 1024 > 0)
				{
					totalPackage++;
				}
				byte[] array = new byte[2];
				if (totalPackage > 1)
				{
					array[0] = (byte)(totalPackage - 1 >> 8);
					array[1] = (byte)(totalPackage - 1);
				}
				else
				{
					array[0] = 0;
					array[1] = (byte)totalPackage;
				}
				buffer = packageHelper.Packing(4, 0, 2, array);
				sPInstance.Write(buffer, 0, buffer.Length);
				bootProcessState = STATE.Booting_WaitResponse1;
				baseTimer.Start();
				lastCmd = 4;
				s.Seek(0L, SeekOrigin.Begin);
				seed = 0;
				dataLen = 0;
				break;
			}
			case STATE.Booting_ReadFile:
			{
				int num2 = s.Read(bufferTx, 0, 1024);
				if (num2 > 0 && num2 < 1024)
				{
					flagFileEnd = true;
					for (int i = num2; i < 1024; i++)
					{
						bufferTx[i] = 0;
					}
				}
				else if (num2 == 0)
				{
					bootProcessState = STATE.Booting_End;
					break;
				}
				buffer = packageHelper.Packing(3, num++, 1024, bufferTx);
				sPInstance.Write(buffer, 0, buffer.Length);
				bootProcessState = STATE.Booting_WaitResponse1;
				baseTimer.Start();
				lastCmd = 3;
				seed = 0;
				dataLen = 0;
				break;
			}
			case STATE.Booting_End:
				buffer = packageHelper.Packing(69, 0, 0, null);
				sPInstance.Write(buffer, 0, buffer.Length);
				bootProcessState = STATE.Booting_WaitResponse1;
				baseTimer.Start();
				lastCmd = 69;
				stateMsg = stateMsg.Remove(stateMsg.LastIndexOf(' ') + 1);
				stateMsg += " 100%";
				stateMsg += " \r\nDownload Completed!";
				s.Close();
				return true;
			case STATE.Booting_WaitResponse1:
				if (sPInstance.BytesToRead >= 1)
				{
					sPInstance.Read(bufferRx, 0, 1);
					if (bufferRx[0] == 170)
					{
						seed++;
						bootProcessState = STATE.Booting_WaitResponse2;
						ErrorCntClr();
						baseTimer.Stop();
						baseTimer.Start();
					}
				}
				break;
			case STATE.Booting_WaitResponse2:
				if (sPInstance.BytesToRead >= 5)
				{
					sPInstance.Read(bufferRx, seed, 5);
					seed += 5;
					bootProcessState = STATE.Booting_WaitResponse3;
				}
				break;
			case STATE.Booting_WaitResponse3:
			{
				if (sPInstance.BytesToRead < dataLen + 2 + 1)
				{
					break;
				}
				int bytesToRead = sPInstance.BytesToRead;
				sPInstance.Read(bufferRx, seed, bytesToRead);
				packageHelper.AnalysePackage(bufferRx);
				if (!packageHelper.Verify)
				{
					break;
				}
				if (packageHelper.CommandArgs == 6)
				{
					ErrorCntClr();
					baseTimer.Stop();
					switch (packageHelper.Command)
					{
					case 66:
						stateMsg += " Entered Boot Mode Successfully!\r\n";
						bootProcessState = STATE.HandShake1;
						break;
					case 10:
						stateMsg += " Handshake Successful!\r\n";
						bootProcessState = STATE.Booting_CheckModelType;
						break;
					case 2:
						stateMsg += " Model Validation Passed!\r\n";
						stateMsg += " Download Progress: 0%";
						bootProcessState = STATE.Booting_SendPackages;
						break;
					case 4:
						bootProcessState = STATE.Booting_ReadFile;
						break;
					case 3:
						pecent = num * 100 / totalPackage;
						stateMsg = stateMsg.Remove(stateMsg.LastIndexOf(' ') + 1);
						stateMsg = stateMsg + (int)pecent + "%";
						bootProcessState = STATE.Booting_ReadFile;
						break;
					case 69:
						stateMsg = stateMsg.Remove(stateMsg.LastIndexOf(' ') + 1);
						stateMsg += " 100%";
						stateMsg += " \r\nDownload Completed!";
						s.Close();
						return true;
					}
				}
				else
				{
					switch (packageHelper.CommandArgs)
					{
					case 225:
						stateMsg += " Handshake Code Error!";
						s.Close();
						return false;
					case 226:
						stateMsg += " Data Verification Error!";
						flagRetry = true;
						break;
					case 227:
						stateMsg += " Wrong Address!";
						s.Close();
						return false;
					case 228:
						stateMsg += " Flash Write Error!";
						s.Close();
						return false;
					case 229:
						stateMsg += " Command Error!";
						s.Close();
						return false;
					case 230:
						stateMsg += " Model Mismatch!";
						s.Close();
						return false;
					}
				}
				break;
			}
			}
			if (flagRetry)
			{
				flagRetry = false;
				if (cntRetry <= 0)
				{
					stateMsg += " Failure!\r\n";
					flagTransmitting = false;
					s.Close();
					return false;
				}
				cntRetry--;
				bootProcessState = STATE.Booting_WaitResponse1;
				sPInstance.Write(buffer, 0, buffer.Length);
				seed = 0;
				dataLen = 0;
				stateMsg = stateMsg + " " + (5 - cntRetry) + "th Resend...\r\n";
			}
		}
		s.Close();
		return false;
	}

	private void ErrorCntClr()
	{
		cntError = 3;
		cntRetry = 5;
	}

	private void BaseTimer_Elapsed(object sender, ElapsedEventArgs e)
	{
		flagRetry = true;
	}
}
