namespace KDH_Bootloader;

public class PackageFmt
{
	public byte Command { get; set; }

	public byte CommandArgs { get; set; }

	public bool Verify { get; set; }

	public byte[] Packing(byte cmd, ushort cmdArgs, ushort dataLen, byte[] data)
	{
		byte[] array = new byte[6 + dataLen + 2 + 1];
		array[0] = 170;
		array[1] = cmd;
		array[2] = (byte)(cmdArgs >> 8);
		array[3] = (byte)cmdArgs;
		array[4] = (byte)(dataLen >> 8);
		array[5] = (byte)dataLen;
		for (int i = 0; i < dataLen; i++)
		{
			array[i + 6] = data[i];
		}
		int num = CrcValidation(array, 1, 5 + dataLen);
		array[6 + dataLen] = (byte)(num >> 8);
		array[6 + dataLen + 1] = (byte)num;
		array[6 + dataLen + 2] = 85;
		return array;
	}

	public byte[] AnalysePackage(byte[] package)
	{
		int num = 0;
		Command = package[1];
		CommandArgs = package[2];
		CommandArgs <<= 8;
		CommandArgs |= package[3];
		num = package[4];
		num <<= 8;
		num |= package[5];
		byte[] array = new byte[num];
		for (int i = 0; i < num; i++)
		{
			array[i] = package[6 + i];
		}
		int num2 = CrcValidation(package, 1, 5 + num);
		int num3 = 0;
		num3 = package[6 + num];
		num3 <<= 8;
		num3 |= package[6 + num + 1];
		num2 &= 0xFFFF;
		num3 &= 0xFFFF;
		if (num2 == num3)
		{
			Verify = true;
		}
		else
		{
			Verify = false;
		}
		return array;
	}

	private int CrcValidation(byte[] dat, int offset, int count)
	{
		int num = 0;
		for (int i = 0; i < count; i++)
		{
			int num2 = dat[i + offset];
			num ^= num2 << 8;
			for (int j = 0; j < 8; j++)
			{
				num = (((num & 0x8000) != 32768) ? (num << 1) : ((num << 1) ^ 0x1021));
			}
		}
		return num;
	}
}
