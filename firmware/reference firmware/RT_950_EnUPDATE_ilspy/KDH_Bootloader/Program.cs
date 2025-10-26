using System;
using System.Windows.Forms;

namespace KDH_Bootloader;

internal static class Program
{
	[STAThread]
	private static void Main()
	{
		Application.EnableVisualStyles();
		Application.SetCompatibleTextRenderingDefault(false);
		Application.Run((Form)(object)new FormMain());
	}
}
