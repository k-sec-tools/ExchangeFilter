using System.IO;
using Microsoft.Exchange.Data.Transport.Email;

namespace ExchangeFilterTests
{
	public static class Helper
	{
		public static EmailMessage LoadEmailMessage(string filePath)
		{
			using (FileStream fs = new FileStream(filePath, FileMode.Open))
			{
				byte[] buff = new byte[fs.Length];
				fs.Read(buff, 0, buff.Length);

				MemoryStream ms = new MemoryStream(buff);
				ms.Seek(0, SeekOrigin.Begin);

				return EmailMessage.Create(ms);
			}
		}
	}
}
