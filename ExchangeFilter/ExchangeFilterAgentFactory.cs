using System;
using log4net;
using Microsoft.Exchange.Data.Transport;
using Microsoft.Exchange.Data.Transport.Smtp;

namespace ExchangeFilter
{
	public class ExchangeFilterAgentFactory : SmtpReceiveAgentFactory
	{
		public static readonly ILog log = LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

		private static readonly ExchangeAttachmentFilterConfig config = new ExchangeAttachmentFilterConfig();

		public override SmtpReceiveAgent CreateAgent(SmtpServer server)
		{
			try
			{
				ExchangeAttachmentFilterConfig.GCCollect();
				return new ExchangeFilterReceiveAgent(config);
			}
			catch (Exception e)
			{
				log.Error($"ExchangeFilterAgentFactory crashed {e.Message}");
				return null;
			}

		}
	}
}
