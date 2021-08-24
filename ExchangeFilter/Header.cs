using System.Collections.Generic;
using Microsoft.Exchange.Data.Mime;

namespace ExchangeFilter
{
	public class Header
	{
		public string Name { get; set; }
		public string Value { get; set; }
		public List<string> ValuesList { get; set; }
		public HeaderValueTypeEnum ValueType { get; set; }

		public Header()
		{
			Name = null;
			Value = null;
			ValuesList = new List<string>();
			ValueType = HeaderValueTypeEnum.Wildcard;
		}

		public static AsciiTextHeader GetMimeHeaderFromAgentHeader(Header header)
		{
			return new AsciiTextHeader(header.Name, header.Value);
		}

		public enum HeaderValueTypeEnum
		{
			Wildcard = 0,
			Regex = 1,
		}
	}


	public class AgentHeaders
	{
		public Header SusupiciousMailHeader { get; set; }
		public Header ProcessedMailHeader { get; set; }
		public List<Header> FilterHeadersWhiteList { get; set; }
		public List<Header> FilterHeadersBlackList { get; set; }

		public AgentHeaders()
		{
			SusupiciousMailHeader = new Header();
			ProcessedMailHeader = new Header();
			FilterHeadersWhiteList = new List<Header>();
			FilterHeadersBlackList = new List<Header>();
		}
	}

}
