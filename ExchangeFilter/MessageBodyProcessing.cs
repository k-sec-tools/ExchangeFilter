using System;
using System.Text;
using Microsoft.Exchange.Data.Transport.Email;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace ExchangeFilter
{
	public sealed partial class ExchangeFilterReceiveAgent
	{
		public MessageProcessingStatusSet ProcessMessageBody(Body body)
		{
			return ProcessTextBody(body);
		}

		private MessageProcessingStatusSet ProcessTextBody(Body body)
		{
			string RegExBodyHyperLinkRgx = _exchangeAttachmentFilterConfig.hyperlinkRegEx;
			Regex hyperLinkRegex = new Regex(RegExBodyHyperLinkRgx, RegexOptions.IgnoreCase);
			Encoding encoding = GetEncodingFromString(body.CharsetName);
			var messageProcessingStatusSet = new MessageProcessingStatusSet { FurtherChecksNeeded = true };

			if (body.TryGetContentReadStream(out var memStream))
			{
				using (StreamReader streamRead = new StreamReader(memStream, encoding))
				{
					String b = streamRead.ReadToEnd();

					messageProcessingStatusSet.MatchedProcessingStatusList.Add(CheckBody(b));

					foreach (Match match in hyperLinkRegex.Matches(b))
					{
						messageProcessingStatusSet.MatchedProcessingStatusList.Add(CheckLink(match.ToString()));
					}


				}

				return messageProcessingStatusSet;
			}

			messageProcessingStatusSet.MatchedProcessingStatusList.Add(new MessageProcessingStatus(AgentModuleName.MessageBodyChecking, MessageProcessingResult.CantProcess));
			return messageProcessingStatusSet;
		}

		public static Encoding GetEncodingFromString(string encodingstring)
		{
			Encoding encoding;
			if (string.IsNullOrEmpty(encodingstring))
				return Encoding.UTF8;

			try
			{
				encoding = Encoding.GetEncoding(encodingstring);
			}
			catch (ArgumentException)
			{
				encoding = Encoding.UTF8;
			}

			return encoding;

		}

		private MessageProcessingStatus CheckBody(string body)
		{

			var regexWhiteList = _exchangeAttachmentFilterConfig.BodyWhitelistRgx;
			var regexBlackList = _exchangeAttachmentFilterConfig.BodyBlacklistRgx;
			var acBlackList = _exchangeAttachmentFilterConfig.BodyBlacklistAcWords;
			var acWhiteList = _exchangeAttachmentFilterConfig.BodyWhitelistAcWords;
			try
			{
				var lowerbody = body.ToLower();

				if (acWhiteList != null && SearchWithAhoCorasick(lowerbody, acWhiteList))
				{
					LogInfo("MessageBody whitelisted");
					return new MessageProcessingStatus(AgentModuleName.MessageBodyChecking, MessageProcessingResult.Whitelisted, "MessageBodyChecking", "body");

				}

				if (regexWhiteList != null && regexWhiteList.Any(x => Regex.IsMatch(body, x, RegexOptions.IgnoreCase)))
				{
					LogInfo("MessageBody whitelisted");
					return new MessageProcessingStatus(AgentModuleName.MessageBodyChecking, MessageProcessingResult.Whitelisted, "MessageBodyChecking", "body");
				}

				if (acBlackList != null && SearchWithAhoCorasick(lowerbody, acBlackList))
				{
					LogInfo("MessageBody blacklisted");
					return new MessageProcessingStatus(AgentModuleName.MessageBodyChecking, MessageProcessingResult.Blacklisted, "MessageBodyChecking", "body");

				}

				if (regexBlackList != null && regexBlackList.Any(x => Regex.IsMatch(body, x, RegexOptions.IgnoreCase)))
				{
					LogInfo("MessageBody blacklisted");
					return new MessageProcessingStatus(AgentModuleName.MessageBodyChecking, MessageProcessingResult.Blacklisted, "MessageBodyChecking", "body");
				}


			}

			catch (Exception ex)
			{
				LogError($"Exception while body processing {ex.Message}");
				return new MessageProcessingStatus(AgentModuleName.MessageBodyChecking, MessageProcessingResult.CantProcess, "MessageBodyChecking", "body");
			}


			return new MessageProcessingStatus(AgentModuleName.MessageBodyChecking, MessageProcessingResult.NoMatch, "MessageBodyChecking", "body");
		}

		private MessageProcessingStatus CheckLink(string link)
		{

			LogInfo("parse link : " + link);

			if (CheckIsWhitelistedUrl(link))
			{
				LogInfo($"Link: {link} is whitelisted");
				return new MessageProcessingStatus(AgentModuleName.UrlChecking, MessageProcessingResult.Whitelisted, "UrlChecking", link);
			}

			try
			{
				var uri = new Uri(link);
				string pathpart = uri.LocalPath.ToLower();
				if (_exchangeAttachmentFilterConfig.HyperlinkBlacklistPathParts.Any(s => pathpart.Contains(s)))
				{
					LogInfo($"Suspicious Hyperlink {link}");
					return new MessageProcessingStatus(AgentModuleName.UrlChecking, MessageProcessingResult.Blacklisted, "UrlChecking", link);
				}
			}
			catch (Exception)
			{
				try
				{
					var uri = new Uri($"updatedbyagent://{link}");
					string pathpart = uri.LocalPath.ToLower();
					if (_exchangeAttachmentFilterConfig.HyperlinkBlacklistPathParts.Any(s => pathpart.Contains(s)))
					{
						LogInfo($"Suspicious Hyperlink {link}");
						return new MessageProcessingStatus(AgentModuleName.UrlChecking, MessageProcessingResult.Blacklisted, "UrlChecking", link);
					}
				}
				catch (Exception e)
				{
					LogError($"Exception: cant process hyperlink as URI {link}: {e.Message}");
				}
			}

			if (_exchangeAttachmentFilterConfig.HyperlinkBlacklistRgx.Any(f => Regex.IsMatch(link, f, RegexOptions.IgnoreCase)))
			{
				LogInfo($"Hyperlink blacklisted with regexp {link}");
				return new MessageProcessingStatus(AgentModuleName.UrlChecking, MessageProcessingResult.Blacklisted, "UrlChecking", link);
			}

			return new MessageProcessingStatus(AgentModuleName.UrlChecking, MessageProcessingResult.NoMatch, "UrlChecking", link);

		}

		private bool CheckIsWhitelistedUrl(string url)
		{
			var regexWhitelist = _exchangeAttachmentFilterConfig.HyperlinkWhitelistRgx;

			try
			{
				if (regexWhitelist != null)
				{
					if (regexWhitelist.Any(x => Regex.IsMatch(url.Trim(), x, RegexOptions.IgnorePatternWhitespace | RegexOptions.IgnoreCase)))
					{
						return true;
					}
					return false;
				}

				LogInfo("Whitelist is empty!");
				return false;
			}
			catch (Exception ex)
			{
				LogError($"Something went wrong with your Whitelist file settings. {ex.Message}");
				return false;
			}
		}

		public static string BodyToString(Body body)
		{
			var bodyReadStream = body.GetContentReadStream();
			Encoding encoding = GetEncodingFromString(body.CharsetName);
			using (var ms = new MemoryStream())
			{
				var buffer = new byte[32768];
				int read;
				while ((read = bodyReadStream.Read(buffer, 0, buffer.Length)) > 0)
				{
					ms.Write(buffer, 0, read);
				}
				ms.Position = 0;

				return encoding.GetString(ms.ToArray());
			}
		}
	}
}
