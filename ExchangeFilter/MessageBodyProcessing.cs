using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Exchange.Data.Transport.Email;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using HtmlAgilityPack;

namespace ExchangeFilter
{
    public sealed partial class ExchangeFilterReceiveAgent
    {

        private MessageProcessingStatusSet ProcessMessageBody(Body body)
        {
            string RegExBodyHyperLinkRgx = _exchangeAttachmentFilterConfig.hyperlinkRegEx;
            Regex hyperLinkRegex = new Regex(RegExBodyHyperLinkRgx, RegexOptions.IgnoreCase);
            Stream memStream;
            Encoding encoding = GetEncodingFromString(body.CharsetName);
            var messageProcessingStatusSet = new MessageProcessingStatusSet { FurtherChecksNeeded = true };

            if (body.TryGetContentReadStream(out memStream))
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
            catch (System.ArgumentException)
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

        public List<string> BodyToStringList(Body body)
        {
            Stream memStream;
            Encoding encoding = GetEncodingFromString(body.CharsetName);
            var ret = new List<string>();

            if (body.TryGetContentReadStream(out memStream))
            {
                using (StreamReader streamRead = new StreamReader(memStream, encoding))
                {
                    String b = streamRead.ReadToEnd();
                    string res = b;
                    try
                    {
                        HtmlDocument htmlDoc = new HtmlDocument();
                        htmlDoc.LoadHtml(b);
                        res = htmlDoc.DocumentNode.InnerText;
                    }
                    catch (Exception ex)
                    {
                        LogError($"Exception while parse as html: {ex.Message}");
                        res = b;
                    }

                    ret = res.Split(new Char[] { ',', '\\', '\n', ' ', '.', '"', '\'' },
                        StringSplitOptions.RemoveEmptyEntries).Distinct().OrderBy(q => q).ToList();
                }

            }

            return ret;
        }
    }
}
