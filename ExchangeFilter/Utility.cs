using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using Microsoft.Exchange.Data.Mime;
using libyaraNET;
using SevenZip;

namespace ExchangeFilter
{

	public sealed partial class ExchangeFilterReceiveAgent
	{
		private readonly ExchangeAttachmentFilterConfig _exchangeAttachmentFilterConfig;

		public MessageProcessingStatus FilenameFilterStatus(string fileName)
		{
			// whitelisted
			if (_exchangeAttachmentFilterConfig.AttachmentsWhitelist.Any(f => Regex.IsMatch(fileName, WildcardToRegex(f), RegexOptions.IgnoreCase)))
				return new MessageProcessingStatus(AgentModuleName.FilenameChecking, MessageProcessingResult.Whitelisted, $"{fileName} whitelisted by filename", fileName);
			// blacklisted
			if (_exchangeAttachmentFilterConfig.AttachmentsBlacklist.Any(f => Regex.IsMatch(fileName, WildcardToRegex(f), RegexOptions.IgnoreCase)))
				return new MessageProcessingStatus(AgentModuleName.FilenameChecking, MessageProcessingResult.Blacklisted, $"{fileName} blacklisted by filename", fileName);

			return new MessageProcessingStatus(AgentModuleName.FilenameChecking, MessageProcessingResult.NoMatch, $"{fileName} no match with filename", fileName);
		}

		public List<MessageProcessingStatus> ProcessEmailAddresses(string sender, List<string> recipientsList)
		{
			var resultList = new List<MessageProcessingStatus>();
			try
			{
				if (_exchangeAttachmentFilterConfig.SendersWhitelist.Any(f => Regex.IsMatch(sender, WildcardToRegex(f), RegexOptions.IgnoreCase)))
					resultList.Add(new MessageProcessingStatus(AgentModuleName.EmailAddressChecking, MessageProcessingResult.Whitelisted, $"whitelisted sender {sender}"));
				if (_exchangeAttachmentFilterConfig.SendersBlacklist.Any(f => Regex.IsMatch(sender, WildcardToRegex(f), RegexOptions.IgnoreCase)))
					resultList.Add(new MessageProcessingStatus(AgentModuleName.EmailAddressChecking, MessageProcessingResult.Blacklisted, $"blacklisted sender {sender}"));

				foreach (var recipient in recipientsList)
				{
					if (_exchangeAttachmentFilterConfig.RecipientsWhitelist.Any(f => Regex.IsMatch(recipient, WildcardToRegex(f), RegexOptions.IgnoreCase)))
						resultList.Add(new MessageProcessingStatus(AgentModuleName.EmailAddressChecking, MessageProcessingResult.Whitelisted, $"whitelisted recipient {recipient}"));
					if (_exchangeAttachmentFilterConfig.RecipientsBlacklist.Any(f => Regex.IsMatch(recipient, WildcardToRegex(f), RegexOptions.IgnoreCase)))
						resultList.Add(new MessageProcessingStatus(AgentModuleName.EmailAddressChecking, MessageProcessingResult.Blacklisted, $"blacklisted recipient {recipient}"));
				}
			}
			catch (Exception ex)
			{
				resultList.Add(new MessageProcessingStatus(AgentModuleName.EmailAddressChecking, MessageProcessingResult.CantProcess, "cant process email"));
				LogError($"Cant process emails, sender: {sender}, recipients: {string.Join(", ", recipientsList.ToArray())}, ex.message: {ex.Message}");
			}

			if (resultList.Count == 0)
				resultList.Add(new MessageProcessingStatus(AgentModuleName.EmailAddressChecking, MessageProcessingResult.NoMatch));

			return resultList;

		}

		public bool IsRecipientInbound(string toRecipient)
		{
			return _exchangeAttachmentFilterConfig.InternalDomains.Any(
					f => Regex.IsMatch(toRecipient, WildcardToRegex(f), RegexOptions.IgnoreCase));
		}

		public bool StringListContainsString(string str, List<string> list)
		{
			return list.Any(
					f => Regex.IsMatch(str, WildcardToRegex(f), RegexOptions.IgnoreCase));
		}

		public bool IsArchive(string fileName, byte[] fileBytes)
		{
			var byName = _exchangeAttachmentFilterConfig.ArchiveFileTypes.Any(
							f =>Regex.IsMatch(fileName, WildcardToRegex(f), RegexOptions.IgnoreCase));
			bool byExtractor;
			try
			{
				using (var ext = new SevenZip.SevenZipExtractor(new MemoryStream(fileBytes)))
				{
					byExtractor = ext.Check();
				}
			}
			catch (Exception)
			{
				byExtractor = false;
			}

			return (byName || byExtractor);
		}


        public List<MessageProcessingStatus> ProcessArchiveBytes(byte[] archiveBytes, string attachmentFileName, string entryHash, int currentDepth, List<string> possiblePasswordsStringList)
        {
            return ProcessArchiveBytesViaSevenZip(archiveBytes, currentDepth + 1, attachmentFileName, possiblePasswordsStringList);
        }

        private List<MessageProcessingStatus> ArchiveBytesProcessing(int currentDepth, string archiveName, List<string> possiblePasswordsStringList,
            byte[] archiveBytes, int totalSize, MD5 md5, string password = null)
        {
            var result = new MessageProcessingStatus(AgentModuleName.ArchiveProcessing);
            var results = new List<MessageProcessingStatus> { result };

            if (password == null)
            {
                using (var abms = new MemoryStream(archiveBytes))
                using (var extractor =
                    new SevenZip.SevenZipExtractor(abms))
                {
                    results.AddRange(ProcessExtractor(currentDepth, archiveName, possiblePasswordsStringList, extractor,
                        totalSize, md5));
                }
            }
            else
            {
                using (var abms = new MemoryStream(archiveBytes))
                using (var extractor =
                    new SevenZip.SevenZipExtractor(abms, password))
                {
                    results.AddRange(ProcessExtractor(currentDepth, archiveName, possiblePasswordsStringList, extractor,
                        totalSize, md5));
                }
            }




            return results;
        }


		private List<MessageProcessingStatus> ProcessExtractor(int currentDepth, string archiveName, List<string> possiblePasswordsStringList,
			SevenZipExtractor extractor, int totalSize, MD5 md5)
		{

			var stopwatch1 = new Stopwatch();
			stopwatch1.Start();

			var result = new MessageProcessingStatus(AgentModuleName.ArchiveProcessing);
			var results = new List<MessageProcessingStatus> { result };
			for (var cnt = 0; cnt <= extractor.FilesCount - 1; cnt++)
			{
				var entrySize = Convert.ToInt32(extractor.ArchiveFileData[cnt].Size);
				var entryName = extractor.ArchiveFileData[cnt].FileName;
				totalSize += entrySize;
				if ((entrySize / 1024 <=
					 _exchangeAttachmentFilterConfig.AttachmentSizeThreshold) &&
					(totalSize / 1024 <= _exchangeAttachmentFilterConfig
						.AttachmentUnarchivedSizeThreshold))
				{
					using (var stream = new MemoryStream())
					{
						extractor.ExtractFile(cnt, stream);
						var md5hash = BitConverter.ToString(md5.ComputeHash(stream))
							.Replace("-", string.Empty);

						if (entryName != null)
						{
							results.Add(FilenameFilterStatus(entryName));
						}
						else
						{
							entryName = $"fakefilename {md5hash}";
							LogInfo($"Archive entry process, cant read filename, md5: {entryName}");
						}

						results.AddRange(ProcessArchiveEntry(entryName, StreamToByteArray(stream),
							md5hash, currentDepth + 1, possiblePasswordsStringList));
					}
				}
				else
				{

					LogInfo($"Archive or entry too big, processing stopped - {entryName}");
					results.Add(new MessageProcessingStatus(AgentModuleName.ArchiveProcessing,
						MessageProcessingResult.CantProcess, $"Too big archive/entry {entryName}",
						archiveName));
					break;
				}
			}
			stopwatch1.Stop();
			return results;
		}

		private List<MessageProcessingStatus> ProcessArchiveBytesViaSevenZip(byte[] archiveBytes, int currentDepth, string archiveName, List<string> possiblePasswordsStringList)
		{
			var result = new MessageProcessingStatus(AgentModuleName.ArchiveProcessing);
			var results = new List<MessageProcessingStatus> { result };
			var stopwatch = new Stopwatch();

			if (currentDepth <= _exchangeAttachmentFilterConfig.AttachmentArchiveDepth)
			{
				try
				{
					using (var abms = new MemoryStream(archiveBytes))
					using (var extractor = new SevenZip.SevenZipExtractor(abms))
					{
						var md5 = MD5.Create();
						var totalSize = 0;
						stopwatch.Start();
						if (ExtractorCheck(extractor))
						{
							results.AddRange(ArchiveBytesProcessing(currentDepth, archiveName, possiblePasswordsStringList, archiveBytes, totalSize, md5));
						}
						else
						{
							LogInfo($"{archiveName} check failed, probably encrypted");
							try
							{

								if (IsArchiveEncrypted(extractor))
								{
									string[] entrynames = new string[extractor.ArchiveFileNames.Count];
									try
									{
										extractor.ArchiveFileNames.CopyTo(entrynames, 0);
									}
									catch (Exception e)
									{
										LogError($"cant read entrynames in {archiveName}: {e.Message}");
									}
									LogInfo($"archive {archiveName} is encrypted, entries: {string.Join(",", entrynames)}");
									try
									{ //bruteforce


										var cnt = 0;
										foreach (var possiblePassword in possiblePasswordsStringList)
										{
											try
											{
												cnt++;
												using (var archivestream = new MemoryStream(archiveBytes))
												using (var extractorpass =
													new SevenZip.SevenZipExtractor(archivestream, possiblePassword))
												{
													if (ExtractorCheck(extractorpass))
													//if (extractorpass.Check())
													{
														
														LogInfo($"archive {archiveName} password in message body: {possiblePassword}");
														var plist = new List<string> { possiblePassword };
														results.AddRange(ArchiveBytesProcessing(currentDepth, archiveName, plist, archiveBytes, totalSize, md5, possiblePassword));
														break;
													}
												}

											}
											catch (Exception e)
											{
												LogError($"cant bruteforce {archiveName}: {e.Message}");
												if (_exchangeAttachmentFilterConfig.BlockUncheckedArchives)
													results.Add(new MessageProcessingStatus(AgentModuleName.ArchiveProcessing,
														MessageProcessingResult.CantProcess, $"exception: Cant process archive {archiveName} correctly, check failed"));
											}

										}
										LogInfo("");
									}
									catch (Exception e)
									{
										LogError($"cant bruteforce {archiveName}: {e.Message}");
										if (_exchangeAttachmentFilterConfig.BlockUncheckedArchives)
											results.Add(new MessageProcessingStatus(AgentModuleName.ArchiveProcessing,
												MessageProcessingResult.CantProcess, $"exception: Cant process archive {archiveName} correctly, check failed"));
									}
								}
								else
								{
									if (_exchangeAttachmentFilterConfig.BlockUncheckedArchives)
										results.Add(new MessageProcessingStatus(AgentModuleName.ArchiveProcessing,
											MessageProcessingResult.CantProcess, $"exception: Cant process archive {archiveName} correctly, check failed"));
								}

							}
							catch (Exception e)
							{
								LogError($"{e.Message} {e.StackTrace}");
								if (_exchangeAttachmentFilterConfig.BlockUncheckedArchives)
									results.Add(new MessageProcessingStatus(AgentModuleName.ArchiveProcessing,
										MessageProcessingResult.CantProcess, $"exception: Cant process archive {archiveName} correctly: {e.Message}"));
							}
						}
					}
				}
				catch (Exception e)
				{
					LogError($"{e.Message} {e.StackTrace}");
					if (_exchangeAttachmentFilterConfig.BlockUncheckedArchives)
						results.Add(new MessageProcessingStatus(AgentModuleName.ArchiveProcessing, MessageProcessingResult.CantProcess,
							$"exception: Cant process archive {archiveName} correctly: {e.Message}"));
				}
			}
			else
			{
				results.Add(new MessageProcessingStatus(AgentModuleName.ArchiveProcessing, MessageProcessingResult.CantProcess, "Depth limit reached"));
			}

			//result = GetWorstStatusFromList(results, AgentModuleName.ArchiveProcessing);
			if (stopwatch.IsRunning)
				stopwatch.Stop();
			return results;
		}
		private string MessageProcessingStatusToString(MessageProcessingStatus status)
		{
			return
				$"{status.AgentModuleName.ToString()}:{status.ObjectName}:{status.Comment}:{status.Result.ToString()}";
		}

        private bool IsArchiveEncrypted(SevenZipExtractor extractor)
        {
            var encrypted = false;
            foreach (var afileData in extractor.ArchiveFileData)
            {
                if (afileData.Encrypted)
                {
                    encrypted = true;
                    break;
                }
            }

            if (!encrypted)
            {
                foreach (var property in _exchangeAttachmentFilterConfig.ArchiveEncryptedProperties)
                {
                    foreach (var archiveProperty in extractor.ArchiveProperties)
                    {
                        if (archiveProperty.Name.ToLower() == property.Name)
                        {
                            encrypted |= Regex.IsMatch(archiveProperty.Value.ToString(), WildcardToRegex(property.Value), RegexOptions.IgnoreCase);
                        }
                        if (encrypted) break;
                    }
                    if (encrypted) break;
                }
            }


            return encrypted;
        }

		private List<MessageProcessingStatus> ProcessArchiveEntry(string filename, byte[] entryBytes, string entryHash, int currentDepth, List<string> possiblePasswordsStringList)
        {
            var resultsList = new List<MessageProcessingStatus>();


            if (_exchangeAttachmentFilterConfig.AttachmentSizeThreshold > entryBytes.Length / 1024 &
                currentDepth <= _exchangeAttachmentFilterConfig.AttachmentArchiveDepth)
            {
                resultsList.AddRange(ProcessFileBytes(entryBytes, filename, entryHash, possiblePasswordsStringList));
            }
            else
            {
                LogInfo($"Archive processing: entry {filename}, md {entryHash} is too big, {entryBytes.Length} kb, skipping");
                resultsList.Add(new MessageProcessingStatus(AgentModuleName.ArchiveProcessing, MessageProcessingResult.NoMatch,
                    $"entry {filename}, md {entryHash} is too big, {entryBytes.Length} kb", filename));
            }


            return resultsList;
        }
		
		public MessageProcessingStatus ProcessMessageSubject(string subject)
		{
			var regexWhiteList = _exchangeAttachmentFilterConfig.SubjectWhitelistRgx;
			var regexBlackList = _exchangeAttachmentFilterConfig.SubjectBlacklistRgx;
			var acBlackList = _exchangeAttachmentFilterConfig.SubjectBlacklistAcWords;
			var acWhiteList = _exchangeAttachmentFilterConfig.SubjectWhitelistAcWords;

			var lowersubject = subject.ToLower();

			if (acWhiteList != null && SearchWithAhoCorasick(lowersubject, acWhiteList))
			{
				LogInfo($"{subject} message subject whitelisted");
				return new MessageProcessingStatus(AgentModuleName.MessageSubjectChecking, MessageProcessingResult.Whitelisted);

			}

			if (regexWhiteList != null && regexWhiteList.Any(x => Regex.IsMatch(subject, x, RegexOptions.IgnoreCase)))
			{
				LogInfo($"{subject} message subject whitelisted");
				return new MessageProcessingStatus(AgentModuleName.MessageSubjectChecking, MessageProcessingResult.Whitelisted);
			}

			if (acBlackList != null && SearchWithAhoCorasick(lowersubject, acBlackList))
			{
				LogInfo($"{subject} message subject blacklisted");
				return new MessageProcessingStatus(AgentModuleName.MessageSubjectChecking, MessageProcessingResult.Blacklisted);

			}

			if (regexBlackList != null && regexBlackList.Any(x => Regex.IsMatch(subject, x, RegexOptions.IgnoreCase)))
			{
				LogInfo($"{subject} message subject blacklisted");
				return new MessageProcessingStatus(AgentModuleName.MessageSubjectChecking, MessageProcessingResult.Blacklisted);
			}
			return new MessageProcessingStatus(AgentModuleName.MessageSubjectChecking, MessageProcessingResult.NoMatch);
		}

        public List<MessageProcessingStatus> ProcessMessageHeaders(HeaderList headerslist)
        {
            var resultList = new List<MessageProcessingStatus>();
            foreach (var filterHeader in _exchangeAttachmentFilterConfig.AgentHeaders.FilterHeadersBlackList)
            {
                resultList.AddRange(SearchSuspHeader(filterHeader, headerslist, MessageProcessingResult.Blacklisted));
            }

            foreach (var filterHeader in _exchangeAttachmentFilterConfig.AgentHeaders.FilterHeadersWhiteList)
            {
                resultList.AddRange(SearchSuspHeader(filterHeader, headerslist, MessageProcessingResult.Whitelisted));
            }

            return resultList;
        }

		public List<MessageProcessingStatus> ProcessMessageId(string messageId)
		{
			var resultList = new List<MessageProcessingStatus>();

			if (StringListContainsString(messageId, _exchangeAttachmentFilterConfig.MessageIDsWhiteList.ToList()))
				resultList.Add(new MessageProcessingStatus(AgentModuleName.MessageIdChecking_List, MessageProcessingResult.Whitelisted,
					"whitelisted by messageid-list"));
			if (StringListContainsString(messageId, _exchangeAttachmentFilterConfig.MessageIDsBlackList.ToList()))
				resultList.Add(new MessageProcessingStatus(AgentModuleName.MessageIdChecking_List, MessageProcessingResult.Blacklisted,
					"blacklisted by messageid-list"));
			if (StringListContainsString(messageId, _exchangeAttachmentFilterConfig.MessageIDsNativeList.ToList()))
				resultList.Add(new MessageProcessingStatus(AgentModuleName.MessageIdChecking_Native, MessageProcessingResult.Whitelisted,
					"whitelisted by messageid-native"));

			if (resultList.Count == 0)
				resultList.Add(new MessageProcessingStatus(AgentModuleName.EmailAddressChecking, MessageProcessingResult.NoMatch));

			return resultList;
		}

		private IEnumerable<MessageProcessingStatus> ProcessSmtpSession(IPAddress remoteEndpointIPAddress, IPAddress lastExternalIPAddress, long sessionId)
		{

			var resultList = new List<MessageProcessingStatus>();
			if (remoteEndpointIPAddress == null)
			{
				resultList.Add(new MessageProcessingStatus(AgentModuleName.SmtpSessionChecking_Internal, MessageProcessingResult.CantProcess,
					"Cant process SMTP session: smtpSession.remoteEndpointAddress is null"));
				LogInfo("Cant process SMTP session: smtpSession.remoteEndpointAddress is null");

				return resultList;
			}

			var isInternal = false;
			var isWhiteListed = false;
			var isBlackListed = false;

			try
			{
				foreach (var subnet in _exchangeAttachmentFilterConfig.InternalSubnets)
				{
					isInternal = isInternal || IpAddressAnalysys.IsIpAddressInSubnet(remoteEndpointIPAddress, subnet);
				}
				foreach (var subnet in _exchangeAttachmentFilterConfig.SubnetsWhiteList)
				{
					isWhiteListed = isWhiteListed || IpAddressAnalysys.IsIpAddressInSubnet(remoteEndpointIPAddress, subnet);
				}
				foreach (var subnet in _exchangeAttachmentFilterConfig.SubnetsBlacklist)
				{
					isBlackListed = isBlackListed || IpAddressAnalysys.IsIpAddressInSubnet(remoteEndpointIPAddress, subnet);
				}
			}
			catch (Exception ex)
			{
				resultList.Add(new MessageProcessingStatus(AgentModuleName.SmtpSessionChecking_Internal, MessageProcessingResult.CantProcess,
					$"Cant process SMTP session: {ex.Message}"));
				LogError($"Cant process SMTP session: {ex.Message}");

			}

			if (isInternal) resultList.Add(new MessageProcessingStatus(AgentModuleName.SmtpSessionChecking_Internal, MessageProcessingResult.Whitelisted,
				 $"Internal RemoteEndPoint: {lastExternalIPAddress}", $"SmtpSession:{sessionId}"));
			if (isWhiteListed) resultList.Add(new MessageProcessingStatus(AgentModuleName.SmtpSessionChecking_List, MessageProcessingResult.Whitelisted,
				$"Whitelisted RemoteEndPoint: {lastExternalIPAddress}", $"SmtpSession:{sessionId}"));
			if (isBlackListed) resultList.Add(new MessageProcessingStatus(AgentModuleName.SmtpSessionChecking_List, MessageProcessingResult.Blacklisted,
				$"Blacklisted RemoteEndPoint: {lastExternalIPAddress}", $"SmtpSession:{sessionId}"));
			if (!(isBlackListed || isWhiteListed || isInternal))
			{
				resultList.Add(new MessageProcessingStatus(AgentModuleName.SmtpSessionChecking_List, MessageProcessingResult.NoMatch,
					$"NoMatch RemoteEndPoint: {lastExternalIPAddress}", $"SmtpSession:{sessionId}"));
				resultList.Add(new MessageProcessingStatus(AgentModuleName.SmtpSessionChecking_Internal, MessageProcessingResult.NoMatch,
					$"NoMatch RemoteEndPoint: {lastExternalIPAddress}", $"SmtpSession:{sessionId}"));
			}
			return resultList;
		}

        private List<MessageProcessingStatus> SearchSuspHeader(Header filterHeader, HeaderList headerslist, MessageProcessingResult awaitingResult)
        {
            var resultList = new List<MessageProcessingStatus>();

            var nameMatches = headerslist.FindAll(filterHeader.Name.ToLower()).ToList();

            if (nameMatches.Count > 0)
            {
                foreach (var matchedHeader in nameMatches)
                {
                    var tmpresult = new MessageProcessingStatus(AgentModuleName.MessageHeadersChecking,
                            MessageProcessingResult.NoMatch)
                        { ObjectName = matchedHeader.Name };
                    switch (filterHeader.ValueType)
                    {
                        case Header.HeaderValueTypeEnum.Wildcard:
                            tmpresult.Result = filterHeader.ValuesList.Any(x => Regex.IsMatch(matchedHeader.Name, WildcardToRegex(filterHeader.Name), RegexOptions.IgnoreCase) &&
                                Regex.IsMatch(matchedHeader.Value, WildcardToRegex(x), RegexOptions.IgnoreCase)) ? awaitingResult : MessageProcessingResult.NoMatch;
                            break;
                        case Header.HeaderValueTypeEnum.Regex:
                            tmpresult.Result = filterHeader.ValuesList.Any(x => Regex.IsMatch(matchedHeader.Name, WildcardToRegex(filterHeader.Name), RegexOptions.IgnoreCase) &&
                                Regex.IsMatch(matchedHeader.Value, x, RegexOptions.IgnoreCase)) ? awaitingResult : MessageProcessingResult.NoMatch;
                            break;
                    }
                    //regexWhiteList.Any(x => Regex.IsMatch(subject, x, RegexOptions.IgnoreCase))
                    resultList.Add(tmpresult);


                }

            }

            return resultList;
        }


		public static string WildcardToRegex(string wildcardString)
		{
			return "^" + Regex.Escape(wildcardString).Replace("\\*", ".*").Replace("\\?", ".") + "$";
		}

		private string StatusListToString(List<MessageProcessingStatus> statusList)
		{
			string result = null;
			foreach (var status in statusList)
			{
				result += MessageProcessingStatusToString(status);
				result += ";";
			}

			return result;
		}

		private bool SearchWithAhoCorasick(string text, IEnumerable<string> words)
		{
			Trie trie = new Trie();

			// add words
			foreach (var word in words)
			{
				trie.Add(word);
			}
			// build search tree
			trie.Build();



			// find words
			return trie.Find(text).Any();
		}

		private static byte[] StreamToByteArray(Stream stream)
		{
			if (stream is MemoryStream memoryStream)
			{
				return memoryStream.ToArray();
			}

			// Jon Skeet's accepted answer 
			return ReadFully(stream);
		}

		private static byte[] ReadFully(Stream input)
		{
			using (MemoryStream ms = new MemoryStream())
			{
				input.CopyTo(ms);
				return ms.ToArray();
			}
		}


		private MessageProcessingStatus GetYaraQSByteArrayMPStatus(byte[] buffer, string fileName, string rulesPath, bool fastScanFlag = true)
		{
			var stopwatch = new Stopwatch();
			stopwatch.Start();

			try
			{
				List<ScanResult> scanResults = QuickScan.Memory(buffer, rulesPath, fastScanFlag ? ScanFlags.Fast : ScanFlags.None);
				stopwatch.Stop();
				//var elapsedquick = stopwatch.ElapsedMilliseconds;
				if (scanResults.Any())
				{
					List<string> matchingRules = scanResults.Select(res => res.MatchingRule.Identifier).ToList();
					if (matchingRules.Count > 0)
					{
						string result = string.Join("|", matchingRules.ToArray());
						return new MessageProcessingStatus(AgentModuleName.YaraFileChecking,
							MessageProcessingResult.Blacklisted, $"Yara got {scanResults.Count} matches, rules: {result}", fileName);
					}

					return new MessageProcessingStatus(AgentModuleName.YaraFileChecking,
							MessageProcessingResult.Blacklisted, $"Yara got {scanResults.Count} matches", fileName);
				}

				return new MessageProcessingStatus(AgentModuleName.YaraFileChecking,
						MessageProcessingResult.NoMatch, "Yara matches not found", fileName);
			}
			catch (Exception ex)
			{
				stopwatch.Stop();
				var elapsedquick = stopwatch.ElapsedMilliseconds;
				LogError($"YaraQS Error: {ex.Message}");
				return new MessageProcessingStatus(AgentModuleName.YaraFileChecking, MessageProcessingResult.CantProcess, $"Yara caught exception in {elapsedquick}ms: {ex.Message}", fileName);
			}

		}


        private bool ExtractorCheck(SevenZipExtractor extractor)
        {
            var res = true;

            if ((extractor.UnpackedSize / 1024 <=
                 _exchangeAttachmentFilterConfig.AttachmentSizeThreshold))
            {
                try
                {
                    if (extractor.ArchiveFileData.FirstOrDefault(x => x.IsDirectory == false).FileName == null)
                    {
                        LogInfo("Empty archive");
                        return true;
                    }
                    using (var stream = new MemoryStream())
                    {
                        extractor.ExtractFile(extractor.ArchiveFileData.FirstOrDefault(x => x.IsDirectory == false).Index, stream);
                        if (stream.Length == 0) res = false;
                    }
                }
                catch (Exception e)
                {
                    res = false;
                    LogError($"Cant check extractor: {e.Message}");
                }
            }
            else
            {
                res = false;
                LogError($"Cant check extractor: unpacked size {extractor.UnpackedSize} more than threshold {_exchangeAttachmentFilterConfig.AttachmentSizeThreshold}");
            }


            return res;
        }
		private bool GetYaraQSByteArrayBool(byte[] buffer, string rulesPath)
		{
			var stopwatch = new Stopwatch();
			stopwatch.Start();
			try
			{
				List<ScanResult> scanResults = QuickScan.Memory(buffer, rulesPath, ScanFlags.Fast);
				stopwatch.Stop();

				if (scanResults.Any())
				{
					return true;
				}
				return false;
			}
			catch (Exception ex)
			{
				stopwatch.Stop();
				var elapsedquick = stopwatch.ElapsedMilliseconds;
				LogError($"YaraQS file type identification error in {elapsedquick}ms: {ex.Message}");
				return false;
			}
		}

	}
}
