using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using Microsoft.Exchange.Data.Transport.Smtp;
using System.Reflection;
using log4net;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Microsoft.Exchange.Data.Transport;
using Microsoft.Exchange.Data.Transport.Email;
using System.Security.Cryptography;
using System.Text.RegularExpressions;


namespace ExchangeFilter
{
	public sealed partial class ExchangeFilterReceiveAgent : SmtpReceiveAgent, IDisposable
	{
		private readonly object _fileLock = new object();
		private static readonly ILog Log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
		private string MessageId = "NoMessageID";
		private AgentAsyncContext agentAsyncContext;
		public ExchangeFilterReceiveAgent(ExchangeAttachmentFilterConfig exchangeAttachmentFilterConfig)
		{
			AppDomain.CurrentDomain.UnhandledException += ExHandler;

			string curDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? AppDomain.CurrentDomain.BaseDirectory;
			string log4netPath = Path.Combine(curDir, "log4net.config");
			log4net.Config.XmlConfigurator.ConfigureAndWatch(new FileInfo(log4netPath));
			Log.Info("CREATE: Create SmtpReceiveAgent instance.");

			_exchangeAttachmentFilterConfig = exchangeAttachmentFilterConfig;

			OnEndOfData += OnEndOfDataHandler;
		}

		private bool _exchangeConfigDisposed; // = false;

		public void Dispose()
		{
			if (!_exchangeConfigDisposed)
			{
				_exchangeConfigDisposed = true;

				OnEndOfData -= OnEndOfDataHandler;

				AppDomain.CurrentDomain.UnhandledException -= ExHandler;
			}
		}

		private void ExHandler(object sender, UnhandledExceptionEventArgs args)
		{
			Exception e = (Exception)args.ExceptionObject;
			LogError($"Unhandled exception caught {e.Message}");
		}

		private void OnEndOfDataHandler(ReceiveMessageEventSource source, EndOfDataEventArgs e)
		{
			lock (_fileLock)
			{
				try
				{
					if (_exchangeAttachmentFilterConfig.AgentEnabled)
					{
						try
						{
							MessageId = e.MailItem.Message.MessageId;
						}
						catch (Exception ex)
						{
							MessageId = "NoMessageId"; LogError($"Cant get messageid: {ex.Message}");

						}


						List<string> recipients = new List<string>();
						foreach (var recipient in e.MailItem.Recipients)
						{
							recipients.Add(recipient.Address.ToString());
						}

						if (recipients.Count == 0)
						{
							recipients.Add("cantreadrecipients@eaft.domain");

							LogInfo("Cant read recipients in mailitem.");
						}

						var senderAddress = e.MailItem.FromAddress;
						if (string.IsNullOrEmpty(senderAddress.ToString()))
						{
							senderAddress = new RoutingAddress("cantreadsender@eaft.agnt");
						}
						LogInfo($"OnSubmitted Message Time {DateTime.Now:MM/dd/yyyy hh:mm:ss.fff} " +
								 $"MailitemSize:  {e.MailItem.MimeStreamLength:N0} " +
								 $"RemoteEndpoint {e.SmtpSession.RemoteEndPoint.Address}");

						var message = e.MailItem.Message;
						var inboundDeliveryMethod = e.MailItem.InboundDeliveryMethod;
						var mimeStreamLength = e.MailItem.MimeStreamLength;

						var smtpSession = e.SmtpSession;

						var action = RunProcessing(message, recipients,
							senderAddress, inboundDeliveryMethod, mimeStreamLength,
							smtpSession.RemoteEndPoint.Address, smtpSession.LastExternalIPAddress, smtpSession.SessionId);
						ResolveMessage(source, action, message, mimeStreamLength);
					}
					else
					{
						Log.Info("Agent disabled by config");
					}

				}

				catch (IOException ex)
				{
					LogError($"IOException: {ex.Data} {ex.StackTrace} {ex.Source}");
				}
				catch (Exception ex)
				{
					LogError($"OnEndOfDataHandler Exception: {ex.Message}");
				}
				finally
				{
					agentAsyncContext?.Complete();
				}
			}
		}

		public ExchangeFilterStatus RunProcessing(EmailMessage message, List<string> recipients,
			RoutingAddress senderAddress, DeliveryMethod inboundDeliveryMethod,
			long mimeStreamLength, IPAddress smtpSessionRemoteEndPointAddress = null, IPAddress smtpSessionLastExternalIPAddress = null, long smtpSessionSessionId = 0)
		{
			var statusSet = ProcessMessage(message, recipients, senderAddress, smtpSessionRemoteEndPointAddress, smtpSessionLastExternalIPAddress, smtpSessionSessionId,
				inboundDeliveryMethod, mimeStreamLength);
			LogInfo($"Processed, statuslist: [{StatusListToString(statusSet.MatchedProcessingStatusList)}]");
			return ManageMessage(statusSet);

		}

		public void ResolveMessage(ReceiveMessageEventSource source, ExchangeFilterStatus action, EmailMessage message,
			long mimeStreamLength)
		{
			switch (action.Status)
			{
				case ExchangeFilterStatusEnum.Accept:
					LogResult(message.MessageId, mimeStreamLength, $"ACCEPTED, {action.Reason}");
					break;
				case ExchangeFilterStatusEnum.AddHeader:
					if (!_exchangeAttachmentFilterConfig.LogOnlyMode)
						message.RootPart.Headers.AppendChild(
							Header.GetMimeHeaderFromAgentHeader(_exchangeAttachmentFilterConfig.AgentHeaders
								.SusupiciousMailHeader));
					LogResult(message.MessageId, mimeStreamLength, $"QUARANTINED [{action.Reason}]");
					break;
				case ExchangeFilterStatusEnum.RejectMessage:
					if (!_exchangeAttachmentFilterConfig.LogOnlyMode)
						source.RejectMessage(SmtpResponse.Create("500", "", "Message rejected - EAFT"));
					LogResult(message.MessageId, mimeStreamLength, $"REJECTED [{action.Reason}]");
					break;
				case ExchangeFilterStatusEnum.UpdateMessageSubject:
					if (!_exchangeAttachmentFilterConfig.LogOnlyMode)
						message.Subject = $"[SUSPICIOUS EMAIL]:[{action.Reason}]" + message.Subject;
					LogResult(message.MessageId, mimeStreamLength, $"SUBJECT UPDATED [{action.Reason}]");
					break;
			}


			if (!_exchangeAttachmentFilterConfig.LogOnlyMode)
				message.RootPart.Headers.AppendChild(
				Header.GetMimeHeaderFromAgentHeader(_exchangeAttachmentFilterConfig.AgentHeaders.ProcessedMailHeader));
			LogInfo($"Processing ended at {DateTime.Now:MM/dd/yyyy hh:mm:ss.fff} MailitemSize: {mimeStreamLength:N0}");
		}

		private static void LogResult(string messageId, long mimeStreamLength, string resolution)
		{
			Log.Info($"MessageId {messageId}: {resolution} at {DateTime.Now:MM/dd/yyyy hh:mm:ss.fff} MailitemSize: {mimeStreamLength:N0}");
		}

		private void LogInfo(string text)
		{
			Log.Info($"MessageId {MessageId}: {text}");
		}

		private void LogError(string text)
		{
			Log.Error($"MessageId {MessageId}: {text}");
		}

		public static void LogStaticError(string text)
		{
			Log.Error(text);
		}

		private ExchangeFilterStatus ManageMessage(MessageProcessingStatusSet statusSet)
		{
			double threatLevel = 0;
			var whiteListMatches = 0;
			var blackListMatches = 0;
			var unProcessedMatches = 0;
			var corellatedModules = new List<AgentModuleName>
			{
				AgentModuleName.MessageIdChecking_Native, AgentModuleName.SmtpSessionChecking_Internal
			};
			foreach (var status in statusSet.MatchedProcessingStatusList)
			{
				if (!corellatedModules.Contains(status.AgentModuleName))
				{
					threatLevel += GetWeight(status);
					switch (status.Result)
					{
						case MessageProcessingResult.Blacklisted:
							blackListMatches++;
							break;
						case MessageProcessingResult.Whitelisted:
							whiteListMatches++;
							break;
						case MessageProcessingResult.CantProcess:
							unProcessedMatches++;
							break;
					}
				}
			}

			//corellated modules - smtp and native messageid
			if (statusSet.MatchedProcessingStatusList
				.Any(x => x.AgentModuleName == AgentModuleName.MessageIdChecking_Native &&
						 x.Result == MessageProcessingResult.Whitelisted))
			{
				if (statusSet.MatchedProcessingStatusList.Any(x =>
					x.AgentModuleName == AgentModuleName.SmtpSessionChecking_Internal &&
					x.Result == MessageProcessingResult.Whitelisted))
				{
					whiteListMatches++;
					threatLevel += GetWeight(new MessageProcessingStatus(AgentModuleName.MessageIdChecking_Native,
						MessageProcessingResult.Whitelisted));
					whiteListMatches++;
					threatLevel += GetWeight(new MessageProcessingStatus(AgentModuleName.SmtpSessionChecking_Internal,
						MessageProcessingResult.Whitelisted));
				}
				else if (statusSet.MatchedProcessingStatusList.Any(x =>
					 x.AgentModuleName == AgentModuleName.SmtpSessionChecking_Internal &&
					 x.Result == MessageProcessingResult.CantProcess))

				{
					whiteListMatches++;
					threatLevel += GetWeight(new MessageProcessingStatus(AgentModuleName.MessageIdChecking_Native,
						MessageProcessingResult.Whitelisted));
					unProcessedMatches++;
					threatLevel += GetWeight(new MessageProcessingStatus(AgentModuleName.SmtpSessionChecking_Internal,
						MessageProcessingResult.CantProcess));
				}
				else if (statusSet.MatchedProcessingStatusList.Any(x =>
					 x.AgentModuleName == AgentModuleName.SmtpSessionChecking_Internal &&
					 x.Result == MessageProcessingResult.Blacklisted))
				{
					blackListMatches++;
					threatLevel += GetWeight(new MessageProcessingStatus(AgentModuleName.MessageIdChecking_Native,
						MessageProcessingResult.Blacklisted));
					blackListMatches++;
					threatLevel += GetWeight(new MessageProcessingStatus(AgentModuleName.SmtpSessionChecking_Internal,
						MessageProcessingResult.Blacklisted));
				}
				else if (statusSet.MatchedProcessingStatusList.Any(x =>
					x.AgentModuleName == AgentModuleName.SmtpSessionChecking_Internal &&
					x.Result == MessageProcessingResult.NoMatch))
				{
					blackListMatches++;
					threatLevel += GetWeight(new MessageProcessingStatus(AgentModuleName.MessageIdChecking_Native,
						MessageProcessingResult.Blacklisted));
					blackListMatches++;
					threatLevel += GetWeight(new MessageProcessingStatus(AgentModuleName.SmtpSessionChecking_Internal,
						MessageProcessingResult.Blacklisted));
				}
				else
				{
					whiteListMatches++;
					threatLevel += GetWeight(new MessageProcessingStatus(AgentModuleName.MessageIdChecking_Native,
						MessageProcessingResult.Whitelisted));
				}

			}
			else
			{
				foreach (var status in statusSet.MatchedProcessingStatusList)
				{
					if (corellatedModules.Contains(status.AgentModuleName))
					{
						threatLevel += GetWeight(status);
						switch (status.Result)
						{
							case MessageProcessingResult.Blacklisted:
								blackListMatches++;
								break;
							case MessageProcessingResult.Whitelisted:
								whiteListMatches++;
								break;
							case MessageProcessingResult.CantProcess:
								unProcessedMatches++;
								break;
						}
					}

				}
			}

            ExchangeFilterStatusEnum agentAction;
            switch (_exchangeAttachmentFilterConfig.AgentAction.ToLower())
            {
                case "accept":
                    agentAction = ExchangeFilterStatusEnum.Accept;
                    break;
				case "header":
                    agentAction = ExchangeFilterStatusEnum.AddHeader;
					break;
                case "subject":
                    agentAction = ExchangeFilterStatusEnum.UpdateMessageSubject;
                    break;
                case "reject":
                    agentAction = ExchangeFilterStatusEnum.RejectMessage;
                    break;
				default:
                    agentAction = ExchangeFilterStatusEnum.AddHeader;
					break;

			}
			//
			if (_exchangeAttachmentFilterConfig.UseMetrics)
			{
				if (threatLevel <= 0)
				{
					return new ExchangeFilterStatus(ExchangeFilterStatusEnum.Accept,
						$"No match; ThreatLevel:{threatLevel}; UnprocessedMatches:{unProcessedMatches}; BlacklistedMatches:{blackListMatches}; WhitelistedMatchess:{whiteListMatches}");
				}
				return new ExchangeFilterStatus(agentAction,
					$"Suspicious elements found; ThreatLevel:{threatLevel}; UnprocessedMatches:{unProcessedMatches}; BlacklistedMatches:{blackListMatches}; WhitelistedMatchess:{whiteListMatches}");
			}


			if (statusSet.MatchedProcessingStatusList.Any(x => (x.AgentModuleName == AgentModuleName.MessageHeadersChecking && x.Result == MessageProcessingResult.Blacklisted)))
				return new ExchangeFilterStatus(agentAction,
					$"Blacklisted by headers; ThreatLevel:{threatLevel}; UnprocessedMatches:{unProcessedMatches}; BlacklistedMatches:{blackListMatches}; WhitelistedMatchess:{whiteListMatches}");

			if (statusSet.MatchedProcessingStatusList.Any(x =>
					(x.AgentModuleName == AgentModuleName.EmailAddressChecking && x.Result == MessageProcessingResult.Whitelisted)
					|| (x.AgentModuleName == AgentModuleName.MessageSubjectChecking && x.Result == MessageProcessingResult.Whitelisted)
					|| (x.AgentModuleName == AgentModuleName.MessageIdChecking_List && x.Result == MessageProcessingResult.Whitelisted)
					|| (x.AgentModuleName == AgentModuleName.MessageIdChecking_Native && x.Result == MessageProcessingResult.Whitelisted)
				)
			)
			{
				return new ExchangeFilterStatus(ExchangeFilterStatusEnum.Accept,
					$"Whitelisted by sender, recipient or subject; ThreatLevel:{threatLevel}; UnprocessedMatches:{unProcessedMatches}; BlacklistedMatches:{blackListMatches}; WhitelistedMatchess:{whiteListMatches}");
			}


			const string NULLVALUE = "{{{null-value}}}";
			var statusDictByObject = new Dictionary<string, List<MessageProcessingStatus>>();
			var maxStatPerModule = new List<MessageProcessingStatus>();
			var modulenames = statusSet.MatchedProcessingStatusList.Select(p => p.AgentModuleName).Distinct();
			foreach (var modulename in modulenames)
			{
				var statusList = statusSet.MatchedProcessingStatusList.Where(p => p.AgentModuleName == modulename);

				statusDictByObject.Clear();
				statusDictByObject[NULLVALUE] = new List<MessageProcessingStatus>();

				foreach (var statusItem in statusList)
				{
					string key = statusItem.ObjectName ?? NULLVALUE;
					if (!statusDictByObject.ContainsKey(key))
					{
						statusDictByObject[key] = new List<MessageProcessingStatus>();
					}
					statusDictByObject[key].Add(statusItem);
				}

				var resultStatusList = new List<MessageProcessingStatus>();
				foreach (var checkedPair in statusDictByObject)
				{
					if (!string.IsNullOrEmpty(checkedPair.Key))
					{
						var statusListPerObject = checkedPair.Value;
						if (statusListPerObject.Any(x => x.Result == MessageProcessingResult.Whitelisted))
						{
							var tmpStatus = statusListPerObject.FirstOrDefault();
							if (tmpStatus != null)
							{
								resultStatusList.Add(new MessageProcessingStatus(tmpStatus.AgentModuleName, MessageProcessingResult.Whitelisted, tmpStatus.Comment, tmpStatus.ObjectName));
							}
						}
						else
						{
							resultStatusList.Add(GetWorstStatusFromList(statusListPerObject, modulename));
						}
					}
				}
				resultStatusList.AddRange(statusDictByObject[NULLVALUE]);

				if (resultStatusList.Count > 0)
				{
					maxStatPerModule.Add(GetWorstStatusFromList(resultStatusList, modulename));
				}
			}

			if (maxStatPerModule.Any(x => (x.Result > MessageProcessingResult.NoMatch) && (x.Result < MessageProcessingResult.Whitelisted)))
			{
				return new ExchangeFilterStatus(agentAction,
					$"Suspicious elements found; ThreatLevel:{threatLevel}; UnprocessedMatches:{unProcessedMatches}; BlacklistedMatches:{blackListMatches}; WhitelistedMatchess:{whiteListMatches}");
			}

			return new ExchangeFilterStatus(ExchangeFilterStatusEnum.Accept,
				$"No match; ThreatLevel:{threatLevel}; UnprocessedMatches:{unProcessedMatches}; BlacklistedMatches:{blackListMatches}; WhitelistedMatchess:{whiteListMatches}");
		}

		private double GetWeight(MessageProcessingStatus status)
		{
			int weight = 0;
			if (_exchangeAttachmentFilterConfig.ModuleWeights.Find(x =>
					x.AgentModuleName == status.AgentModuleName) != null)
				switch (status.Result)
				{
					case MessageProcessingResult.Blacklisted:
						weight = Config.AgentModuleWeightDefault;
						if (_exchangeAttachmentFilterConfig.ModuleWeights.Find(x =>
								x.AgentModuleName == status.AgentModuleName) != null)
							weight = _exchangeAttachmentFilterConfig.ModuleWeights
								.Find(x => x.AgentModuleName == status.AgentModuleName).blacklistMatchWeight;
						break;
					case MessageProcessingResult.Whitelisted:
						weight = -1 * Config.AgentModuleWeightDefault;
						if (_exchangeAttachmentFilterConfig.ModuleWeights.Find(x =>
								x.AgentModuleName == status.AgentModuleName) != null)
							weight = -1 * _exchangeAttachmentFilterConfig.ModuleWeights
								.Find(x => x.AgentModuleName == status.AgentModuleName).whitelistMatchWeight;
						break;
					case MessageProcessingResult.CantProcess:
						weight = Config.AgentModuleWeightDefault / 2;
						if (_exchangeAttachmentFilterConfig.ModuleWeights.Find(x =>
								x.AgentModuleName == status.AgentModuleName) != null)
							weight = _exchangeAttachmentFilterConfig.ModuleWeights
								.Find(x => x.AgentModuleName == status.AgentModuleName).unproñessedWeight;
						break;
					case MessageProcessingResult.NoMatch:
						weight = 0;
						break;
				}


			return weight;
		}

		private static string GetMD5(Stream stream)
		{
			return BitConverter.ToString(MD5.Create().ComputeHash(stream)).Replace("-", string.Empty);
		}

		public MessageProcessingStatusSet ProcessMessage(EmailMessage message, List<string> mailItemRecipients,
			RoutingAddress mailItemFromAddress, IPAddress smtpSessionRemoteEndPointAddress, IPAddress smtpSessionLastExternalIPAddress, long smtpSessionSessionId,
			DeliveryMethod mailItemInboundDeliveryMethod,
			long mailItemMimeStreamLength)
		{
			agentAsyncContext = null;

			var stopwatch = new Stopwatch();
			stopwatch.Start();
			var messageProcessingStatusSet = new MessageProcessingStatusSet { FurtherChecksNeeded = false };


			var headerslist = message.RootPart.Headers;
			var recipientList = new StringBuilder();
			for (var i = 0; i < mailItemRecipients.Count; i++)
			{
				recipientList.Append(i == 0
					? mailItemRecipients[i]
					: "; " + mailItemRecipients[i]);

				if (String.Equals(mailItemRecipients[i].ToLower(),
					mailItemFromAddress.ToString().ToLower(), StringComparison.CurrentCultureIgnoreCase))
				{
					messageProcessingStatusSet.MatchedProcessingStatusList.Add(new MessageProcessingStatus(AgentModuleName.SelfSentChecking, MessageProcessingResult.Blacklisted,
										"self sent"));

				}
			}

			var subject = message.Subject;
			var mailItemStatusText =
				$"[from: {mailItemFromAddress}] [to: {recipientList}] [method: {mailItemInboundDeliveryMethod}] [subject: {subject}] [size: {mailItemMimeStreamLength:N0}] [messageID: {message.MessageId}]";
			LogInfo(mailItemStatusText);
			var inboundRecipients = new List<string>();
			foreach (var addr in mailItemRecipients)
			{
				if (IsRecipientInbound(addr))
				{
					inboundRecipients.Add(addr);
					messageProcessingStatusSet.FurtherChecksNeeded = true;
				}

			}
			messageProcessingStatusSet.MatchedProcessingStatusList.AddRange(ProcessMessageId(message.MessageId.ToLower().TrimEnd('>').TrimStart('<')));
			messageProcessingStatusSet.MatchedProcessingStatusList.AddRange(
				ProcessEmailAddresses(mailItemFromAddress.ToString(), inboundRecipients));


			if (messageProcessingStatusSet.FurtherChecksNeeded)
			{
				if (_exchangeAttachmentFilterConfig.CheckMessageSubject)
				{
					messageProcessingStatusSet.MatchedProcessingStatusList.Add(ProcessMessageSubject(subject));
				}

				if (_exchangeAttachmentFilterConfig.CheckSmtpSession)
				{
					messageProcessingStatusSet.MatchedProcessingStatusList.AddRange(ProcessSmtpSession(smtpSessionRemoteEndPointAddress, smtpSessionLastExternalIPAddress, smtpSessionSessionId));
				}

				if (_exchangeAttachmentFilterConfig.CheckMessageHeaders)
				{
					messageProcessingStatusSet.MatchedProcessingStatusList.AddRange(ProcessMessageHeaders(headerslist));
				}

				if (_exchangeAttachmentFilterConfig.CheckMessageBody)
				{

					foreach (var status in ProcessMessageBody(message.Body).MatchedProcessingStatusList)
					{
						messageProcessingStatusSet.MatchedProcessingStatusList.Add(status);
					}
				}

				if (_exchangeAttachmentFilterConfig.CheckAttachments && message.Attachments.Count != 0)
				{
					#region foreachattachment

					try
					{
						foreach (var attachment in message.Attachments)
						{
							var fileName = attachment.FileName;
							var attachmentMD5 = GetMD5(attachment.GetContentReadStream());

							messageProcessingStatusSet.MatchedProcessingStatusList.Add(FilenameFilterStatus(fileName));

							try
							{
								LogInfo($"Attachment processing started {attachment.FileName} MD5 {attachmentMD5}");
								try
								{
									if (attachment.ContentType == "application/pdf" ||
										attachment.FileName.Substring(fileName.Length - 3, 3).ToLower() == "pdf")
									{
										Stream attachreadstream = attachment.GetContentReadStream();
										PDFTools tools = new PDFTools(_exchangeAttachmentFilterConfig, message.MessageId, attachment.FileName,
											attachreadstream);
										if (tools.Detect())
										{
											if (tools.ScanPDF())
											{
												Stream attachwritestream = attachment.GetContentWriteStream();
												tools.DisarmedStream.WriteTo(attachwritestream);
												attachwritestream.Flush();
												attachwritestream.Close();

												messageProcessingStatusSet.MatchedProcessingStatusList.Add(
													new MessageProcessingStatus(AgentModuleName.Undefined,
													MessageProcessingResult.NoMatch, $"{fileName} disarmed", fileName));
											}
										}

									}
								}
								catch (Exception ex)
								{
									LogError($"Exception while disarming pdf {fileName}: {ex.Message}\r\n{ex.StackTrace}");
								}

								var attachBytes = StreamToByteArray(attachment.GetContentReadStream());
								var result = ProcessFileBytes(attachBytes, fileName, attachmentMD5);
								messageProcessingStatusSet.MatchedProcessingStatusList.AddRange(result);
							}
							catch (Exception ex)
							{
								var message1 = new MessageProcessingStatus(AgentModuleName.Undefined,
									MessageProcessingResult.CantProcess, $"{fileName} cant process, MD5 {attachmentMD5}", fileName);
								messageProcessingStatusSet.MatchedProcessingStatusList.Add(message1);
								LogError($"Exception while processing attachment {ex.Message}\r\n{ex.StackTrace}");
							}

							LogInfo($"Attachment processing ended {fileName} MD5 {attachmentMD5}");
						}
					}
					catch (Exception ex)
					{
						LogError($"Exception while attachments checking: {ex.Message}\r\n{ex.StackTrace}");
						var message2 = new MessageProcessingStatus(AgentModuleName.Undefined, MessageProcessingResult.CantProcess,
							"Cant process attachments");
						messageProcessingStatusSet.MatchedProcessingStatusList.Add(message2);
					}

					#endregion foreachattachment
				}
			}

			return messageProcessingStatusSet;
		}

		private List<MessageProcessingStatus> ProcessFileBytes(byte[] fileBytes, string fileName, string md5)
		{
			var attachmentStatusList = new List<MessageProcessingStatus>();
			try
			{
				var attachLength = fileBytes.Length / 1024; //to KB
				if (_exchangeAttachmentFilterConfig.AttachmentSizeThreshold != 0 &&
					attachLength > _exchangeAttachmentFilterConfig.AttachmentSizeThreshold)
				{
					attachmentStatusList.Add(new MessageProcessingStatus(
						AgentModuleName.Undefined, MessageProcessingResult.Whitelisted,
						$"{fileName} whitelisted by filesize, MD5 {md5}", fileName));
					LogInfo(
						$"SKIP attachment: [reason: attachment '{fileName}' size more than '{_exchangeAttachmentFilterConfig.AttachmentSizeThreshold}' KB], MD5 {md5}");
					return attachmentStatusList;
				}
			}
			catch (Exception ex)
			{
				attachmentStatusList.Add(new MessageProcessingStatus(
					AgentModuleName.Undefined, MessageProcessingResult.CantProcess,
					$"{fileName}, MD5 {md5} exception: {ex.Message}", fileName));
				LogError($"Attachment threshold exception: {ex.Message}");
				return attachmentStatusList;
			}

			bool yaraProcessed = false;

			foreach (var yaraHelper in _exchangeAttachmentFilterConfig.YaraHelpers)
			{
				if (GetYaraQSByteArrayBool(fileBytes, yaraHelper.SignaturesPath))
				{
					yaraProcessed = true;
					attachmentStatusList.Add(GetYaraQSByteArrayMPStatus(fileBytes, fileName, yaraHelper.RulesPath));
				}
			}

			foreach (var yaraExtension in _exchangeAttachmentFilterConfig.YaraExtensions)
			{
				if (yaraExtension.FileExtensions.Any(f =>
					Regex.IsMatch(fileName, WildcardToRegex(f), RegexOptions.IgnoreCase)))
				{
					yaraProcessed = true;
					attachmentStatusList.Add(
						GetYaraQSByteArrayMPStatus(fileBytes, fileName, yaraExtension.YaraFilePath));
				}
			}

			//ArchiveChecking
			if (!yaraProcessed && _exchangeAttachmentFilterConfig.ScanArchives &&
				IsArchive(fileName, fileBytes))
			{
				attachmentStatusList.Add(ProcessArchiveBytes(fileBytes, fileName, md5, 0));
			}

			return attachmentStatusList;
		}

	}
}