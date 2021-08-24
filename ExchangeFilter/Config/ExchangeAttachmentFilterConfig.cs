using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security;
using System.Xml.Schema;
using System.Xml.Linq;
using log4net;
using System.Text.RegularExpressions;
using System.Threading;

namespace ExchangeFilter
{
	public class ExchangeAttachmentFilterConfig
	{
		private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
		private readonly Timer timer;

		public ExchangeAttachmentFilterConfig()
		{
			string curDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

			if (curDir == null)
			{
				log.Error("Config ERROR: Current directory is NULL.");
				return;
			}

			string configFileName = Path.Combine(curDir, "Config", "log4net.config");
			log4net.Config.XmlConfigurator.ConfigureAndWatch(new FileInfo(configFileName));
			// get config directory (the same as agent's dll dir)

			ReloadConfigs(null);

			long period = (long)TimeSpan.FromMinutes(1).TotalMilliseconds;
			timer = new Timer(ReloadConfigs, null, period, period);
		}

		private static DateTime LastGCTime;

		public static void GCCollect()
		{
			if (DateTime.Now.Subtract(LastGCTime) >= TimeSpan.FromMinutes(GCCollectInterval))
			{
				LastGCTime = DateTime.Now;
				var stopwatch = new Stopwatch();
				stopwatch.Start();
				GC.Collect(2, GCCollectionMode.Forced, false);
				stopwatch.Stop();
				log.Info($"Ended GC.Collect in {stopwatch.ElapsedMilliseconds}ms; LastGCTime = {LastGCTime}");
			}
		}

		private DateTime configLastModify = DateTime.MinValue;

		public void ReloadConfigs(object state)
		{
			string curDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
			if (string.IsNullOrEmpty(curDir))
			{
				throw new Exception("Current Directory is null or empty");
			}
			var configDirectory = Path.Combine(curDir, "Config");
			var xDocPath = Path.Combine(configDirectory, Config.ConfigFileName);

			var xDocFile = new FileInfo(xDocPath);
			if (!xDocFile.Exists)
			{
				log.Error($"Config not found: {xDocPath}");
				xDocPath = Path.Combine(configDirectory, Config.DefaultConfigFileName);
				xDocFile = new FileInfo(xDocPath);
				if (!xDocFile.Exists)
				{
					log.Error($"Default config not found: {xDocPath}");
					throw new Exception($"Config files are not found or broken.");
				}
			}
			DateTime lastChangeTime = (xDocFile.LastWriteTime > xDocFile.CreationTime) ? xDocFile.LastWriteTime : xDocFile.CreationTime;
			bool firstTime = (configLastModify == DateTime.MinValue);

			if (!firstTime && (lastChangeTime <= configLastModify))
			{
				return;
			}
			configLastModify = lastChangeTime;

			var xSchPath = Path.Combine(configDirectory, Config.ConfigSchemaFilename);
			string xmlValidationMessage = ValidateXml(xDocPath, xSchPath);
			if (xmlValidationMessage == null)
			{
				try
				{
					LoadConfig(xDocPath);
					log.Info($"Config loaded: {xDocPath}");
				}
				catch (Exception ex)
				{
					log.Error($"Can not load config {xDocPath}: {ex.Message}");
				}
			}
			else
			{
				log.Error($"Config validation ERROR: {xDocPath} {xmlValidationMessage}");
				xDocPath = Path.Combine(configDirectory, Config.DefaultConfigFileName);
				xmlValidationMessage = ValidateXml(xDocPath, xSchPath);
				if (xmlValidationMessage == null)
				{
					try
					{
						LoadConfig(xDocPath);
						log.Error($"Default config loaded: {xDocPath}");
					}
					catch (Exception ex)
					{
						log.Error($"Can not load default config {xDocPath}: {ex.Message}");
					}
				}
				else
				{
					log.Error($"Default config validation ERROR: {xDocPath} {xmlValidationMessage}");
					throw new Exception($"Config files are not found or broken.");
				}
			}
			if (!firstTime)
			{
				GCCollect();
			}
		}

		/// <summary>
		/// Loads XML configuration file and sets up exposed configuration properties.
		/// </summary>
		public void LoadConfig(string xDocPath)
		{
			try
			{
				// parse config xml file
				var xDoc =
					XDocument.Load(
						new StreamReader(new FileStream(xDocPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)));
				var root = xDoc.Root;
				if (root == null)
					throw new XmlSyntaxException("Invalid XML configuration.");

				var attachments = root.Element("attachments");
				if (attachments != null)
				{
					AttachmentsWhitelist =
						attachments.Element("whitelist")?.Elements("attachment").Select(e => e.Value).ToList();
					AttachmentsBlacklist =
						attachments.Element("blacklist")?.Elements("attachment").Select(e => e.Value).ToList();
					var archiveFileTypes = attachments.Element("archivefiletypes");
					if (archiveFileTypes != null)
					{
						ArchiveFileTypes = archiveFileTypes.Elements("fileextension").Select(e => e.Value).ToList();
					}
					else
					{
						ArchiveFileTypes = Config.ArchiveFileTypesDefault;
					}
				}
				else
				{
					AttachmentsWhitelist = new List<string>();
					AttachmentsBlacklist = new List<string>();
					ArchiveFileTypes = Config.ArchiveFileTypesDefault;
				}

				var headers = root.Element("agentsettings").Element("headers");
				AgentHeaders.ProcessedMailHeader = GetAgentHeader(headers, "processed", ProcessedMailHeader, HeaderValue, HeaderValueType);
				AgentHeaders.SusupiciousMailHeader = GetAgentHeader(headers, "suspicious", SusupiciousMailHeader, HeaderValue, HeaderValueType);
                AgentHeaders.FilterHeadersBlackList = GetFilterHeadersList(headers, Config.HeaderValueTypeDefault, "blacklist");
				AgentHeaders.FilterHeadersWhiteList = GetFilterHeadersList(headers, Config.HeaderValueTypeDefault, "whitelist");

				var senders = root.Element("senders");
				if (senders != null)
				{
					SendersWhitelist =
						senders.Element("whitelist")?.Elements("emailaddress").Select(e => e.Value).ToList();
					SendersBlacklist =
						senders.Element("blacklist")?.Elements("emailaddress").Select(e => e.Value).ToList();
				}
				else
				{
					SendersWhitelist = new List<string>();
					SendersBlacklist = new List<string>();
				}

				var recipients = root.Element("recipients");
				if (recipients != null)
				{
					RecipientsWhitelist =
						recipients.Element("whitelist")?.Elements("emailaddress").Select(e => e.Value).ToList();
					RecipientsBlacklist =
						recipients.Element("blacklist")?.Elements("emailaddress").Select(e => e.Value).ToList();
				}
				else
				{
					RecipientsWhitelist = new List<string>();
					RecipientsBlacklist = new List<string>();
				}

				var internalDomains = root.Element("agentsettings").Element("inboundmaildomains");
				if (internalDomains != null)
				{
					InternalDomains =
						internalDomains.Elements("domain").Select(e => e.Value).ToList();
				}
				else
				{
					InternalDomains = new List<string> { "*@domain.one", "*@domain.two" };
				}


				var internalSubnets = root.Element("agentsettings").Element("internalNetworks");
				if (internalSubnets != null)
				{
					InternalSubnets =
						internalSubnets.Elements("subnet").Select(e => e.Value).ToList();
				}
				else
				{
					InternalSubnets = new List<string> { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7" };
				}

				var subnetsWhitelisted = root.Element("networks").Element("whitelistedNetworks");
				if (subnetsWhitelisted != null)
				{
					SubnetsWhiteList =
						subnetsWhitelisted.Elements("subnet").Select(e => e.Value).ToList();
				}
				else
				{
					SubnetsWhiteList = new List<string>();
				}

				var subnetsBlacklisted = root.Element("networks").Element("blacklistedNetworks");
				if (subnetsBlacklisted != null)
				{
					SubnetsBlacklist =
						subnetsBlacklisted.Elements("subnet").Select(e => e.Value).ToList();
				}
				else
				{
					SubnetsBlacklist = new List<string>();
				}

				var messageIDs = root.Element("messageIDs");
				if (messageIDs != null)
				{
					MessageIDsWhiteList =
						messageIDs.Element("whitelist")?.Elements("messageID").Select(e => e.Value).ToList();
					MessageIDsNativeList =
						messageIDs.Element("native")?.Elements("messageID").Select(e => e.Value).ToList();
					MessageIDsBlackList =
						messageIDs.Element("blacklist")?.Elements("messageID").Select(e => e.Value).ToList();
				}
				else
				{
					MessageIDsWhiteList = new List<string>();
					MessageIDsNativeList = new List<string>();
					MessageIDsBlackList = new List<string>();
				}

				var kwtmp = root.Element("attachments").Element("pdfdisarm").Elements("keyword").Select(e => e.Value).ToList();
				PdfKeywords = (kwtmp.Count > 0) ? kwtmp : new List<string>();

				var yaraFolderPath = root.Element("agentsettings").Element("yarafolderpath").Value;
				var yaraRulesExt = root.Element("agentsettings").Element("yararulewildcard").Value;
				var yaraSignExt = root.Element("agentsettings").Element("yarasignwildcard").Value;
				var yaraFastScan = root.Element("agentsettings").Element("yarasignwildcard").Value == "0";
				try
				{
					var yaraConfigFiles = Directory.GetFiles(yaraFolderPath);
					if (yaraConfigFiles.Length > 0)
					{
						var yaraRulesPaths = Array.FindAll(yaraConfigFiles,
							s => Regex.IsMatch(s, WildcardToRegex(yaraRulesExt)));

						var yaraSignPaths = Array.FindAll(yaraConfigFiles,
							s => Regex.IsMatch(s, WildcardToRegex(yaraSignExt)));

						var tmpYaraHelpers = new List<YaraHelper>();
						foreach (var yaraSignPath in yaraSignPaths)
						{
							var name = Path.GetFileNameWithoutExtension(yaraSignPath);
							var yaraRulesPath = Array.Find(yaraRulesPaths, s =>
								Regex.IsMatch(s, WildcardToRegex($"*{name}{yaraRulesExt.TrimStart('*')}")));
							if (yaraRulesPath != null && yaraSignPath != null)
							{
								tmpYaraHelpers.Add(new YaraHelper(yaraSignPath, yaraRulesPath, yaraFastScan, name));
							}
						}
						YaraHelpers = tmpYaraHelpers;

						var yaraext = attachments.Element("yaraext");
						var tmpYaraExt = new List<YaraExtension>();
						if (yaraext != null)
						{
							foreach (var rule in yaraext.Elements("rule").ToList())
							{
								var yaraExtension = new YaraExtension
								{
									FileExtensions = rule.Elements("fileextension").Select(e => e.Value).ToList(),
									YaraFilePath = Array.Find(yaraRulesPaths,
										s => Regex.IsMatch(s, WildcardToRegex(rule.Element("yarafile").Value)))
								};
								tmpYaraExt.Add(yaraExtension);
							}
						}
						YaraExtensions = tmpYaraExt;
					}
				}
				catch (Exception ex)
				{

					log.Error($"Cannot load YARA files: {ex.Message}");
				}

                if (root.Element("agentsettings").Element("subjectupdatetext")?.Value != null)
                    SubjectUpdText = root.Element("agentsettings").Element("subjectupdatetext")?.Value;

                if (root.Element("agentsettings").Element("rejectresponsetext")?.Value != null)
                    RejectMessageText = root.Element("agentsettings").Element("rejectresponsetext")?.Value;


				var sevenzippath = root.Element("agentsettings").Element("sevenziplibpath").Value;
				if (File.Exists(sevenzippath))
					SevenZipLibPath = sevenzippath;

				SevenZip.SevenZipBase.SetLibraryPath(SevenZipLibPath);

				_Mailer = GetMailer(root);

				hyperlinkRegEx = root.Element("messagebodyprocessingsettings").Element("hyperlinkregex").Value;
				HyperlinkWhitelistRgx = root.Element("messagebodyprocessingsettings").Element("hyperlinks").Element("whitelist")?.Elements("rgx").Select(e => e.Value).ToList();
				HyperlinkBlacklistPathParts = root.Element("messagebodyprocessingsettings").Element("hyperlinks").Element("blacklist")?.Elements("localpathpart").Select(e => e.Value).ToList();
				HyperlinkBlacklistRgx = root.Element("messagebodyprocessingsettings").Element("hyperlinks").Element("blacklist")?.Elements("rgx").Select(e => e.Value).ToList();

				BodyBlacklistRgx = root.Element("messagebodyprocessingsettings").Element("bodytext").Element("blacklist")?.Elements("rgx").Select(e => e.Value).ToList();
				BodyWhitelistRgx = root.Element("messagebodyprocessingsettings").Element("bodytext").Element("whitelist")?.Elements("rgx").Select(e => e.Value).ToList();
				SubjectBlacklistRgx = root.Element("messagesubjectprocessingsettings").Element("subjecttext").Element("blacklist")?.Elements("rgx").Select(e => e.Value).ToList();
				SubjectWhitelistRgx = root.Element("messagesubjectprocessingsettings").Element("subjecttext").Element("whitelist")?.Elements("rgx").Select(e => e.Value).ToList();

				BodyBlacklistAcWords = root.Element("messagebodyprocessingsettings").Element("bodytext").Element("blacklist")?.Elements("acword").Select(e => e.Value).ToList();
				BodyWhitelistAcWords = root.Element("messagebodyprocessingsettings").Element("bodytext").Element("whitelist")?.Elements("acword").Select(e => e.Value).ToList();
				SubjectBlacklistAcWords = root.Element("messagesubjectprocessingsettings").Element("subjecttext").Element("blacklist")?.Elements("acword").Select(e => e.Value).ToList();
				SubjectWhitelistAcWords = root.Element("messagesubjectprocessingsettings").Element("subjecttext").Element("whitelist")?.Elements("acword").Select(e => e.Value).ToList();


				var parameters = root.Element("agentsettings").Element("parameters");
				if (parameters == null)
				{
					ModuleWeights = new List<AgentModule>();
					AttachmentSizeThreshold = Config.AttachmentSizeThresholdDefault;
					AttachmentUnarchivedSizeThreshold = Config.AttachmentSizeThresholdDefault;
					AttachmentArchiveDepth = Config.AttachmentArchiveDepth;
					ScanArchives = Config.ScanArchivesDefault;
					BlockUncheckedArchives = Config.BlockUncheckedArchives;
					MailboxMethodSafe = Config.MailboxMethodSafeDefault;
					CheckMessageBody = Config.CheckMessageBodyDefault;
					CheckMessageSubject = Config.CheckMessageSubjectDefault;
					CheckAttachments = Config.CheckAttachmentsDefault;
					CheckMessageHeaders = Config.CheckMessageHeadersDefault;
					CheckSmtpSession = Config.CheckSmtpSessionDefault;
					LogOnlyMode = Config.LogOnlyModeDefault;
					AgentEnabled = Config.AgentEnabledDefault;
					return;
				}

				ModuleWeights = GetModuleWeights(root.Element("agentsettings").Element("filtermodules"));

				AttachmentSizeThreshold = GetParameterValueAsInt(parameters, "attachmentSizeThreshold", Config.AttachmentSizeThresholdDefault, "parameter");
				AttachmentUnarchivedSizeThreshold = GetParameterValueAsInt(parameters, "attachmentUnarchivedSizeThreshold", Config.AttachmentSizeThresholdDefault, "parameter");
				AttachmentArchiveDepth = GetParameterValueAsInt(parameters, "attachmentArchiveDepth", 2, "parameter");
				AttachmentArchiveProcessingTime = GetParameterValueAsInt(parameters, "attachmentArchiveProcessingTime", 2, "parameter");
				ScanArchives = GetParameterValueAsBool(parameters, "scanArchives", Config.ScanArchivesDefault, "parameter");
				BlockUncheckedArchives =
					GetParameterValueAsBool(parameters, "blockUnprocessedArchives", BlockUncheckedArchives, "parameter");
				GCCollectInterval = GetParameterValueAsInt(parameters, "gcCollectInterval", Config.GCCollectInterval, "parameter");
				MailboxMethodSafe = GetParameterValueAsBool(parameters, "mailboxMethodSafe", Config.MailboxMethodSafeDefault,
					"parameter");
				CheckMessageBody = GetParameterValueAsBool(parameters, "checkMessageBody",
					Config.CheckMessageBodyDefault, "parameter");
				CheckMessageSubject = GetParameterValueAsBool(parameters, "checkMessageSubject",
					Config.CheckMessageSubjectDefault, "parameter");
				CheckAttachments = GetParameterValueAsBool(parameters, "checkAttachments",
					Config.CheckAttachmentsDefault, "parameter");
				CheckMessageHeaders = GetParameterValueAsBool(parameters, "checkMessageHeaders",
					Config.CheckMessageHeadersDefault, "parameter");
				CheckSmtpSession = GetParameterValueAsBool(parameters, "checkSmtpSession",
					Config.CheckSmtpSessionDefault, "parameter");
				LogOnlyMode = GetParameterValueAsBool(parameters, "logOnlyMode",
					Config.CheckMessageHeadersDefault, "parameter");
				AgentEnabled = GetParameterValueAsBool(parameters, "agentEnabled",
					Config.CheckMessageHeadersDefault, "parameter");

                var actionsElement = root.Element("agentsettings").Element("actions");
                if (actionsElement != null)
                {
                    var acts = new List<AgentAction>();
                    foreach (var element in actionsElement.Elements("action").ToList())
                    {


                        var rng = new Range<int>(int.Parse(GetXMLElementAtributeValue(element, "minscore", int.MinValue.ToString())),
                            int.Parse(GetXMLElementAtributeValue(element, "maxscore", int.MaxValue.ToString())));

                        var elementAction = new AgentAction(rng, element.Value);

                        if (acts.Count > 0)
                        {
                            var overlap = acts.FirstOrDefault(x => Range<int>.RangesOverlapping(rng, x.Range));
                            if (overlap != null)
                            {
                                log.Error($"ranges overlapping: {elementAction} and {overlap}");
                                acts.Remove(acts.FirstOrDefault(x => Range<int>.RangesOverlapping(rng, x.Range)));
                            }
                        }
                        acts.Add(elementAction);
                    }

                    AgentActions = acts;
                }
                else
                {
                    AgentActions.Add(new AgentAction());
                }


			}
			catch (Exception ex)
			{
				log.Error($"LoadConfig ERROR: {ex.Message}");
			}
		}

        private static string GetXMLElementAtributeValue(XElement element, string attributename, string defaultValue)
        {
            return element.Attribute(attributename)?.Value ?? defaultValue;
        }

		private static List<AgentModule> GetModuleWeights(XElement subroot)
		{
			var result = new List<AgentModule>();
			foreach (AgentModuleName module in Enum.GetValues(typeof(AgentModuleName)))
			{
				var tmpModule = new AgentModule { AgentModuleName = module };
				var tmpElement = subroot.Elements("module").FirstOrDefault(x => x.Element("name")?.Value == tmpModule.AgentModuleName.ToString());
				if (tmpElement == null)
				{
					tmpModule.blacklistMatchWeight = Config.AgentModuleWeightDefault;
					tmpModule.whitelistMatchWeight = Config.AgentModuleWeightDefault;
					tmpModule.unproсessedWeight = Config.AgentModuleWeightDefault / 2;
				}
				else
				{
					string node = tmpElement.Element("blacklistmatchweight")?.Value;
					if (node != null)
						tmpModule.blacklistMatchWeight = int.Parse(node);
					else
					{
						tmpModule.blacklistMatchWeight = Config.AgentModuleWeightDefault;
					}
					node = tmpElement.Element("whitelistmatchweight")?.Value;
					if (node != null)
						tmpModule.whitelistMatchWeight = int.Parse(node);
					else
					{
						tmpModule.whitelistMatchWeight = Config.AgentModuleWeightDefault;
					}
					node = tmpElement.Element("unprocessedweight")?.Value;
					if (node != null)
						tmpModule.unproсessedWeight = Int32.Parse(node);
					else
					{
						tmpModule.unproсessedWeight = Config.AgentModuleWeightDefault / 2;
					}
				}

				result.Add(tmpModule);
			}

			return result;
		}

		public Dictionary<AgentModuleName, int> GetModuleWeightDictionary(XElement paremeters)
		{
			var result = new Dictionary<AgentModuleName, int>();
			foreach (AgentModuleName module in Enum.GetValues(typeof(AgentModuleName)))
			{
				string name = module.ToString();
				var val = GetParameterValueAsInt(paremeters, name, Config.AgentModuleWeightDefault, "moduleweight");
				result.Add(module, val);
			}

			return result;
		}

		private static Header GetAgentHeader(XElement headers, string headerXElementName, string defaultHeaderName, string defaultHeaderValue, Header.HeaderValueTypeEnum defaultHeaderValueType)
		{
			var header = new Header
			{
				Name = headers.Element(headerXElementName).Element("name").Value,
				Value = headers.Element(headerXElementName).Element("value").Value
			};
			if (header.Name == null) header.Name = defaultHeaderName;
			if (header.Value == null) header.Value = defaultHeaderValue;
			header.ValueType = defaultHeaderValueType;

			return header;
		}
		private Header GetAgentHeader(XElement element, Header.HeaderValueTypeEnum defaultHeaderValueType)
		{
			var header = new Header
			{
				Name = element.Element("name").Value,
				ValuesList = element.Elements("value").Select(e => e.Value).ToList()
			};
			header.ValuesList.RemoveAll(x => x == null);
			if (header.Name == null || header.ValuesList.Count == 0) return null;
			switch (element.Element("valuetype").Value)
			{
				case "string":
					header.ValueType = Header.HeaderValueTypeEnum.Wildcard;
					break;
				case "rgx":
					header.ValueType = Header.HeaderValueTypeEnum.Regex;
					break;
				default:
					header.ValueType = defaultHeaderValueType;
					break;
			}

			return header;
		}

		private List<Header> GetFilterHeadersList(XElement xheaders, Header.HeaderValueTypeEnum defaultHeaderValueType, string listname)
		{
			var headersList = new List<Header>();
			var headerelements = xheaders.Element(listname).Elements("header").ToList();
			foreach (var element in headerelements)
			{
				var header = GetAgentHeader(element, defaultHeaderValueType);
				if (header != null) headersList.Add(header);
			}

			return headersList;
		}

		/// <summary>
		/// Gets XML configuration parameter value as string.
		/// </summary>
		/// <param name="parametersElement">Root container element with 'parameter' nodes.</param>
		/// <param name="parameterName">Name of the parameter.</param>
		/// <param name="defaultValue">Default value returned if the parameter name is not found.</param>
		/// <returns>Parameter value as string.</returns>
		private static string GetParameterValue(XContainer parametersElement, string parameterName, string defaultValue, string subName)
		{
			var parameterElement = parametersElement.Elements(subName).FirstOrDefault(x =>
			{
				var xAttribute = x.Attribute("name");
				return xAttribute != null && xAttribute.Value.ToLower().Equals(parameterName.ToLower());
			});

			return parameterElement?.Value ?? defaultValue;
		}

		/// <summary>
		/// Gets XML configuration parameter value as boolean.
		/// </summary>
		/// <param name="parametersElement">Root container element with 'parameter' nodes.</param>
		/// <param name="parameterName">Name of the parameter.</param>
		/// <param name="defaultValue">Default value returned if the parameter name is not found.</param>
		/// <returns>Parameter value as boolean.</returns>
		private static bool GetParameterValueAsBool(XContainer parametersElement, string parameterName, bool defaultValue, string subName)
		{
			return GetParameterValue(parametersElement, parameterName, defaultValue ? "1" : "0", subName).Trim().Equals("1");
		}

		/// <summary>
		/// Gets XML configuration parameter value as integer.
		/// </summary>
		/// <param name="parametersElement">Root container element with 'parameter' nodes.</param>
		/// <param name="parameterName">Name of the parameter.</param>
		/// <param name="defaultValue">Default value returned if the parameter name is not found.</param>
		/// <returns></returns>
		private static int GetParameterValueAsInt(XContainer parametersElement, string parameterName, int defaultValue, string subName)
		{
			var value = GetParameterValue(parametersElement, parameterName, null, subName);
			if (value == null)
			{
				return defaultValue;
			}

			try
			{
				return int.Parse(value);
			}
			catch (Exception)
			{
				log.Error($"Config ERROR: Cannot parse '{parameterName}' value '{value}' as integer value. Using default '{defaultValue}'");
				return defaultValue;
			}
		}

		public static IMailer GetMailer(XElement root)
		{
			XElement mailerSettings = root.Element("agentsettings").Element("mailersettings");
			IMailer m = new SmtpMailer
			{
				Body = mailerSettings.Element("body").Value,
				UserName = mailerSettings.Element("username").Value,
				Password = mailerSettings.Element("password").Value,
				Subject = mailerSettings.Element("subject").Value,
				FromAddress = mailerSettings.Element("fromaddress").Value,
				DefaultRecipient = mailerSettings.Element("defaultrecipient")
					.Value,
				Server = mailerSettings.Element("server").Value,
				Port = int.Parse(mailerSettings.Element("port").Value),
				Enabled = Convert.ToBoolean(int.Parse(mailerSettings.Element("enabled").Value))
			};
			return m;
		}


		public static byte[] StringToByteArray(String hex)
		{
			int NumberChars = hex.Length;
			byte[] bytes = new byte[NumberChars / 2];
			for (int i = 0; i < NumberChars; i += 2)
				bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
			return bytes;
		}

		private string ValidateXml(string xDocPath, string xSchPath)
		{
			string msg = null;
			try
			{
				XmlSchemaSet schemas = new XmlSchemaSet();
				schemas.Add("", xSchPath);
				XDocument doc = XDocument.Load(xDocPath);

				doc.Validate(schemas, (o, e) =>
				{
					msg += e.Message + Environment.NewLine;
				});
			}
			catch (Exception e)
			{
				log.Error(e.Message);
				msg += e.Message + Environment.NewLine;
			}
			return msg;
		}


		public static string WildcardToRegex(string wildcardString)
		{
			return "^" + Regex.Escape(wildcardString).Replace("\\*", ".*").Replace("\\?", ".") + "$";
		}

		public IEnumerable<string> ArchiveFileTypes = Config.ArchiveFileTypesDefault;

		// parameters
		public static int GCCollectInterval { get; private set; } = Config.GCCollectInterval;
		public int AttachmentSizeThreshold { get; private set; } = Config.AttachmentSizeThresholdDefault;
		public int AttachmentUnarchivedSizeThreshold { get; private set; } = Config.AttachmentSizeThresholdDefault;
		public int AttachmentArchiveDepth { get; private set; } = Config.AttachmentArchiveDepth;
		public int AttachmentArchiveProcessingTime { get; private set; } = Config.AttachmentArchiveProcessingTime;
		public bool ScanArchives { get; private set; } = Config.ScanArchivesDefault;
		public bool MailboxMethodSafe { get; private set; } = Config.MailboxMethodSafeDefault;
		//public bool ScanOfficeDocuments { get; private set; } = Config.ScanOfficeDocumentsDefault;
		public bool BlockUncheckedArchives { get; private set; } = Config.BlockUncheckedArchives;
		//public bool BlockUPasswordProtectedArchives { get; private set; } = Config.BlockUncheckedArchives;
		public bool CheckMessageBody { get; private set; } = Config.CheckMessageBodyDefault;
		public bool CheckMessageSubject { get; private set; } = Config.CheckMessageSubjectDefault;
		public bool CheckMessageHeaders { get; private set; } = Config.CheckMessageHeadersDefault;
		public bool CheckAttachments { get; private set; } = Config.CheckAttachmentsDefault;
		public bool CheckSmtpSession { get; private set; } = Config.CheckSmtpSessionDefault;
		public bool AgentEnabled { get; private set; } = Config.AgentEnabledDefault;
		public bool LogOnlyMode { get; private set; } = Config.LogOnlyModeDefault;

		public AgentHeaders AgentHeaders { get; set; } = new AgentHeaders();
		public string SusupiciousMailHeader { get; } = Config.SusupiciousMailHeaderDefault;
		public string ProcessedMailHeader { get; } = Config.ProcessedMailHeaderDefault;
		public string WhiteListedMailHeader { get; } = Config.WhiteListedMailHeaderDefault;
		public string HeaderValue { get; } = Config.HeaderValueDefault;
		public Header.HeaderValueTypeEnum HeaderValueType { get; } = Config.HeaderValueTypeDefault;


		public string hyperlinkRegEx = string.Empty;
		public IMailer _Mailer = new SmtpMailer();

		// lists
		public List<string> InternalDomains { get; private set; } = new List<string>();
		public List<string> InternalSubnets { get; private set; } = new List<string>();
		public List<string> SubnetsWhiteList { get; private set; } = new List<string>();
		public List<string> SubnetsBlacklist { get; private set; } = new List<string>();
		public List<string> HyperlinkWhitelistRgx { get; private set; } = new List<string>();
		public List<string> HyperlinkBlacklistPathParts { get; private set; } = new List<string>();
		public List<string> HyperlinkBlacklistRgx { get; private set; } = new List<string>();
		public List<string> BodyBlacklistRgx { get; private set; } = new List<string>();
		public List<string> BodyWhitelistRgx { get; private set; } = new List<string>();
		public List<string> SubjectBlacklistRgx { get; private set; } = new List<string>();
		public List<string> SubjectWhitelistRgx { get; private set; } = new List<string>();
		public List<string> BodyBlacklistAcWords { get; private set; } = new List<string>();
		public List<string> BodyWhitelistAcWords { get; private set; } = new List<string>();
		public List<string> SubjectBlacklistAcWords { get; private set; } = new List<string>();
		public List<string> SubjectWhitelistAcWords { get; private set; } = new List<string>();
		public List<string> AttachmentsWhitelist { get; private set; } = new List<string>();
		public List<string> AttachmentsBlacklist { get; private set; } = new List<string>();
		public List<string> MessageIDsWhiteList { get; private set; } = new List<string>();
		public List<string> MessageIDsBlackList { get; private set; } = new List<string>();
		public List<string> MessageIDsNativeList { get; private set; } = new List<string>();
		public List<string> SendersWhitelist { get; private set; } = new List<string>();
		public List<string> SendersBlacklist { get; private set; } = new List<string>();
		public List<string> RecipientsWhitelist { get; private set; } = new List<string>();
		public List<string> RecipientsBlacklist { get; private set; } = new List<string>();
		public List<YaraHelper> YaraHelpers { get; private set; } = new List<YaraHelper>();

		public List<YaraExtension> YaraExtensions = new List<YaraExtension>();

		public List<AgentModule> ModuleWeights = new List<AgentModule>();

		public List<string> PdfKeywords = new List<string>();

		public string SevenZipLibPath = Config.ConfigFileSevenZipLibraryPath;

        public List<ArchiveProperty> ArchiveEncryptedProperties = new List<ArchiveProperty>();

        public string SubjectUpdText = "ALARM";
        public string RejectMessageText = "Message rejected";
        public List<AgentAction> AgentActions { get; private set; } = new List<AgentAction>();
	}

    public class AgentAction
    {
        public Range<int> Range { get; set; }
        public ExchangeFilterStatusEnum Action { get; set; }


        public AgentAction()
        {
            Range = new Range<int>(int.MinValue, int.MaxValue);
            Action = ExchangeFilterStatusEnum.Accept;
        }

        public AgentAction(Range<int> rrange, string aaction)
        {
            Range = rrange;
            switch (aaction.ToLower())
            {
                case "accept":
                    Action = ExchangeFilterStatusEnum.Accept;
                    break;
                case "header":
                    Action = ExchangeFilterStatusEnum.AddHeader;
                    break;
                case "subject":
                    Action = ExchangeFilterStatusEnum.UpdateMessageSubject;
                    break;
                case "reject":
                    Action = ExchangeFilterStatusEnum.RejectMessage;
                    break;
                default:
                    Action = ExchangeFilterStatusEnum.AddHeader;
                    break;
            }
        }

        public override string ToString()
        {
            return string.Format("[{0} : {1}]", this.Range, this.Action);
        }
    }

	public class ArchiveProperty
    {
        public string Name { get; set; }
        public string Value { get; set; }

        public ArchiveProperty()
        {
            Name = null;
            Value = null;
        }

        public static ArchiveProperty GetArchiveProperty(string name, string value)
        {
            var ap = new ArchiveProperty { Value = value, Name = name };
            return ap;
        }
    }
	

	public class Range<T> where T : IComparable<T>
	{
        //https://stackoverflow.com/a/5343033

		/// <summary>Minimum value of the range.</summary>
		public T Minimum { get; set; }

		/// <summary>Maximum value of the range.</summary>
		public T Maximum { get; set; }

		/// <summary>Presents the Range in readable format.</summary>
		/// <returns>String representation of the Range</returns>
		public override string ToString()
		{
			return string.Format("[{0} - {1}]", this.Minimum, this.Maximum);
		}

		/// <summary>Determines if the range is valid.</summary>
		/// <returns>True if range is valid, else false</returns>
		public bool IsValid()
		{
			return this.Minimum.CompareTo(this.Maximum) <= 0;
		}

		/// <summary>Determines if the provided value is inside the range.</summary>
		/// <param name="value">The value to test</param>
		/// <returns>True if the value is inside Range, else false</returns>
		public bool ContainsValue(T value)
		{
			return (this.Minimum.CompareTo(value) <= 0) && (value.CompareTo(this.Maximum) <= 0);
		}

		/// <summary>Determines if this Range is inside the bounds of another range.</summary>
		/// <param name="Range">The parent range to test on</param>
		/// <returns>True if range is inclusive, else false</returns>
		public bool IsInsideRange(Range<T> range)
		{
			return this.IsValid() && range.IsValid() && range.ContainsValue(this.Minimum) && range.ContainsValue(this.Maximum);
		}

		/// <summary>Determines if another range is inside the bounds of this range.</summary>
		/// <param name="Range">The child range to test</param>
		/// <returns>True if range is inside, else false</returns>
		public bool ContainsRange(Range<T> range)
		{
			return this.IsValid() && range.IsValid() && this.ContainsValue(range.Minimum) && this.ContainsValue(range.Maximum);
		}

		public static bool RangesOverlapping(Range<int> r1, Range<int> r2)
		{
			return r1.IsValid() && r2.IsValid() && ((Math.Max(0, Math.Min(r1.Maximum, r2.Maximum) - Math.Max(r1.Minimum, r2.Minimum) + 1) != 0) || r1.ContainsRange(r2) || r1.IsInsideRange(r2));
		}

		public Range(T min, T max)
		{
			Minimum = min;
			Maximum = max;
		}
	}
}
