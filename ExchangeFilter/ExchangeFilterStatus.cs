using System.Collections.Generic;

namespace ExchangeFilter
{
	public enum ExchangeFilterStatusEnum
	{
		Accept = 0,
		UpdateMessageSubject = 1,
		AddHeader = 2,
		RejectMessage = 3,
	}


	public class MessageProcessingStatus
	{

		public AgentModuleName AgentModuleName { get; set; }
		public MessageProcessingResult Result { get; set; }
		public string ObjectName { get; set; }
		public string Comment { get; set; }

		public MessageProcessingStatus(AgentModuleName agentModuleName, MessageProcessingResult result)
		{
			AgentModuleName = agentModuleName;
			Result = result;
			ObjectName = null;
			Comment = null;
		}
		public MessageProcessingStatus(AgentModuleName agentModuleName, MessageProcessingResult result, string comment)
		{
			AgentModuleName = agentModuleName;
			Result = result;
			ObjectName = null;
			Comment = comment;
		}

		public MessageProcessingStatus(AgentModuleName agentModuleName)
		{
			AgentModuleName = agentModuleName;
			Result = MessageProcessingResult.NoMatch;
			ObjectName = null;
			Comment = null;
		}

		public MessageProcessingStatus(AgentModuleName agentModuleName, MessageProcessingResult result, string comment, string objectname)
		{
			AgentModuleName = agentModuleName;
			Result = result;
			ObjectName = objectname;
			Comment = comment;
		}

		public MessageProcessingStatus()
		{
			AgentModuleName = AgentModuleName.Undefined;
			Result = MessageProcessingResult.NoMatch;
			ObjectName = null;
			Comment = null;
		}

		public MessageProcessingStatus(string fileName)
		{
			AgentModuleName = AgentModuleName.Undefined;
			Result = MessageProcessingResult.NoMatch;
			ObjectName = fileName;
			Comment = null;
		}
	}

	public enum AgentModuleName
	{
		SelfSentChecking,
		MessageBodyChecking,
		UrlChecking,
		FilenameChecking,
		ArchiveProcessing,
		MessageSubjectChecking,
		Undefined,
		EmailAddressChecking,
		MessageHeadersChecking,
		MessageIdChecking_List,
		MessageIdChecking_Native,
		SmtpSessionChecking_Internal,
		SmtpSessionChecking_List,
		YaraFileChecking,
	}


	public enum MessageProcessingResult
	{
		NoMatch = 0,
		CantProcess = 1,
		Blacklisted = 2,
		Whitelisted = 3,
	}

	public class AgentModule
	{
		public AgentModuleName AgentModuleName;
		public int whitelistMatchWeight;
		public int blacklistMatchWeight;
		public int unproсessedWeight;

		public AgentModule()
		{
			AgentModuleName = AgentModuleName.Undefined;
			whitelistMatchWeight = 1;
			blacklistMatchWeight = -1;
			unproсessedWeight = 0;
		}
	}

	public class MessageProcessingStatusSet
	{
		public List<MessageProcessingStatus> MatchedProcessingStatusList { get; set; }
		public bool FurtherChecksNeeded { get; set; }

		public MessageProcessingStatusSet()
		{
			MatchedProcessingStatusList = new List<MessageProcessingStatus>();
			FurtherChecksNeeded = true;
		}
	}

	public class ExchangeFilterStatus
	{
		public ExchangeFilterStatus(ExchangeFilterStatusEnum status, int statusTag, string reason)
		{
			Status = status;
			StatusTag = statusTag;
			Reason = reason;
		}

		public ExchangeFilterStatus(ExchangeFilterStatusEnum status, string reason)
			: this(status, 0, reason)
		{ }

		public ExchangeFilterStatusEnum Status { get; }
		public string Reason { get; }
		public int StatusTag { get; }
	}
}
