using System;
using System.Collections.Generic;
using System.Net.Mail;

namespace ExchangeFilter
{
	public interface IMailer
	{
		string UserName { get; set; }
		string Password { get; set; }
		string Subject { get; set; }
		string Body { get; set; }
		string FromAddress { get; set; }
		string DefaultRecipient { get; set; }
		string Server { get; set; }
		bool Enabled { get; set; }
		int Port { get; set; }

		void SendLetter(List<string> toAddresses, List<string> attachmentNames, string sender, string messageSubject);
	}

	public class SmtpMailer : IMailer
	{
		public string UserName { get; set; }
		public string Password { get; set; }
		public string Subject { get; set; }
		public string Body { get; set; }
		public string FromAddress { get; set; }
		public string DefaultRecipient { get; set; }
		public string Server { get; set; }
		public bool Enabled { get; set; }
		public int Port { get; set; }

		public void SendLetter(List<string> toAddresses, List<string> attachmentNames, string sender, string messageSubject)
		{
			SmtpClient client = new SmtpClient
			{
				UseDefaultCredentials = false,
				Host = Server,
				Credentials = new System.Net.NetworkCredential(UserName, Password),
				Port = Port,
				DeliveryMethod = SmtpDeliveryMethod.Network
			};

			MailMessage mail = new MailMessage {IsBodyHtml = true};

			if (toAddresses.Count == 0)
			{
				mail.To.Add(DefaultRecipient);
				mail.From = new MailAddress("user@domain.com");
				mail.Subject = "cant send alert to user";
				mail.Body += "To:<br/>";
				mail.Body += toAddresses.ToString();
				mail.Body += "<br/>From:<br/>";
				mail.Body += FromAddress;
				mail.Body += "<br/>Subject:<br/>";
			}
			else
			{
				mail.From = new MailAddress(FromAddress);
				foreach (var address in toAddresses)
				{
					mail.To.Add(address);
				}
				mail.Subject = Subject;
				string mailBody = Body + "<br/>Subject: " + messageSubject + " <br/>Sender: " + sender;
				if (attachmentNames.Count != 0)
				{
					mailBody += "<br/>Attachments:";
					foreach (var attachmentName in attachmentNames)
					{
						mailBody += "<br/>" + attachmentName + "<br/>";
					}
				}

				mail.Body = mailBody;
			}

			try
			{
				client.Send(mail);
			}
			catch (Exception e)
			{
				ExchangeFilterReceiveAgent.LogStaticError($"{e.Message} {e.InnerException} {e.StackTrace} {e.Data}");
			}
		}

	}

	public class Log4NetMailer : IMailer
	{
		public string UserName { get; set; }
		public string Password { get; set; }
		public string Subject { get; set; }
		public string Body { get; set; }
		public string FromAddress { get; set; }
		public string DefaultRecipient { get; set; }
		public string Server { get; set; }
		public bool Enabled { get; set; }
		public int Port { get; set; }

		public void SendLetter(List<string> toAddresses, List<string> attachmentNames, string sender,
			string messageSubject)
		{

			throw new Exception();
		}
	}

}
