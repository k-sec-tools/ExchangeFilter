using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using ExchangeFilter;
using Microsoft.Exchange.Data.Transport;
using Microsoft.Exchange.Data.Transport.Email;
using System.Security.Cryptography;
using System.Text;
using System.Net;
using System.Net.Mail;


namespace ExchangeFilterTests
{
	[TestClass]
	public class ExchangeFilterTests
	{

		[TestMethod]
		public void Positive_WildcardToRegexEmptyString()
		{
			string actual = ExchangeFilterReceiveAgent.WildcardToRegex("");
			Console.WriteLine(actual);
			Assert.AreEqual(actual, "^$", "WildcardToRegex method parse error");
		}

		[TestMethod]
		public void Positive_LoadConfig()
		{
			var cfg = new ExchangeAttachmentFilterConfig();
		}


		[TestMethod]
		public void Negative_MessageProcessing_GoodMail_DontMarkSuspect()
		{
			const string headerName = "X-Malicious-Message";
			const string headerValue = "YES";
			const string pathToEml = @"..\..\..\GoodMail.eml";
			var colRecipients = new List<string> { "sample@sampledomaincin.com" };
			var fromAddress = new RoutingAddress();

			RunEmlHeadersTest(headerName, headerValue, pathToEml, colRecipients, fromAddress, 500, IPAddress.Parse("208.72.57.18"), IPAddress.Parse("208.72.57.18"), 637033480323893625);
			RunEmlExTest(pathToEml, colRecipients, fromAddress, 500);
		}

        [TestMethod]
        public void Positive_MessageProcessing_BlackListed_Attachment_exploit_vcf_MarkSuspect()
        {
            string headerName = "X-Malicious-Message";
            string headerValue = "YES";
            string pathToEml = @"..\..\..\expl_vcf.eml";
            List<string> colRecipients = new List<string> { "sample@sampledomaincin.com" };
            RoutingAddress fromAddress = new RoutingAddress();

            RunEmlHeadersTest(headerName, headerValue, pathToEml, colRecipients, fromAddress, 500);
            RunEmlExTest(pathToEml, colRecipients, fromAddress, 500);
        }

        [TestMethod]
        public void Negative_MessageProcessing_SubstringInPdf_Disarm()
        {
            string headerName = "X-Malicious-Message";
            string headerValue = "YES";
            string pathToEml = @"..\..\..\PdfWithOpenAction.eml";
            List<string> colRecipients = new List<string> { "sample@sampledomaincin.com" };
            RoutingAddress fromAddress = new RoutingAddress();

            RunEmlHeadersTest(headerName, headerValue, pathToEml, colRecipients, fromAddress, 500);
            RunEmlExTest(pathToEml, colRecipients, fromAddress, 500);
        }

        [TestMethod]
        public void Positive_MessageProcessing_BadLinkInHtmlBody_MarkSuspect()
        {
            string headerName = "X-Malicious-Message";
            string headerValue = "YES";
            string pathToEml = @"..\..\..\WithBadLinkInHtml.eml";

            List<string> colRecipients = new List<string> { "sample@sampledomaincin.com" };
            RoutingAddress fromAddress = new RoutingAddress();

            RunEmlHeadersTest(headerName, headerValue, pathToEml, colRecipients, fromAddress, 500);
            RunEmlExTest(pathToEml, colRecipients, fromAddress, 500);
        }


		[TestMethod]
        public void Positive_MessageProcessing_PhishingMessageWithFakeMessageId_MarkSuspect()
        {
            string headerName = "X-Malicious-Message";
            string headerValue = "YES";
            string pathToEml = @"..\..\..\PhishingMessageWithFakeMessageId.eml";
            List<string> colRecipients = new List<string> { "sample@sampledomaincin.com" };
            RoutingAddress fromAddress = new RoutingAddress();

            RunEmlHeadersTest(headerName, headerValue, pathToEml, colRecipients, fromAddress, 500, IPAddress.Parse("208.72.57.18"), IPAddress.Parse("208.72.57.18"), 637033480323893625);
            RunEmlExTest(pathToEml, colRecipients, fromAddress, 500);

        }



		[TestMethod]
        public void Positive_MessageProcessing_BlackListed_HTMLWithScriptTag_MarkSuspect()
        {
            string headerName = "X-Malicious-Message";
            string headerValue = "YES";
            string pathToEml = @"..\..\..\htmlwithtags.eml";
            List<string> colRecipients = new List<string> { "sample@sampledomaincin.com" };
            RoutingAddress fromAddress = new RoutingAddress();

            RunEmlHeadersTest(headerName, headerValue, pathToEml, colRecipients, fromAddress, 500);
            RunEmlExTest(pathToEml, colRecipients, fromAddress, 500);
        }



        [TestMethod]
        public void Positive_MessageProcessing_BlackListed_Subject_MarkSuspect()
        {
            string headerName = "X-Malicious-Message";
            string headerValue = "YES";
            string pathToEml = @"..\..\..\BlackListedSubject.eml";
            List<string> colRecipients = new List<string> { "sample@sampledomaincin.com" };
            RoutingAddress fromAddress = new RoutingAddress();

            RunEmlHeadersTest(headerName, headerValue, pathToEml, colRecipients, fromAddress, 500);
            RunEmlExTest(pathToEml, colRecipients, fromAddress, 500);
        }




		private void RunEmlExTest(string pathToEml,
			List<string> mailItemRecipients, RoutingAddress mailItemFromAddress,
			long mailItemMimeStreamLength, IPAddress smtpSessionRemoteEndPointAddress = null, IPAddress smtpSessionLastExternalIPAddress = null, long smtpSessionSessionId = 0)
		{
			var agent = (ExchangeFilterReceiveAgent)(new ExchangeFilterAgentFactory().CreateAgent(null));

			EmailMessage processedEmail = Helper.LoadEmailMessage(pathToEml);
			EmailMessage sourceEmail = Helper.LoadEmailMessage(pathToEml);

			if (mailItemRecipients.Count == 0 && processedEmail.To.Count != 0)
			{
				foreach (var emailRecipient in processedEmail.To)
				{
					mailItemRecipients.Add(emailRecipient.SmtpAddress);
				}
			}
			else if (mailItemRecipients.Count == 0)
			{
				mailItemRecipients.Add("recipients@eafttest.ru");
			}

			if (string.IsNullOrEmpty(mailItemFromAddress.ToString()) && processedEmail.From?.SmtpAddress != null)
			{
				mailItemFromAddress = new RoutingAddress(processedEmail.From.SmtpAddress);
			}
			else if (string.IsNullOrEmpty(mailItemFromAddress.ToString()))
			{
				mailItemFromAddress = new RoutingAddress("sender@eafttest.ru");
			}

			const DeliveryMethod mailItemInboundDeliveryMethod = DeliveryMethod.Unknown;

			if (mailItemMimeStreamLength == 0) mailItemMimeStreamLength = processedEmail.ToString().Length;

			agent.ProcessMessage(processedEmail, mailItemRecipients, mailItemFromAddress, smtpSessionRemoteEndPointAddress, smtpSessionLastExternalIPAddress, smtpSessionSessionId, mailItemInboundDeliveryMethod,
				mailItemMimeStreamLength);

			MD5 md5 = MD5.Create();
			string sourceBody = BodyToString(sourceEmail.Body);
			string processedBody = BodyToString(processedEmail.Body);

			Assert.IsTrue(string.Equals(processedBody, sourceBody));

			var sourceMD5List = new List<string>();
			var processedMD5List = new List<string>();


			if (processedEmail.Attachments.Count > 0)
			{
				foreach (var attachment in sourceEmail.Attachments)
				{
					try
					{
						var attachstream = attachment.GetContentReadStream();
						sourceMD5List.Add(Encoding.Default.GetString(md5.ComputeHash(attachstream)));

					}
					catch (Exception)
					{
						break;
					}

				}

				foreach (var attachment in processedEmail.Attachments)
				{
					try
					{
						var attachstream = attachment.GetContentReadStream();
						processedMD5List.Add(Encoding.Default.GetString(md5.ComputeHash(attachstream)));

					}
					catch (Exception)
					{
						break;
					}

				}

				Assert.IsTrue(sourceMD5List.Count == processedMD5List.Count);
				Assert.IsTrue(ScrambledEquals(sourceMD5List, processedMD5List));

			}
		}


		private void RunEmlHeadersTest(string headerName, string headerValue, string pathToEml,
			List<string> mailItemRecipients, RoutingAddress mailItemFromAddress,
			long mailItemMimeStreamLength, IPAddress smtpSessionRemoteEndPointAddress = null, IPAddress smtpSessionLastExternalIPAddress = null, long smtpSessionSessionId = 0)
		{
			var agent = (ExchangeFilterReceiveAgent)(new ExchangeFilterAgentFactory().CreateAgent(null));

			EmailMessage email = Helper.LoadEmailMessage(pathToEml);

			var header = email.RootPart.Headers.FindFirst(headerName);
			Assert.IsTrue(header == null, String.Format("Email message already have header {0}", headerName));

			if (mailItemRecipients.Count == 0 && email.To.Count != 0)
			{
				foreach (var emailRecipient in email.To)
				{
					mailItemRecipients.Add(emailRecipient.SmtpAddress);
				}
			}
			else if (mailItemRecipients.Count == 0)
			{
				mailItemRecipients.Add("recipient@eafttest.ru");
			}

			if (string.IsNullOrEmpty(mailItemFromAddress.ToString()) && email.From?.SmtpAddress != null)
			{
				mailItemFromAddress = new RoutingAddress(email.From.SmtpAddress);
			}
			else if (string.IsNullOrEmpty(mailItemFromAddress.ToString()))
			{
				mailItemFromAddress = new RoutingAddress("sender@eafttest.ru");
			}

			var mailItemInboundDeliveryMethod = DeliveryMethod.Unknown;

			if (mailItemMimeStreamLength == 0) mailItemMimeStreamLength = email.ToString().Length;


			var status = agent.RunProcessing(email, mailItemRecipients, mailItemFromAddress, mailItemInboundDeliveryMethod, mailItemMimeStreamLength, smtpSessionRemoteEndPointAddress, smtpSessionLastExternalIPAddress, smtpSessionSessionId);
			agent.ResolveMessage(null, status, email, mailItemMimeStreamLength);
			//agent.ProcessMessage(email, mailItemRecipients, mailItemFromAddress, mailItemInboundDeliveryMethod, mailItemMimeStreamLength);

			//header = email.RootPart.Headers.FindFirst(headerName).Value;
			Assert.IsTrue(String.Equals(email.RootPart.Headers.FindFirst(headerName).Value,
				headerValue, StringComparison.InvariantCultureIgnoreCase));
		}

		public static bool ScrambledEquals<T>(IEnumerable<T> list1, IEnumerable<T> list2)
		{
			var cnt = new Dictionary<T, int>();
			foreach (T s in list1)
			{
				if (cnt.ContainsKey(s))
				{
					cnt[s]++;
				}
				else
				{
					cnt.Add(s, 1);
				}
			}
			foreach (T s in list2)
			{
				if (cnt.ContainsKey(s))
				{
					cnt[s]--;
				}
				else
				{
					return false;
				}
			}
			return cnt.Values.All(c => c == 0);
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

	}
}
