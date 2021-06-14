// https://github.com/braktech/xdpdf

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using log4net;
using Microsoft.Exchange.Data.TextConverters;
using Microsoft.Exchange.Data.Transport.Email;


namespace ExchangeFilter
{
	public class PDFTools : IDisposable
	{
		public static readonly ILog log = LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
		private readonly string messageid;
		private readonly Stream attachstream;
		private readonly string attachname;
		private readonly Dictionary<int, string> disarmbytes = new Dictionary<int, string>();
		private bool isdisarmed;
		private readonly int longestword;
		private byte[] original;
		private byte[] disarmed;

		private readonly byte[] header_magic =
		{
			0x25,
			0x50,
			0x44,
			0x46
		}; // %PDF

		private readonly string[] Keywords;
		//String outpath;
		private readonly List<string> detectedwords = new List<string>();

		public PDFTools(ExchangeAttachmentFilterConfig config, string id, string name, Stream instream)
		{
			Keywords = config.PdfKeywords.ToArray();
			messageid = id;
			attachname = name;
			attachstream = instream;
			foreach (string keyword in Keywords)
			{
				if (keyword.Length * 3 > longestword)
				{
					longestword = keyword.Length * 3; // Need to allow for any word to be completely hex encoded
				}
			}
		}

		public string AttachGuid { get; set; }

		public MemoryStream DisarmedStream { get; set; }

		public bool Detect()
		{
			byte[] b = new byte[1024];
			attachstream.Read(b, 0, 1024);
			return CheckForSequence(b, header_magic);
		}

		protected virtual void Dispose(bool disposing)
		{
			if (disposing)
			{
				DisarmedStream.Dispose();
			}
		}

		public void Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}

		public bool ScanPDF()
		{
			int streamlength = Convert.ToInt32(attachstream.Length);
			List<string> wordexact;
			ASCIIEncoding encoding = new ASCIIEncoding();
			original = new byte[streamlength];
			disarmed = new byte[streamlength];

			original = ReadToEnd(attachstream, streamlength);
			Collection<int> slashes = FindBytes(original, 0x2f); // Searching for '/'
			foreach (int slashlocation in slashes)
			{
				int streamposition = slashlocation + 1;
				int streamoffset = 0;
				bool inword = true;
				string word = "";
				wordexact = new List<string>();

				while (streamoffset < longestword && inword && streamposition + streamoffset < streamlength)
				{
					string character = encoding.GetString(original, streamposition + streamoffset, 1);
					if (IsAlphaNumeric(character))
					{
						word += character;
						wordexact.Add(character);
					}
					else if (character.Equals("#") && streamposition + streamoffset < (streamlength - 2))
					{
						string digit1 = encoding.GetString(original, streamposition + streamoffset + 1, 1);
						string digit2 = encoding.GetString(original, streamposition + streamoffset + 2, 1);
						if (IsHexadecimal(digit1) && IsHexadecimal(digit2))
						{
							string hexchar = digit1 + digit2;
							var hexint = Convert.ToInt32(hexchar, 16);
							character = Convert.ToChar(hexint).ToString();
							word += character;
							wordexact.Add(hexchar);
							streamoffset += 2;
						}
						else
						{
							inword = false;
						}
					}
					else
					{
						inword = false;
					}
					streamoffset++;
				}
				// The word has finished; now disarm
				bool detected = UpdateWords(word);
				if (detected)
				{
					isdisarmed = true;
					int disarmposition = slashlocation + 1;
					disarmbytes[disarmposition] = "x";
					disarmbytes[disarmposition + 1] = "x";
				}
			}

			if (isdisarmed)
			{
				log.Info($"{messageid}: attachment \"{attachname}\" is being disarmed");
				LogAndDisarm();
			}
			else
			{
				log.Info($"{messageid}: attachment \"{attachname}\" did not contain any specified keywords");
			}
			return isdisarmed;
		}

		private Boolean UpdateWords(string word)
		{
			Boolean detected = false;
			if (Keywords.Contains("/" + word))
			{
				detected = true;
				if (!detectedwords.Contains(word))
				{
					detectedwords.Add(word);
				}
			}
			return detected;
		}

		void LogAndDisarm()
		{
			original.CopyTo(disarmed, 0);

			string suspect_words = "";
			foreach (var item in detectedwords)
			{
				suspect_words += item + ", ";
			}
			suspect_words = suspect_words.Substring(0, suspect_words.Length - 2);
			log.Info($"{messageid}: attachment \"{attachname}\" contained the following suspicious keywords: {suspect_words}");

			foreach (var location in disarmbytes)
			{
				disarmed[location.Key] = Encoding.ASCII.GetBytes(location.Value)[0];
			}

			AttachGuid = Guid.NewGuid().ToString();


			DisarmedStream = new MemoryStream();
			BinaryWriter disarmedstreamwriter = new BinaryWriter(DisarmedStream);
			disarmedstreamwriter.Write(disarmed);
		}

		private static bool IsAlphaNumeric(string character)
		{
			return CharInRange(character, "A", "Z") ||
					CharInRange(character, "0", "9");
		}

		private static bool IsHexadecimal(string character)
		{
			return CharInRange(character, "A", "F") ||
					CharInRange(character, "0", "9");
		}

		private static bool CharInRange(string testchar, string firstchar, string secondchar)
		{
			return string.Compare(testchar, firstchar, true) >= 0 &&
					string.Compare(testchar, secondchar, true) <= 0;
		}

		private static byte[] ReadToEnd(Stream stream, int length)
		{
			long originalposition = stream.Position;
			stream.Position = 0;

			if (length < 1)
			{
				length = 32768;
			}

			byte[] buffer = new byte[length];
			int read = 0;

			int chunk;
			while ((chunk = stream.Read(buffer, read, buffer.Length - read)) > 0)
			{
				read += chunk;

				//If we're at the end of the buffer, check for more data
				if (read == buffer.Length)
				{
					int nextbyte = stream.ReadByte();
					// if the next byte is -1 we're at the end of the stream
					if (nextbyte == -1)
					{
						stream.Position = originalposition;
						return buffer;
					}
					// Still more data; keep reading
					byte[] newbuffer = new byte[buffer.Length * 2];
					Array.Copy(buffer, newbuffer, buffer.Length);
					buffer = newbuffer;
					read++;
				}
			}
			//The buffer is probably too big - shrink it before returning
			byte[] ret = new byte[read];
			Array.Copy(buffer, ret, read);
			stream.Position = originalposition;
			return ret;
		}

		public static bool CheckForSequence(byte[] buffer, byte[] pattern)
		{
			bool found = false;
			int i = Array.IndexOf(buffer, pattern[0], 0);
			while (i >= 0 && i <= buffer.Length - pattern.Length && !found)
			{
				byte[] segment = new byte[pattern.Length];
				Buffer.BlockCopy(buffer, i, segment, 0, pattern.Length);
				if (segment.SequenceEqual(pattern))
				{
					found = true;
				}
				i = Array.IndexOf(buffer, pattern[0], i + pattern.Length);
			}
			return found;
		}

		public static Collection<int> FindBytes(byte[] buffer, byte searchfor)
		{
			var positions = new Collection<int>();
			int i = Array.IndexOf(buffer, searchfor, 0);
			while (i >= 0 && i <= buffer.Length - 1)
			{
				positions.Add(i);
				i = Array.IndexOf(buffer, searchfor, i + 1);
			}
			return positions;
		}

		public static void AddFooterToBody(string messageid, Body body, string text)
		{
			Stream originalbodycontent = null;
			Stream newbodycontent = null;

			try
			{
				BodyFormat bodyformat = body.BodyFormat;
				if (!body.TryGetContentReadStream(out originalbodycontent))
				{
					//body can't be decoded
					log.Info($"{messageid}: email body format could not be decoded - warning footer not appended");
				}

				Encoding encoding;
				string charsetname;
				if (BodyFormat.Text == bodyformat)
				{
					charsetname = body.CharsetName;
					if (null == charsetname || !Microsoft.Exchange.Data.Globalization.Charset.TryGetEncoding(charsetname, out encoding))
					{
						// either no charset, or charset is not supported by the system
						log.Info($"{messageid}: email body character set is either not defined or not supported by the system - warning footer not appended");
					}
					else
					{
						TextToText texttotextconversion = new TextToText
						{
							InputEncoding = encoding,
							HeaderFooterFormat = HeaderFooterFormat.Text,
							Footer = text
						};
						newbodycontent = body.GetContentWriteStream();
						try
						{
							texttotextconversion.Convert(originalbodycontent, newbodycontent);
						}
						catch (TextConvertersException)
						{
							log.Error($"{messageid}: error while performing body text conversion - warning footer not appended");
						}
					}

				}
				else if (BodyFormat.Html == bodyformat)
				{
					charsetname = body.CharsetName;
					if (null == charsetname ||
						!Microsoft.Exchange.Data.Globalization.Charset.TryGetEncoding(charsetname, out encoding))
					{
						log.Info($"{messageid}: email body character set is either not defined or unsupported - warning footer not appended");
					}
					else
					{
						HtmlToHtml htmltohtmlconversion = new HtmlToHtml
						{
							InputEncoding = encoding,
							HeaderFooterFormat = HeaderFooterFormat.Html,
							Footer = "<p><font size=\"-1\">" + text + "</font></p>"
						};
						newbodycontent = body.GetContentWriteStream();

						try
						{
							htmltohtmlconversion.Convert(originalbodycontent, newbodycontent);
						}
						catch (TextConvertersException)
						{
							// the conversion has failed..
							log.Error($"{messageid}: error while performing body html conversion - warning footer not appended");
						}
					}

				}
				else if (BodyFormat.Rtf == bodyformat)
				{
					RtfToRtf rtftortfconversion = new RtfToRtf
					{
						HeaderFooterFormat = HeaderFooterFormat.Html,
						Footer = "<font face=\"Arial\" size=\"+1\">" + text + "</font>"
					};
					Stream uncompressedbodycontent = body.GetContentWriteStream();

					try
					{
						rtftortfconversion.Convert(originalbodycontent, uncompressedbodycontent);
					}
					catch (TextConvertersException)
					{
						//Conversion failed
						log.Error($"{messageid}: error while decompressing body rtf - warning footer not appended");
					}

					RtfToRtfCompressed rtfcompressionconversion = new RtfToRtfCompressed
					{
						CompressionMode = RtfCompressionMode.Compressed
					};
					newbodycontent = body.GetContentWriteStream();

					try
					{
						rtfcompressionconversion.Convert(uncompressedbodycontent, newbodycontent);
					}
					catch (TextConvertersException)
					{
						// the conversion has failed..
						log.Info($"{messageid}: error compressing body rtf - warning footer not appended");
					}
				}

				else
				{
					// Handle cases where the body format is not one of the above.
					log.Info(($"{messageid}: format {bodyformat.ToString()} : unsupported body email format - warning footer not appended"));
				}
			}

			finally
			{
				originalbodycontent?.Close();

				newbodycontent?.Close();
			}
		}
	}
}
