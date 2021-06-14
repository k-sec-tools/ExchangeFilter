using System.Collections.Generic;

namespace ExchangeFilter
{
	public class YaraHelper
	{
		public string Name { get; set; }
		public string SignaturesPath { get; set; }
		public string RulesPath { get; set; }
		public bool FastRuleScan { get; set; }

		public YaraHelper(bool fast = true)
		{
			Name = null;
			SignaturesPath = null;
			RulesPath = null;
			FastRuleScan = fast;
		}

		public YaraHelper(string rPath, bool fast = true)
			: this(fast)
		{
			RulesPath = rPath;
		}

		public YaraHelper(string sPath, string rPath, bool fast = true, string name = null)
			: this(rPath, fast)
		{
			Name = name;
			SignaturesPath = sPath;
		}
	}
	public class YaraExtension
	{
		public List<string> FileExtensions { get; set; }
		public string YaraFilePath { get; set; }


		public YaraExtension()
		{
			FileExtensions = new List<string>();
			YaraFilePath = null;
		}
	}
}
