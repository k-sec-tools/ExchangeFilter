using System.Net;

namespace ExchangeFilter
{
	public static class IpAddressAnalysys
	{
		//public static readonly ILog log = LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

		public static bool AreIpAddressesEqual(IPAddress ip1, IPAddress ip2)
		{
			return Equals(ip1, ip2);
		}

		public static bool IsIpAddressInSubnet(IPAddress ipaddress, string subnet)
		{
			//using ipnetwork https://github.com/lduchosal/ipnetwork

			if (subnet.Contains("/"))
			{
				var ipnetwork = IPNetwork.Parse(subnet);
				return IsIpAddressInSubnet(ipnetwork, ipaddress);
			}
			var ipaddress2 = IPAddress.Parse(subnet);
			return AreIpAddressesEqual(ipaddress, ipaddress2);

		}

		public static bool IsIpAddressInSubnet(IPNetwork subnet, IPAddress address)
		{
			var ipnetwork = subnet;
			var ipaddress = address;
			return ipnetwork.Contains(ipaddress);
		}

	}
}
