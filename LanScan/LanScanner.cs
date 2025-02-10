using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace LanScan;

public class LanScanner
{

    public async Task<List<IPAddress>> ScanNetwork()
    {
        ConcurrentBag<IPAddress> addresses = new ConcurrentBag<IPAddress>();
        var local = GetLocalIPAddress() ?? throw new Exception("Error retrieving local IP address.");
        var subnet = GetSubnetMask(local) ?? throw new Exception("Error retrieving subnet mask.");

        var (networkAddress, broadcastAddress) = GetSubnetRange(local, subnet);

        uint start = IpToUInt(networkAddress);
        uint end = IpToUInt(broadcastAddress);

        var pingTasks = new List<Task>();

        for (uint i = start; i < end; i++)
        {
            var pingAddress = UIntToIp(i);
            pingTasks.Add(PingDevice(pingAddress, addresses));
        }

        await Task.WhenAll(pingTasks);

        return addresses.ToList();
    }

    private async Task PingDevice(IPAddress address, ConcurrentBag<IPAddress> ips)
    {
        try
        {
            using Ping p = new Ping();
            var reply = await p.SendPingAsync(address, 1000);
            if (reply.Status == IPStatus.Success)
            {
                ips.Add(address);
            }
        }
        catch
        {
            // Do nothing
        }
    }
    private IPAddress? GetLocalIPAddress()
    {
        var host = Dns.GetHostEntry(Dns.GetHostName());
        foreach (var ip in host.AddressList)
        {
            if (ip.AddressFamily == AddressFamily.InterNetwork) return ip;
        }
        return null;
    }

    private IPAddress? GetSubnetMask(IPAddress localIp)
    {
        var interfaces = NetworkInterface.GetAllNetworkInterfaces();
        foreach (var interf in interfaces)
        {
            if (interf.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                interf.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;
            var ipInfo = interf.GetIPProperties();
            foreach (var ip in ipInfo.UnicastAddresses)
            {
                if (localIp.Equals(ip.Address)) return ip.IPv4Mask;
            }
        }
        return null;
    }

    private (IPAddress, IPAddress) GetSubnetRange(IPAddress localIp, IPAddress subnetMask)
    {
        byte[] ipBytes = localIp.GetAddressBytes();
        byte[] subnetBytes = subnetMask.GetAddressBytes();

        if (ipBytes.Length != subnetBytes.Length) throw new ArgumentException("Lengths of IP address and subnet mask do not match.");

        byte[] networkBytes = new byte[ipBytes.Length];
        byte[] broadcastBytes = new byte[subnetBytes.Length];

        for (int i = 0; i < networkBytes.Length; i++)
        {
            networkBytes[i] = (byte)(ipBytes[i] & subnetBytes[i]);
            broadcastBytes[i] = (byte)(ipBytes[i] | ~subnetBytes[i]);
        }

        return (new IPAddress(networkBytes), new IPAddress(broadcastBytes));
    }

    private uint IpToUInt(IPAddress ip)
    {
        byte[] bytes = ip.GetAddressBytes();
        return (uint)bytes[0] << 24 | (uint)bytes[1] << 16 | (uint)bytes[2] << 8 | bytes[3];
    }

    private IPAddress UIntToIp(uint ip)
    {
        return IPAddress.Parse($"{ip >> 24 & 0xFF}.{ip >> 16 & 0xFF}.{ip >> 8 & 0xFF}.{ip & 0xFF}");
    }
}