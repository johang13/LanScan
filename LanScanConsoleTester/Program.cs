using LanScan;

var scanner = new LanScanner();
var lanDevices = await scanner.ScanNetwork();
foreach (var device in lanDevices)
{
    Console.WriteLine(device);
}