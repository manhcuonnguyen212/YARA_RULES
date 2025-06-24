using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace Ytest
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("This is a test file for Yara.");
            Console.WriteLine("Embedded trigger strings are:");

            List<string> triggerStrings = new List<string>()
            {
                "Ws2_32.dll",
	            "wsock32.dll",
                "System.Net",
                "WSAStartup",
                "sendto",
                "recvfrom",
                "WSASendTo",
                "WSARecvFrom",
                "UdpClient"
            };

            foreach (var s in triggerStrings)
            {
                Console.WriteLine("\t - "+s);
            }

            var processes = Process.GetProcessesByName("Program_Static_Ytest");            
            foreach (var p in processes)
            {
                Console.WriteLine($"Ytest process found with ID: {p.Id}");
            }
            Console.WriteLine("Ready for Yara rule testing....");
            Console.ReadLine();
        }
    }
}
