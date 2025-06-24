using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.IO;
namespace Ytest
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("This is a test file for Yara.");
            Console.WriteLine("Embedded trigger strings are:");

            try
            { 
                var triggerFile = File.ReadAllLines("D:\\YARA\\YARA_RULES\\YARA_RULES\\Ytest.txt");
                var triggerStrings = new List<string>(triggerFile);

                foreach (var s in triggerStrings)
                {
                    Console.WriteLine("\t - " + s);
                }
            }
            catch (Exception e)
            { 
                Console.WriteLine("There was an error getting the trigger list.  Make sure Ytest.txt is in the current directory.");
                Console.ReadLine();
                Environment.Exit(0);
            };
                       

            var processes = Process.GetProcessesByName("Program_Dynamic_Ytest");            
            foreach (var p in processes)
            {
                Console.WriteLine($"Ytest process found with ID: {p.Id}");
            }
            Console.WriteLine("Ready for Yara rule testing....");
            Console.ReadLine();
        }
    }
}


