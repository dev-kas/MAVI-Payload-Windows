using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TestingFrameworkCLI
{
    internal class Program
    {
        private static Thread workerThread;
        static void Main(string[] args)
        {
            Console.WriteLine("Testing Framework CLI started.");

            workerThread = new Thread(() =>
            {
                try
                {
                    StartServiceWorker();
                }
                catch (Exception ex)
                {
                    System.IO.File.AppendAllText(@"C:\mavi.txt", "Exception: " + ex.Message + "\n");
                    Environment.Exit(1);
                }
                ;
            });
            workerThread.IsBackground = true;
            workerThread.Start();

            Console.WriteLine("Press Enter to stop the service.");
            Console.ReadLine();

            StopServiceWorker();
            if (workerThread != null && workerThread.IsAlive)
            {
                workerThread.Join();
            }

            Console.WriteLine("Testing Framework CLI stopped.");
        }

        [DllImport("C:\\Users\\kas\\source\\repos\\MAVI-Payload-Windows\\x64\\Release\\ServiceWorker.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void StartServiceWorker();

        [DllImport("C:\\Users\\kas\\source\\repos\\MAVI-Payload-Windows\\x64\\Release\\ServiceWorker.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void StopServiceWorker();
    }
}
