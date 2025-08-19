using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace MAVI_Payload_Windows
{
    public partial class Service1 : ServiceBase
    {
        private Thread workerThread;
        public Service1()
        {
            InitializeComponent();
            this.ServiceName = "MAVI Service";
        }

        protected override void OnStart(string[] args)
        {
            workerThread = new Thread(() =>
            {
                try
                {
                    StartServiceWorker();
                }
                catch (Exception _ex)
                {
                    Console.WriteLine("Exception: " + _ex.Message);
                    Environment.Exit(1);
                };
            });
            workerThread.IsBackground = true;
            workerThread.Start();
        }

        protected override void OnStop()
        {
            StopServiceWorker();
            if (workerThread != null && workerThread.IsAlive)
            {
                workerThread.Join();
            }
        }

        [DllImport("ServiceWorker.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void StartServiceWorker();

        [DllImport("ServiceWorker.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void StopServiceWorker();
    }
}
