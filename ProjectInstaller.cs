﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ComponentModel;
using System.Configuration.Install;
using System.ServiceProcess;

namespace Elis_Monitoring_Email
{

    [RunInstaller(true)]
    public class ProjectInstaller : Installer
    {
        private ServiceInstaller serviceInstaller;
        private ServiceProcessInstaller processInstaller;

        public ProjectInstaller()
        {
            // Tworzenie i konfigurowanie processInstaller
            processInstaller = new ServiceProcessInstaller();
            processInstaller.Account = ServiceAccount.LocalSystem;

            // Tworzenie i konfigurowanie serviceInstaller
            serviceInstaller = new ServiceInstaller();
            serviceInstaller.ServiceName = "Elis_Monitoring_Email";
            serviceInstaller.DisplayName = "Elis_Monitoring_Email";
            serviceInstaller.Description = "Elis Textile Service POLAND";
            serviceInstaller.StartType = ServiceStartMode.Automatic;

            // Dodawanie instalatorów do kolekcji Installers
            Installers.Add(processInstaller);
            Installers.Add(serviceInstaller);
        }
    }
}