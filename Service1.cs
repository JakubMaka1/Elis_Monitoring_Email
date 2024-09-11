using MailKit.Net.Imap;
using MailKit.Search;
using MailKit.Security;
using MailKit;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using Newtonsoft.Json.Linq;
using System.Linq;
using System.Net.Http;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using static System.Net.WebRequestMethods;
using System.Net.Mail;
using System.Xml.Linq;
using System.Security.Authentication;
using System.Net;

namespace Elis_Monitoring_Email
{
    public static class GlobalsVariables
    {
        public static string email = Environment.GetEnvironmentVariable("EMAIL_ADDRESS");        
        public static string appPassword = Environment.GetEnvironmentVariable("EMAIL_PASSCODE");
        public static string logEmailPath = "C:/Logs/EmailLog.txt";
        public static string logSystemPath = "C:/Logs/SystemLog.txt";
        public static string filePolicyMainPath = "C:/Logs/Policy_Main.txt";
        public static string filePolicyInternetPath = "C:/Logs/Policy_Internet.txt";
        public static string filePolicyVPNPath = "C:/Logs/Policy_VPN.txt";
        public static string filePolicySitePath = "C:/Logs/Policy_Site.txt";
        public static string dateFormat = "dd.MM.yyyy HH:mm:ss";
    }
    [RunInstaller(true)]
    public partial class Service1 : ServiceBase
    {
        private CancellationTokenSource _cancellationTokenSource;
        private Task _monitoringTask;

        public Service1()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            _cancellationTokenSource = new CancellationTokenSource();
            _monitoringTask = Task.Run(() => StartMonitoring(_cancellationTokenSource.Token));
            
        }

        protected override void OnStop()
        {
            _cancellationTokenSource.Cancel();
            SMTP.SendEmail("jakub.maka@elis.com", "Error", "Wyłaczenie programu");
            Logger.WriteSystemLog("OnStop");
            
        }

        private async Task StartMonitoring(CancellationToken cancellationToken)
        {
            ProgramRuntime programRuntime = new ProgramRuntime();
            Logger.WriteSystemLog("StartMonitoring");
            
            //Logger.CompareDate();

            if (GlobalsVariables.email == null || GlobalsVariables.appPassword == null)
            {
                Logger.WriteEmailLog("Email or password environment variable is not set.");
                SMTP.SendEmail("jakub.maka@elis.com", "Error", "Email or password environment variable is not set.");
            }
            
        StartMonitoringLoop:
            using (var client = new ImapClient())
            {
                Logger.WriteSystemLog("ImapClient");
                string who = string.Empty;
                
                try
                {
                    //ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;

                    // Ustawienia timeoutu
                    client.Timeout = 60000;  // 60 sekund                    

                    // Łączenie się z klientem

                    await client.ConnectAsync("imap.gmail.com", 993, SecureSocketOptions.SslOnConnect);
                    Logger.WriteSystemLog("Laczenie z imap");
                    await client.AuthenticateAsync(GlobalsVariables.email, GlobalsVariables.appPassword);
                    var inbox = client.Inbox;
                    await inbox.OpenAsync(FolderAccess.ReadWrite);

                    Logger.WriteSystemLog("Monitoring folderu INBOX...");

                    while (!cancellationToken.IsCancellationRequested)
                    {
                        await inbox.CheckAsync(cancellationToken);
                        var uids = await inbox.SearchAsync(SearchQuery.NotSeen);

                        foreach (var uid in uids)
                        {
                            // Czyszczenie logów
                            Logger.CleanOldLogs(GlobalsVariables.logEmailPath);
                            Logger.CleanOldLogs(GlobalsVariables.logSystemPath);

                            var message = await inbox.GetMessageAsync(uid);
                            who = message.From.ToString();
                            Logger.WriteEmailLog($"Odebrano wiadomość: {message.Subject}");
                            Logger.WriteSystemLog($"Otrzymano od {who} ");
                            await inbox.AddFlagsAsync(uid, MessageFlags.Seen, true);

                            //Wyłączenie security policy a więc wyłaczenie włączonych polityk
                            if (Regex.IsMatch(message.TextBody, $@"\b{Regex.Escape("DisablE")}\b"))
                            {
                                string PathFlie = GlobalsVariables.filePolicyMainPath;
                                string jsonData = "{ \"status\": \"disable\" }";
                                await SendPutRequest(jsonData, who, PathFlie);
                                string getResult = await SendGETRequest(PathFlie);
                                SMTP.SendEmail(who, "Przetworzono wiadomość", $"Wynik zapytania GET:\n{getResult}");

                            }
                            //Włączenie security policy
                            if (Regex.IsMatch(message.TextBody, $@"\b{Regex.Escape("EnablE")}\b"))
                            {
                                string PathFlie = GlobalsVariables.filePolicyMainPath;
                                string jsonData = "{ \"status\": \"enable\" }";
                                await SendPutRequest(jsonData, who, PathFlie);
                                string getResult = await SendGETRequest(PathFlie);
                                SMTP.SendEmail(who, "Przetworzono wiadomość", $"Wynik zapytania GET:\n{getResult}");

                            }
                            //Włączenie konretnych security policy odpowiedzialnych za zablokowanie VPN
                            if (Regex.IsMatch(message.TextBody, $@"\b{Regex.Escape("vPn")}\b"))
                            {
                                string PathFlie = GlobalsVariables.filePolicyVPNPath;
                                string jsonData = "{ \"status\": \"enable\" }";
                                await SendPutRequest(jsonData, who, PathFlie);
                                string getResult = await SendGETRequest(PathFlie);
                                SMTP.SendEmail(who, "Przetworzono wiadomość", $"Wynik zapytania GET:\n{getResult}");

                            }
                            //Włączenie konretnych security policy odpowiedzialnych za zablokowanie Site
                            if (Regex.IsMatch(message.TextBody, $@"\b{Regex.Escape("sItE")}\b"))
                            {
                                string PathFlie = GlobalsVariables.filePolicySitePath;
                                string jsonData = "{ \"status\": \"enable\" }";
                                await SendPutRequest(jsonData, who, PathFlie);
                                string getResult = await SendGETRequest(PathFlie);
                                SMTP.SendEmail(who, "Przetworzono wiadomość", $"Wynik zapytania GET:\n{getResult}");

                            }
                            //Włączenie konretnych security policy odpowiedzialnych za zablokowanie Intenret
                            if (Regex.IsMatch(message.TextBody, $@"\b{Regex.Escape("iNtErNeT")}\b"))
                            {
                                string PathFlie = GlobalsVariables.filePolicyInternetPath;
                                string jsonData = "{ \"status\": \"enable\" }";
                                await SendPutRequest(jsonData, who, PathFlie);
                                string getResult = await SendGETRequest(PathFlie);
                                SMTP.SendEmail(who, "Przetworzono wiadomość", $"Wynik zapytania GET:\n{getResult}");

                            }

                        }
                        await Task.Delay(10000, cancellationToken);
                    }
                    await client.DisconnectAsync(true);
                }
                catch (ImapProtocolException ex)
                {
                    Logger.WriteSystemLog($"ImapProtocolException: {ex.Message}. Próba ponownego połączenia...");
                    await client.DisconnectAsync(true);
                    goto StartMonitoringLoop;  // Ponowne uruchomienie połączenia
                }
                catch (IOException ex)
                {
                    Logger.WriteSystemLog($"IOException: {ex.Message}. Próba ponownego połączenia...");
                    await client.DisconnectAsync(true);
                    goto StartMonitoringLoop;  // Ponowne uruchomienie połączenia
                }
                catch (OperationCanceledException)
                {
                    Console.WriteLine("Operacja anulowana.");
                    Logger.WriteSystemLog("Operacja anulowana.");
                    programRuntime.ErrorStopAndDisplayRuntime("Operacja anulowana");
                }
                catch (Exception ex) //błąd gdy forti jest wyłaczony 
                {
                    Console.WriteLine($"Wystąpił błąd: {ex.Message}");
                    Logger.WriteSystemLog($"Wystąpił błąd catch ex: {ex.Message}");
                    SMTP.SendEmail("jakub.maka@elis.com", "Error z połaczeniem z FG", $"Wystąpił błąd: {ex.Message}");
                    await client.DisconnectAsync(true);

                    goto StartMonitoringLoop;  // Ponowne uruchomienie połączenia
                }
            }
        }

        private async Task SendPutRequest(string jsonData, string who, string PathFile)
        {
            Logger.WriteSystemLog("SendPutRequest started");

            using (var httpClient = new HttpClient())
            {

                string[] policyLines = System.IO.File.ReadAllLines(PathFile);

                foreach (var policy in policyLines)
                {
                    try
                    {
                        var content = new StringContent(jsonData, Encoding.UTF8, "application/json");
                        var response = await httpClient.PutAsync($"https://172.19.8.254:8443/api/v2/cmdb/firewall/policy/{policy}/?access_token=qQ6nbj043zyqzhnf8typm49nq4Q1f7", content);

                        if (response.IsSuccessStatusCode)
                        {
                            Logger.WriteSystemLog("Operacja aktualizacji statusu udana.");
                        }
                        else
                        {
                            Logger.WriteSystemLog($"Wystąpił błąd else send put: {response.StatusCode}");
                            SMTP.SendEmail(who, "Error_PUT", $"Wystąpił błąd: {response.StatusCode}");
                        }
                    }

                    catch (Exception ex)
                    {
                        // Logowanie wyjątku
                        string exceptionMessage = $"Wyjątek podczas aktualizacji policy {policy}: {ex.Message}";
                        Logger.WriteSystemLog(exceptionMessage);

                        // Wysyłanie e-maila z informacją o wyjątku
                        SMTP.SendEmail(who, "Error_PUT", $"Wystąpił wyjątek podczas aktualizacji policy {policy}. \nSzczegóły: {ex.Message}");
                    }

                }
            }
        }


        private async Task<string> SendGETRequest(string PathFile)
        {
            // Tworzenie zmiennej do przechowywania wyników, które będą wysłane w mailu
            StringBuilder resultBuilder = new StringBuilder();
            Logger.WriteSystemLog("SendGETRequest started");

            using (var httpClient = new HttpClient())
            {
                string[] policyLines = System.IO.File.ReadAllLines(PathFile);

                foreach (var policy in policyLines)
                {
                    HttpResponseMessage response = await httpClient.GetAsync($"https://172.19.8.254:8443/api/v2/cmdb/firewall/policy/{policy}?access_token=qQ6nbj043zyqzhnf8typm49nq4Q1f7");
                    string json = await response.Content.ReadAsStringAsync();
                    JObject jsonObject = JObject.Parse(json);

                    foreach (var result in jsonObject["results"])
                    {
                        if ((string)result["policyid"] == policy)
                        {
                            Logger.WriteEmailLog($"Nazwa policy: {result["name"]}");
                            Logger.WriteEmailLog($"Aktualny status: {result["status"]}");
                            Logger.WriteSystemLog($"Nazwa policy: {result["name"]}");
                            Logger.WriteSystemLog($"Aktualny status: {result["status"]}");

                            // Dodanie wyników do zmiennej StringBuilder
                            resultBuilder.AppendLine($"{DateTime.Now} Nazwa policy: {result["name"]}");
                            resultBuilder.AppendLine($"{DateTime.Now} Aktualny status: {result["status"]}");
                            resultBuilder.AppendLine();
                        }
                    }
                }
            }
            return resultBuilder.ToString();
        }

    }
}
