using SharpSploit.Enumeration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Principal;
//using System.Management.Automation;

namespace ad_security_checker
{
    class Program
    {

        public static FileStream fs = new FileStream("secusploit.txt", FileMode.Create);
        public static StreamWriter sw = new StreamWriter(fs);
        public static String DomainName;
        static void Main(string[] args)
        {
            art();
            Console.WriteLine("[*] Checking which mode to run");
            int mode;
            if (args.Length == 0)
            {
                mode = 1;
                Console.WriteLine("[+] Starting without arguments and defaulting to mode1. For mode2 run with argument -mode2");
                Console.WriteLine("[+] Output file will be: secusploit.txt");
            }
            else
                if (args[1] == "-mode2")
            {
                mode = 2;
                Console.WriteLine("Running in mode2");
            }
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[*]AV muste be disabled. More Information: ");
            Console.WriteLine("[*] https://www.tenforums.com/tutorials/5918-turn-off-windows-defender-antivirus-windows-10-a.html");
            Console.ResetColor();
            Console.WriteLine("[*] Checking if user has local administrator rights");

            if ((!checkAdministrator()))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Please make sure to run as Administrator");
                Console.ForegroundColor = ConsoleColor.White;

            }
            else
                Console.WriteLine("[+] Running as local Administrator");
            //create FileStream Object to create Textfile
            //public static FileStream fs = new FileStream("Test.txt", FileMode.Create);
            // First, save the standard output.
            TextWriter tmp = Console.Out;
            //public static StreamWriter sw = new StreamWriter(fs);
            // Redirect output to Textfile
            DateTime currentDate = DateTime.Now;
            sw.WriteLine(currentDate);
            sw.WriteLine("Running in Mode1");

            //check for admin privs and run the mode selector
            if (checkAdministrator() == true)
            {
                modeSelector(1);
            }

            sw.Close();
        }


        static void modeSelector(int mode)
        {
            //gets the run mode and calls the needed funtions for run mode
            if (mode == 1)
            {
                getDomainName();
                GetDomainAdministrators();
                GetDomainLevel();
                GetDomainControllers();
                GetGroupPolicies();

            }
            else if (mode == 2)
            {
                //unsupported yet
            }
            else
                Console.WriteLine("Unknown mode: quitting");
        }

        public static bool IsAdministrator()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        static Boolean checkAdministrator()
        {
            //check for Admin Privs
            return true;
        }

        static string getIPAdress(string HostName)
        {
            System.Net.IPAddress[] ip = System.Net.Dns.GetHostAddresses(HostName);
            return ip.ToString();
        }

        static String getSessionsOfUsers(string UserName)
        {
            //gets an enumerated domain admin and checks of the user has any sessions on a host
            //get notificatio if SRM is needed

            return UserName;
        }
        static void getDomainName()
        {
            Console.WriteLine("[*] Getting Domain Name");
            DomainName = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
            Console.WriteLine("[+] Domain Name is: " + DomainName);
            sw.WriteLine("Domain Name is: " + DomainName);
        }

        static void GetDomainAdministrators()
        {
            //checks the domain for users with domain administrator rights or higher
            //checks wether those users have sessions on any host of the domain
            Console.WriteLine("[*] Enumerating Administrators");
            Domain.DomainSearcher searcher = new Domain.DomainSearcher();
            IList<Domain.DomainObject> users = searcher.GetDomainUsers(null);
            sw.WriteLine("Domain Administrators:");

            //List of logged in Users of a System


            foreach (Domain.DomainObject user in users)
            {

                if ((user.admincount == "1" && !(user.name.Contains("$")) && !(user.name.Contains("krbtgt"))))
                {
                    Console.WriteLine("[+] Found Domain Administrator: " + user.name.ToString());
                    sw.WriteLine("\\item " + user.name.ToString());

                    SharpSploit.Enumeration.Domain.DomainSearcher usersearcher = new SharpSploit.Enumeration.Domain.DomainSearcher();
                    List<SharpSploit.Enumeration.Domain.DomainObject> c = usersearcher.GetDomainComputers();
                   
                        foreach (SharpSploit.Enumeration.Domain.DomainObject val in c)
                        {

                            List<Net.LoggedOnUser> AdministratorSessions = Net.GetNetLoggedOnUsers(new List<string> { val.name });
                            foreach (var b in AdministratorSessions)
                            {

                                if ((!(b.UserName.Contains("$")) && b.UserName == user.name))
                                {
                                    Console.WriteLine("[+] Found session on " + b.ComputerName + " for: " + b.UserName);
                                    sw.WriteLine("[+] Found session on " + b.ComputerName + " for: " + b.UserName);

                            }

                            }
                        }
                    

                    

                }
            }


        }
        static void GetDomainLevel()
        {


            Console.WriteLine("[*] Enumerating Domain Mode Function Level");
            //string a = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().ToString();
            //System.DirectoryServices.ActiveDirectory.Domain searcher = new System.DirectoryServices.ActiveDirectory.Domain(get);
            //<List<Domain.DomainObject> abc = new List<Domain.DomainObject>(null);
            //Console.WriteLine(a);
            //System.DirectoryServices.ActiveDirectory.Domain domain = new System.DirectoryServices.ActiveDirectory();
        }

        static void GetDomainControllers()
        {
            //gets the Domain Controllers of the Domain and prints the logged in Users

            Console.WriteLine("[*] Enumerating Domain Controllers and logged on User Sessions");
            Console.WriteLine("[*] Multiple Sessions of a single User on a Domain Controller possible");
            //used as a concatinated string of the hostnames of all DCs found to pass into the nmap command
            string dc_hostnames = "";

            //Create Domain Searcher
            SharpSploit.Enumeration.Domain.DomainSearcher searcher = new SharpSploit.Enumeration.Domain.DomainSearcher();
            //Create list of Domain Computers
            List<SharpSploit.Enumeration.Domain.DomainObject> a = searcher.GetDomainComputers();

            //Create List of String Objects containing the found Domain Controllers
            List<Net.LoggedOnUser> users;


            //Iterate through all Domain Objects (Domain Computers) 
            List<String> DomainControllers = new List<string>();
            sw.WriteLine("Domain Controllers:");

            foreach (SharpSploit.Enumeration.Domain.DomainObject val in a)
            {
                if (val.cn.Contains("DC"))
                {
                    //store in List of Domain Controllers
                    DomainControllers.Add(val.name.ToString());
                    //output the found Domain Controllers and write also to output file
                    Console.WriteLine("[+] Found Domain Controller: " + val.name.ToString());
                    if (dc_hostnames == "")
                        dc_hostnames = val.name.ToString();
                    else
                        dc_hostnames = dc_hostnames + ", " + val.name.ToString();
                    sw.WriteLine("\\item " + "\\textbf{" + val.name.ToString() + "}");
                    users = Net.GetNetLoggedOnUsers(new List<string> { val.name });

                    sw.WriteLine("List of logged in Users on " + val.name + ":");
                    //iterate over list of logged on users for the domain object
                    foreach (var s in users)
                    {
                        //filter out "Windows Computer Accounts"
                        if (!(s.UserName.Contains("$")))
                        {
                            Console.WriteLine("[+] Found user session on " + val.name + ": " + s.UserName);
                            sw.WriteLine("\\item" + "" + s.UserName);
                        }
                    }
                }
            }


            //create Todo for manual enumration of SMB-Signing with nmap
            Console.WriteLine("[+] To Do: manual Enumeration of SMB-Signing of the Domain Controllers");
            sw.WriteLine("To Do: Check if SMB-Signing enabled on the host:");
            sw.WriteLine("nmap -p137,139,445 --script smb-security-mode " + dc_hostnames);

        }

        static void GetGroupPolicies()
        {
            //PowerShell ps = PowerShell.Create();
            SharpSploit.Enumeration.GPO hodor = new SharpSploit.Enumeration.GPO();

            //ps.AddCommand("Get-Date");
            //ps.Invoke();
            //String s = SharpSploit.Enumeration.GPO.GetRemoteAccessPolicies.ToString();


        }


        static void art()
        {
            string asci =
            @"
                           
                             ___ ___ _    ___ ___ _____ 
             ___ ___ __ _  _/ __| _ \ |  / _ \_ _|_   _|
            (_-</ -_) _| || \__ \  _/ |_| (_) | |  | |  
            /__/\___\__|\_,_|___/_| |____\___/___| |_|  
                                                        ";

            string console = "@                           [non Axiforma Edition v 0.1]@@";


            console = console.Replace("@", System.Environment.NewLine);
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(asci);
            Console.WriteLine(console);
            Console.ResetColor();
        }
    }
}