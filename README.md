###### ⚠️ `Disclaimer`: This walkthrough is intended solely for educational purposes to enhance the learner's understanding of cybersecurity concepts, tools, and methodologies. This includes hands-on practice scripting/programming and using the terminal/shell to write complex commands. It is carefully written to avoid revealing flags, specific answers, credentials, or any information that could spoil the learning experience. All credit for the lab content and challenge design goes to TryHackMe as the original source. Learners are encouraged to complete the lab independently before referring to this guide for support.

# Lookup Walkthrough-TryHackMe

<img src="https://github.com/user-attachments/assets/e75c95dc-e1a7-4a81-8ef4-6afda360ae96" height="150" width="300" >

## 🔶 Introduction

`Lookup` offers you a treasure trove of learning opportunities as an aspiring ethical hacker. This engaging `TryHackMe` lab challenges you with real-world vulnerabilities — from web application flaws to privilege escalation techniques — giving you hands-on experience that sharpens your hacking skills.

As you explore `Lookup`, you'll dive deep into reconnaissance, scanning, and enumeration, uncovering hidden services and subdomains. You'll learn to exploit web vulnerabilities like command injection and gain a deeper understanding of why secure coding practices matter.

Beyond just manual exploitation, `Lookup` encourages you to automate tasks, showing you the power of scripting in penetration testing. It's a lab that pushes you to think like an attacker — and grow like a pro.

## 🔶 Reconnaissance, Scanning, and Enumeration

### ✅ Step 1: Reconnaissance and Scanning

To kick off the `reconnaissance` phase, the goal is to gather preliminary information about the target with minimal interaction. This step helps us identify whether the host is online and reachable — a crucial starting point before deeper scanning. We’ll begin by performing basic host discovery on the `Target IP Address` using an `Nmap` ping sweep scan to check if the target is up.

**🔹 Ping Sweep Scan:** *`nmap -sn 10.10.x.x`*

![image](https://github.com/user-attachments/assets/9f5e59bd-f1fb-4eb6-aafc-82022872a13c)

Since the `host` is live, the next step is to identify which common ports are open. This helps us determine what services might be running and where to focus our enumeration efforts.

We can perform a `basic port scan` of the `top 1,000` most commonly used ports. This default scan checks only for open ports and gives a quick overview of the most likely entry points.

**🔹 Basic Port Scan:** *`nmap 10.10.x.x`*

![image](https://github.com/user-attachments/assets/11ebd3d8-cb90-4e66-b4d7-9c7816e93fbb)

As a result, we discovered that `ports 22 (SSH)` and `80 (HTTP)` are open. This indicates that the machine is running an `SSH service` and a `web server` — both of which are common entry points for further exploration.

To gather more information about these services, we’ll perform a `version detection scan` to identify the exact software and versions running on each port. This can help determine if there are any known vulnerabilities associated with the specific versions of the services.

**🔹 Version Detection Scan:** *`nmap -sV -p 22,80 10.10.x.x`*

![image](https://github.com/user-attachments/assets/ad18b1c2-5504-43b5-a046-adbe45a14fe8)

The `version detection scan` revealed that `Apache httpd 2.4.41` is running on `port 80`. With this information, we now have a few paths to explore.

### ✅ Step 2: Web Server Enumeration

Visit the `target IP address` in your browser or use *`curl`* to check the `HTTP responses`.

**🔹 Open 10.10.x.x in Firefox**

![image](https://github.com/user-attachments/assets/c12dd862-d6a5-4100-9497-bdcdcf1d0f2a)

![image](https://github.com/user-attachments/assets/83a04cd0-66ee-41d3-a508-b90d30c04c04)

We can see the `target IP address` returns to `http://lookup.thm/`, along with `“Server Not Found”` and `“Connection failure”` messages. 

**🔹 Use Curl:** *`curl -I 10.10.x.x`*

![image](https://github.com/user-attachments/assets/8a1ad7e4-d839-4284-9ebf-2cf6a8b404c3)

We can also see the `target IP address` returns to `http://lookup.thm`.

Now, these results mean the `web server` is working and issuing a redirect (hence the `HTTP/1.1 302 Found`), but our system doesn’t know where `lookup.thm` is — so it fails with `“Server Not Found”`.

### ✅ Step 3: Set Up Local DNS Resolution

To fix this redirect, open the `/etc/hosts` file in a text editor (e.g., `nano`) with `sudo` and add a line at the bottom; mapping `lookup.thm` to the `target’s IP address` (e.g., `10.10.x.x`), as shown below. Then, save and exit the file.

**🔹 Edit the `hosts` file:** *`sudo nano /etc/hosts`*

![image](https://github.com/user-attachments/assets/f93fae87-9d07-4325-8650-084d115106ba)

![image](https://github.com/user-attachments/assets/8cc66241-9f0e-4ab4-b2d7-33c0079f2a80)

### ✅ Step 4: Web Server Enumeration – Continue

Once we’ve updated the `hosts` file, visit the `target IP address` in your browser again.

**🔹 Open 10.10.x.x in Firefox**

![image](https://github.com/user-attachments/assets/17657bc5-92bd-4274-b0a0-21d1dc919819)

Once again, we observe that accessing the `target IP` redirects us to `http://lookup.thm/`. This time, it presents a running `web application` featuring a `login page` interface that prompts for a `username` and `password`. This authentication mechanism opens up potential avenues for `web exploitation`, including `credential brute-forcing`, `SQL injection`, and `authentication bypass` techniques. 

## 🔶 Web Application Enumeration and Exploitation

### ✅ Step 1: Web Application Enumeration

While testing common credentials, such as `admin:admin`, the web application redirects to a `/login.php` page, which means the login logic is handled there, along with an error message `"Wrong password. Please try again."`, as shown below. This indicates that the `username` might exist in the backend database while the `password` is incorrect, meaning the application is checking `usernames` first, then validating `passwords`.

![image](https://github.com/user-attachments/assets/366c8d1c-f645-4f78-a728-c3fb115b1a45)

Based on the specific error message returned, we can attempt to enumerate additional `usernames` to identify which ones may exist in the system, this will allow us to focus our efforts on targeted `password` attacks, significantly increasing our chances of gaining unauthorized access.

### ✅ Step 2: Username Enumeration – Python Script

To streamline this approach, we can develop a custom script to automate the process of enumerating potential `usernames`. For this task, we’ll utilize `Python` as our scripting language due to its simplicity, flexibility, and wide support for `HTTP libraries`. By scripting the enumeration process, we can efficiently test a large number of `usernames` against the `login interface` and analyze the application's responses to identify valid accounts.

The `Python-based Username Enumerator` script below is designed to target the `login endpoint` at `http://lookup.thm/login.php`, with the `URL` statically defined within the source code. It utilizes the `names.txt` wordlist located at `/usr/share/seclists/Usernames/Names/names.txt`, going through each entry in the list to test for valid `usernames`. Each `username` is sent in a `login request`, and based on the presence of a specific message like `"Wrong password"` in the `HTTP response`, the script determines whether a `username` likely exists—automating the enumeration process efficiently within a single loop.

**🔹 If necessary, install seclists:** *`sudo apt install seclists`*

**Note:** Ensure that the specific message `"Wrong password"` is accurately written in your `Python` script, matching the exact casing and wording used by the web application, as it is case-sensitive and any variation may result in incorrect detection of valid `usernames`.

![image](https://github.com/user-attachments/assets/850a5cda-0b51-44c1-95aa-2cd90bc887f0)

**Note:** Before running the `username enumerator` script, make sure your `TryHackMe` lab machine has sufficient remaining time to avoid any interruptions since the script may take approximately `30-40 minutes` to complete. 

Once you have your script (e.g., `username_enumerator.py`) saved, make sure you’re in the same directory as your `Python` script before you run it.

**🔹 Run username enumerator script:** *`python3 <your_script_name.py>`*

![image](https://github.com/user-attachments/assets/637b03d2-72eb-462d-9791-f667d2efc266)

After the script finishes running, we identify a second valid `username`, *`jxxx`* in addition to our previously suspected account *`admin`*.  This discovery strengthens our position for the next phase of the attack by expanding our list of potential targets. With multiple valid `usernames` at hand, we can now proceed to execute an `authentication bypass` attempt—this time through a focused `brute-force attack`—significantly increasing our chances of gaining unauthorized access.

### ✅ Step 3: Brute Force Attack

To proceed with this task, we’ll perform a `brute-force attack` targeting the `usernames` *`admin`* and *`jxxx`*. For this purpose, we’ll leverage `Hydra`, a powerful and widely-used tool designed specifically for password brute-forcing across various protocols.

`Hydra` will target the `HTTP POST login form` hosted on `http://lookup.thm/login.php`. It will attempt to authenticate using the specified `username` in combination with `password` guesses sourced from the popular `rockyou.txt` wordlist, which comes pre-installed in `Kali Linux`.

**Note:** By default, `rockyou.txt` is stored in the compressed format `rockyou.txt.gz`, which needs to be extracted.

**🔹 Extract `rockyou.txt`:** *`sudo gunzip /usr/share/wordlists/rockyou.txt.gz`*

You should see the `rockyou.txt` file on the `/usr/share/wordlists/` path.

The following `Hydra` command is configured to stop execution immediately after discovering the first valid `password` for the given `username`, improving efficiency and reducing unnecessary load on the target service.

![image](https://github.com/user-attachments/assets/40773fc0-3904-4136-aca0-684552eeeb79)

| **Part** | **Explanation** |
|-|-|
| -l | Indicates single `username` |
| *`jxxx`* | `Username` (verify case-sensitivity) |
| -P /usr/share/wordlists/rockyou.txt | Path to your `password` list |
| lookup.thm | Target domain (make sure it’s resolved or in /etc/hosts) |
| http-post-form | Protocol/module to use |
| /login.php | Form path |
| username=^USER^&password=^PASS^ | `POST` parameters (`Hydra` swaps `^USER^` and `^PASS^`) |
| Wrong password | Response string to detect failure (`Wrong password`) |
| -t 4 | Number of parallel tasks (adjust as needed) |
| -f | Stop after finding the first valid `password` for the `username` |

**Note:** After executing the `Hydra` command, it will take approximately `10 minutes` to complete.

As a result, `Hydra` successfully discovered a valid `password` for the user *`jxxx`*, as shown in the output below. However, when executing the `Hydra` command for the user *`admin`*, it returns the same `password` as found for *`jxxx`*. This behavior occurs because the command includes the `-f` flag, which instructs `Hydra` to stop after identifying the first valid `password`.

If we remove the `-f` flag, `Hydra` will continue testing the remaining `passwords` in the wordlist even after finding a valid one. However, in this specific scenario, `Hydra` continues to return the same `password` for both *`admin`* and *`jxxx`*. This is likely because the `rockyou.txt` wordlist does not contain additional `passwords` that trigger the failure response string `"Wrong password"` — allowing the login attempt to be considered successful.

This outcome suggests that both `usernames` may be sharing the same valid `password`, or that the application is not properly distinguishing failed attempts beyond the first correct match. Either way, the result gives us a working `password` to move forward in the exploitation phase.

![image](https://github.com/user-attachments/assets/a62f51fe-a8b9-48cb-aeaf-c7b3f6e5f210)

![image](https://github.com/user-attachments/assets/272554fb-f830-4ffc-ad16-617b0b83819a)

Now that we’ve successfully obtained valid credentials, we proceed to log in to `http://lookup.thm`. 

Upon authentication, the application attempts to redirect us to a new subdomain: `http://files.lookup.thm`. However, this request fails with a `"Server Not Found"` error.

![image](https://github.com/user-attachments/assets/24b81b17-13e1-46d6-a6cf-cce20d55d25f)   ![image](https://github.com/user-attachments/assets/fba2933c-5be5-4a6f-878d-3f08bb053d72)

This indicates that our local system cannot resolve the hostname `files.lookup.thm`—a similar situation like our earlier encounter during the initial web application enumeration phase. This suggests that we need to update our `/etc/hosts` file to manually map the new subdomain to the same `target IP address` to proceed with further analysis.

**🔹 Edit the `hosts` file:** *`sudo nano /etc/hosts`*

![image](https://github.com/user-attachments/assets/50af38a8-e44a-45ce-9683-9b9a8ab7c1dc)

Once we updated our `/etc/hosts` file to include the necessary subdomains, we can log in again using our valid credentials. 

### ✅ Step 4: Post-Authentication Enumeration

Upon successful authentication, we are redirected to the `files.lookup.thm` webpage, which reveals a web-based file management interface known as `elFinder`.

![image](https://github.com/user-attachments/assets/9e26eb47-61c4-4cb0-b115-b876e921ccca)

Navigating through the file structure, no files initially appear to contain sensitive or noteworthy content. However, accessing the `"About"` section of the application provides us with valuable insight into the underlying software, such as the current version of `elFinder` in use, `“Version 2.1.47”`.

![image](https://github.com/user-attachments/assets/a9cce57a-dd2f-41ba-90a4-857de9b98bcc)

This version detail is particularly significant—it may allow us to search for known vulnerabilities associated with this specific release, potentially opening the door to `privilege escalation` or `remote code execution` if the application is misconfigured or unpatched.

The next logical step is to investigate whether this specific version is affected by any known vulnerabilities. To accomplish this, we’ll utilize a powerful tool called `SearchSploit`, which comes pre-installed with `Kali Linux`.

`SearchSploit` allows you to query a local database of publicly disclosed exploits and advisories from the `Exploit Database (Exploit-DB)`. By running a targeted search with the keyword `"elFinder"`, we can quickly determine whether there are any documented vulnerabilities or proof-of-concept exploits available for this version. If a match is found, it could potentially present a clear path to exploiting the application, depending on the context and the permissions of the web service.

**🔹 Run SearchSploit:** *`searchsploit elfinder`*

![image](https://github.com/user-attachments/assets/0af3de01-ae19-4122-a70c-021ad027dc43)

As a result, we uncover four potential exploits related to the `elFinder` file manager. Among these findings, one exploit stands out in particular:
`PHP Connector < 2.1.48 - 'exiftran' Command Injection (Metasploit)`.

This specific exploit targets versions of `elFinder` prior to `2.1.48`, which aligns with the version currently deployed on the target system `2.1.47`. The exploit leverages a `command injection` vulnerability in the `exiftran` utility used by the `elFinder` `PHP connector`, potentially allowing for arbitrary command execution on the underlying server. Given that our target version falls within the vulnerable range, this exploit presents a compelling opportunity for further analysis and testing.

### ✅ Step 5: Web Application Exploitation

Considering that the identified vulnerability includes a dedicated `Metasploit` module, we’ll proceed by launching `Metasploit Framework (msfconsole)` to continue our exploitation approach. Utilizing `Metasploit` provides a streamlined and efficient way to deploy known exploits, especially when a module has already been crafted for a specific vulnerability.

After launching `Metasploit`, we'll search for matching modules related to `elFinder` by using the *`search elFinder`* command. This will help us identify the appropriate exploit module, in this case targeting the `exiftran` `command injection` vulnerability affecting versions of `elFinder` prior to `2.1.48`.

Once we locate the correct module, we’ll proceed to configure and execute it against the target, aiming to achieve `remote code execution` or establish a `shell` for further post-exploitation activities.

**🔹 Launch `Metasploit` Framework:** *`msfconsole`*

**🔹 Search `elFinder` Modules:** *`search elfinder`*

![image](https://github.com/user-attachments/assets/f5475c38-7f86-4cc6-bb02-c2f07749c421)

As a result, we are presented with five available modules, among them, we identify `Module #4: exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection`, which directly targets the `PHP Connector exiftran Command Injection` vulnerability affecting `elFinder` versions prior to `2.1.48`.

We’ll proceed by selecting it for exploitation; crafted to exploit improper input handling in the `exiftran` functionality, potentially allowing `remote code execution` on the server.

We'll load `module 4` using the *`use`* command in `Metasploit`.

**🔹 Load Module #4:** *`use 4`*

![image](https://github.com/user-attachments/assets/7fa41ca1-4edf-4078-801e-dfdc14297db7)

Next, we’ll proceed by configuring the exploit parameters. We begin by accessing the module’s `options menu`, which provides a comprehensive overview of all configurable settings, including `target URL`, `payload options`, and `required fields`. This step is critical, as it allows us to verify and customize each parameter to align with the specifics of our target.

**🔹 Access Options Menu:** *`show options`*

![image](https://github.com/user-attachments/assets/bc01fd90-b793-4c91-8af7-0e0557dd83b6)

Now, we'll set the `RHOSTS` parameter to `files.lookup.thm`, and then we’ll verify the change. This specifies the remote host that we intend to target. This step is essential because `RHOSTS` tells `Metasploit` where to direct the exploit. Since the vulnerable application—`elFinder` `version 2.1.47`—is hosted on the subdomain `files.lookup.thm`.

**🔹 Set `RHOSTS`:** *`set RHOSTS files.lookup.thm`*

**🔹 Access Options Menu:** *`show options`*

![image](https://github.com/user-attachments/assets/f58b51e4-4d32-4beb-8fae-976b30a08275)

Now we are ready to *`run`* our exploit. 

**🔹 Run Exploit:** *`run`*

![image](https://github.com/user-attachments/assets/9ea85fbf-0c90-45d1-ac7f-0192783a6e4e)

🛑 After trying to run the exploit, we encounter an error, `Exploit completed, but no session was created.`, indicating the exploit was executed, but it failed to establish a reverse connection back to our system. 

Since we are running a `Kali Linux VM` on `VirtualBox` and connected to the target environment via `OpenVPN` (as provided by `TryHackMe`), additional network configuration is required to ensure a successful `reverse shell` connection.

If you're encountering a similar issue, it’s crucial to adjust specific `Metasploit` parameters, particularly the `LHOST` value.

When using `OpenVPN` through `TryHackMe`, the target machine resides behind a `firewall` that may block or restrict outgoing connections to your `Kali Linux VM’s` default network interface. This means using your system’s default IP for `LHOST` might not work as expected.

Instead, your `LHOST` should be set to the IP address assigned to your `VPN interface (tun0)`. You can find this IP address by running either of the commands below.

**🔹 VPN Interface (tun0) IP Address:** *`ip a`*

Or

**🔹 VPN Interface (tun0) IP Address:** *`ifconfig`*

Or 

**🔹 VPN Interface (tun0) IP Address:** *`ifconfig tun0`*

![image](https://github.com/user-attachments/assets/c96b5b42-bf15-4d79-826c-fa1776e42d2f)

Once we’ve identified our `VPN interface IP address`, we’ll return to `Metasploit` and reconfigure the necessary exploit parameters, such as updating the `LHOST` parameter to reflect our `VPN-assigned IP address` (associated with the `tun0` interface) and then access the module’s `options menu` (*`show options`*) to verify the change.

This step is essential, as it ensures the `reverse shell` connection is properly routed back to our machine over the established `VPN tunnel`—allowing the target system to communicate securely and directly with our `Kali Linux VM` attacking machine.

**🔹 Set `LHOST`:** *`set LHOST <your_tun0_ip_address>`*

**🔹 Access Options Menu:** *`show options`*

![image](https://github.com/user-attachments/assets/505b4cd7-f14e-4710-bb84-9a8ea953e231)

Next, it’s important to note the default `LPORT` (port `4444`) may not successfully establish a connection, especially when operating behind restrictive firewalls. If port `4444` fails when paired with your `VPN-assigned` `LHOST`, you’ll need to opt for more firewall-friendly ports that are commonly open for outbound traffic or more likely to bypass firewall restrictions, such as ports `80`, `443`, or `8080`.

In this case, we’ll configure `LPORT` to use port `80`, which is typically allowed through most firewalls and proxy setups due to its association with standard `HTTP` traffic. Then, we’ll run (*`show options`*) to confirm our updated configuration is correctly applied and ready for execution.

**🔹 Set LPORT:** *`set LPORT 80`*

**🔹 Access Options Menu:** *`show options`*

![image](https://github.com/user-attachments/assets/3664c725-bb72-409f-b8a4-7980f7c26932)

Now we are ready to *`run`* our exploit. 

**🔹 Run Exploit:** *`run`*

![image](https://github.com/user-attachments/assets/e2feae6f-e95a-4180-b247-58dd234ed0a3)

🎉 Success! The exploit worked, and we now have `remote access` to the target system as we have established a `Meterpreter` session. 

`Meterpreter` is a powerful and flexible payload included with `Metasploit`. It gives us a `remote shell` on the compromised system but with extra capabilities beyond a normal terminal.

### ✅ Step 6: Post-Web Application Exploitation - Enumeration

Once inside the target system, we will gather system information as shown below.

**🔹 Gather System Information:** *`sysinfo`*

**🔹 See Current Privileged Level User:** *`getuid`*

![image](https://github.com/user-attachments/assets/4bc04854-76cd-40e5-acbc-9ba980b8de65)

As a result, we can see that our `Meterpreter` session is currently running as the *`www-data`* user on the target system, which is a low-privileged user commonly used by web servers like `Apache` or `Nginx`. It’s the default account used to run web apps for security reasons — so if a web app is compromised, the attacker only gets access to this restricted user.

The next step in our exploitation process is to focus on privilege escalation. We’ll continue investigating to identify potential `vulnerabilities`, `misconfigurations`, or `accessible files` that can help us elevate our privileges to a more powerful user, such as *`root`*.

Let’s navigate to the `root` of the file system by using the command (*`cd /`*), and then list the contents with (*`ls`*) to explore key directories. Specifically, the following subdirectories:

•	`/home` – Typically contains user-specific files. These may include `configuration files`, `bash histories`, or other data that could provide credentials or insights into user activity.

•	`/root` – The home directory of the `root` user. If we can access this directory or its contents, it may indicate we already have elevated privileges.

•	`/etc` – This directory houses `configuration files` for the system and various services. Files such as `passwd`, `shadow`, `crontab`, or service-specific configs may expose sensitive data or misconfigurations.

•	`/var/www` – Commonly used for hosting `web application files`. These could contain `source code`, `backup files`, or hardcoded credentials that aid further exploitation.

By investigating these directories, we aim to gather valuable information or find footholds that can assist in escalating our access beyond the current user *`www-data`*.

**🔹 Navigate to Root Directory:** *`cd /`*

**🔹 List Root Directory Contents:** *`ls`*

![image](https://github.com/user-attachments/assets/8b02a740-be09-4f06-9441-2c1f2e921449)

**🔹 Navigate to Home Directory:** *`cd home`*

**🔹 List Home Directory Contents:** *`ls`*

![image](https://github.com/user-attachments/assets/2b322fb3-4387-45f4-9888-8855f38204b2)

After examining the `/home` directory, we discover a subdirectory named *`think`*, which is likely associated with a local user account on the system. This discovery is valuable, as targeting real user accounts can open new paths for `privilege escalation`.

To gather more information about this subdirectory, we can investigate the `/etc` directory — specifically the `passwd` file — by using the command *`cat /etc/passwd`*. This file contains a list of all user accounts on the system, along with their corresponding home directories and default shells. Reviewing this file can help confirm the presence of the user *`think`* and may also reveal other user accounts that could be leveraged for `privilege escalation`.

**🔹 Investigate `passwd` File:** *`cat /etc/passwd`*

![image](https://github.com/user-attachments/assets/61145bff-8a62-4c9f-a5db-2045b2bd09d7)

As a result of inspecting the `/etc/passwd` file, we can confirm the presence of a local user account named *`think`*, supported by the fact that the account is assigned a `UID` and `GID` of `1000`, which typically indicates it is the first `non-root` user created during the system's initial setup — often used as the primary user for daily operations with `sudo` privileges. Additionally, the account's designated home directory is `/home/think`, and the default `shell` is `/bin/bash`, suggesting it's configured for interactive use, making it a potential target for `privilege escalation`.

**Note:** On most `Linux` distributions, `UID` of `0` is reserved for the *`root`* user, which has full administrative privileges. `UIDs` `1–999` are typically reserved for `system users` (like `services` and `daemons`). The first `regular (human) user` created during the system's setup is usually assigned `UID` and `GID` of `1000`.

**🔹 Navigate to `think’s` Home Directory:** *`cd /home/think`*

**🔹 List `think’s` Directory Contents:** *`ls`*

![image](https://github.com/user-attachments/assets/a7b44754-6e94-41bc-a977-9dbebc4cacfa)

Navigating to the account’s home directory at `/home/think`, we discover a file named `.passwords`. However, we are unable to read its contents because we are currently operating as the low-privileged web server user *`www-data`*. The file’s permissions are set to `100640 (rw-r-----)`, which means only the `file owner` has `read and write` access, and the `group` has `read` access. Since *`www-data`* is neither the file `owner` nor a member of the associated `group`, we lack the necessary permissions to access this file. 

### 🔶 Privilege Escalation

Now that we’ve gathered sufficient information, the next logical step in our `privilege escalation` process is to identify `SUID (Set User ID)` binaries present on the system. The `SUID` bit is a special file permission in `Unix`-like operating systems that allows users to execute a file with the privileges of the file’s `owner`, rather than their own. This is particularly significant when the file owner is *`root`*.

`SUID` binaries are commonly used to allow limited users to perform specific system-level tasks without granting full administrative access. However, if a `SUID` binary is misconfigured or inherently vulnerable, it can potentially be exploited to execute arbitrary commands with elevated privileges.

This makes `SUID` binaries a critical target during `privilege escalation` assessments. By discovering and analyzing these executables, we might find a pathway to elevate our access from the current limited user (*`www-data`*) to a more privileged user or even full `root` access.

**Note:** If you're currently in a `Meterpreter` session, traditional `Linux` commands like *`find`* may not execute as expected. This is because `Meterpreter` uses its own command set. To run standard `Linux` commands, you’ll need to drop into a system `shell` environment by typing *`shell`*. Once in the `shell` session, you can execute typical `Linux` commands. To return to the `Meterpreter` environment, type *`exit`*.

**🔹 Drop to `Shell` Environment:** *`shell`*

While in the system `shell`, we can begin by scanning the entire file system for `SUID`-enabled binaries using the following command:

**🔹 Identify `SUID` Binaries:** *`find / -perm -4000 -type f 2>/dev/null`*

| **Part** | **Explanation** |
|-|-|
| -perm -4000 | Finds files with the `SUID` bit |
| -type f | Only looks at regular files |
| 2>/dev/null | Suppresses permission errors in the output |

![image](https://github.com/user-attachments/assets/5ada9786-31f6-4389-9183-27ea3a6315c5)

After searching for `SUID` binaries, we come across one suspicious `/usr/sbin/pwm` file that is not a standard or default `SUID` binary on `Linux` systems. It’s likely that this binary has been added by a specific application or package on the target machine. In most `Linux` distributions, the `SUID` bit is set on specific binaries that need to perform privileged actions, but `PWM` is not a common tool or service associated with default `Linux` installations.

`PWM (Pulse Width Modulation)` is typically a method used for controlling the brightness of LEDs, motor speed, or similar hardware-related tasks. However, the presence of this `SUID` binary with this name could imply that it's designed to run with elevated privileges. If `PWM` is owned by the *`root`* user, it means any user, including non-privileged users like ourselves *`www-data`*, can execute it with `root` privileges, which creates a security risk. Let’s verify its permissions.

**🔹 Verify `PWM` Permissions:** *`ls -l /usr/sbin/pwm`*

![image](https://github.com/user-attachments/assets/52969bf1-a2c3-47aa-89dd-485125c4d84a)

As suspected, the `PWM` binary is owned by the *`root`* user and has the `SUID` bit set. This means it will execute with `root` privileges regardless of the user running it. Since we have `execute` permissions, we can attempt to run the file and observe its behavior.

**🔹 Run `PWM` Binary:** *`/usr/sbin/pwm`*

![image](https://github.com/user-attachments/assets/b68e9add-3441-4274-a6af-ac312c6332f2)

We observe that the `PWM` binary internally executes the *`id`* command to determine the current user, which it correctly identifies as *`www-data`*. It then attempts to access a *`.passwords`* file located in `/home/www-data/`, but since this directory does not exist, the operation fails. This behavior indicates that `PWM` is designed to interact with user-specific data and expects certain files like *`.passwords`* to be present in the executing user's home directory. This insight suggests the binary may be relying on user context for its functionality, which could be a valuable clue for `privilege escalation` or crafting a `targeted exploit path`.

To investigate further, we’ll execute the `PWM` binary followed immediately by the *`id`* command. This allows us to observe the identity of the current user *`www-data`*, and helps us analyze how the binary behaves and whether it alters our privileges or environment in any way.

**🔹 Display Current User’s Identity:** *`/usr/sbin/pwm;  id`*

**Note:** In most shells, a semicolon ( *`;`* ) is used to separate multiple command on the same line.

![image](https://github.com/user-attachments/assets/89ac12de-467c-4b85-a744-e1d55ef8a0f1)

It’s observed that the binary `/usr/sbin/pwm` executes the `id` command without specifying its full path (i.e., `/usr/bin/id`). When a program invokes a command without the full path, it depends on the system’s `$PATH` environment variable to locate and execute it. This behavior introduces a potential security risk known as `path hijacking`. By placing a malicious script or executable named `id` in a directory that appears earlier in the `$PATH`, an attacker can trick the `SUID` binary into executing their custom code with elevated privileges. This vulnerability can be leveraged to `escalate privileges` on the system.

Let’s check the current value of the `$PATH` environment variable. This variable defines a list of directories, separated by colons, that the `shell` searches through to locate and execute commands. Understanding its order is crucial, especially when analyzing potential `path hijacking` vulnerabilities.

**🔹 Display Environment Path:** *`echo $PATH`*

![image](https://github.com/user-attachments/assets/5ba99589-d275-4a51-a0d0-6a05fc294e28)

It’s important to note that the system will search these directories in order from `left to right` to find the corresponding executable. Since `/usr/sbin/pwm` runs (*`id`*) without the full path (i.e., `/usr/bin/id`), and `/usr/bin` appears after `/usr/local/bin` in the list, we can control the `$PATH` and create a custom malicious (*`id`*) executable in a writable directory where the binary will execute our custom command instead of a legitimate one that will elevate our privileges.

Below, we’ll create a custom (*`id`*) command that overrides the default behavior. To do this, we’ll craft a file named `id` within the `/tmp` directory to include a `shebang` — indicating the system that the file should be executed using the `Bash shell`. Inside this file, we’ll include a simple `echo` command that mimics user identity output for user *`think`*. After creating the file, we’ll make it executable using `chmod`.

**🔹 Create `id` File:** *`echo “#!/bin/bash” > /tmp/id`*

**🔹 Echo Command:** *`echo ‘echo “uid=33(think) gid=33(think) groups=(think)”’ >> /tmp/id`*

**🔹 Chmod `id` File:** *`chmod +x /tmp/id`*

![image](https://github.com/user-attachments/assets/e2663e7e-4ce5-44f2-b0e2-fa9ecf26de96)

This script will not only simulate the output of the real *`id`* command but will also attempt to read the `.passwords` file located in `/home/think`.

Now, we’ll verify that our custom executable has been created with our modifications.

**🔹 Verify Custom `id` File:** *`cat /tmp/id`*

![image](https://github.com/user-attachments/assets/64f598f8-7539-45c2-ad2a-e6efc9577828)

Now we’ll modify the `$PATH` environment variable by placing `/tmp` earlier in the `$PATH`, when the vulnerable `pwm` binary runs *`id`* without its full path, our custom script will be executed instead, potentially giving us access to the restricted `.passwords` file.

**🔹 Modify `$PATH` Environment:** *`export PATH=/tmp:$PATH`*

**🔹 Verify `$PATH` Environment:** *`echo $PATH`*

![image](https://github.com/user-attachments/assets/5add3b7f-10c5-4093-a74e-781f51ba1ac9)

Now that the `/tmp` directory has been placed in the `$PATH` environment, we can proceed to finally executing the `pwm` binary one more time.

**🔹 Run `PWM` Binary:** *`/usr/sbin/pwm`*

![image](https://github.com/user-attachments/assets/a3e3942d-1b13-40ee-8dcc-5250b0323208)

We can confirm that the binary executed and accessed the `.passwords` file from the user *`think`* instead of the default user *`www-data`*. This demonstrates that our `path hijacking` technique was successful, allowing us to impersonate the user *`think`* and obtain a list of potential `passwords` for gaining further access.

Now that we’ve obtained a list of potential `passwords`, the next step is to perform a `brute-force attack` to identify the correct one using `Hydra`. By systematically attempting each `password` against the `SSH` service, we aim to gain valid user-level access. Once the correct credentials are identified, we can initiate an `SSH` session as the user *`think`*, moving one step closer to a full system compromise.

**Note:** Be sure to copy, paste, and save the list of `passwords` into a `.txt` file on your machine to use during the `brute-force attack`.

![image](https://github.com/user-attachments/assets/5e95e768-012d-4e3e-af37-a7266c007e67)

Now that we’ve found the `password` for the user *`think`*, we can perform an `SSH` session with these credentials.

**🔹 `SSH` Session:** *`sudo ssh think@[target_IP_address]`*

![image](https://github.com/user-attachments/assets/4b15e2d8-62a5-4a42-8369-c19f372b6178)

![image](https://github.com/user-attachments/assets/9e48bc75-77db-41e0-baed-a0f5956f5190)

And we’ve successfully authenticated as the user *`think`*! Let’s explore the current working directory to see what we have access to. 

**🔹 List Directory Contents:** *`ls`*

![image](https://github.com/user-attachments/assets/ea0e00db-f4de-425e-b9bd-1a9a90f25372)

Upon listing the contents, we notice a file named `user.txt`. This file likely contains the `user flag` or valuable information—let’s go ahead and read its contents

**🔹 Read File Contents:** *`cat user.txt`*

![image](https://github.com/user-attachments/assets/b95de57c-f9ab-485c-a08d-11033418f409)

Congratulations!!! We have our `User FLAG`!!! On to the next!!!

Lastly, we’ll need to escalate our privileges to the *`root`* user. To accomplish this, let’s check which commands can be executed with `sudo` privileges while being the user *`think`*—either without a `password` or after successful authentication.

**🔹 List Sudo Commands:** *`sudo -l`*

![image](https://github.com/user-attachments/assets/a6d88b2a-7cc9-432a-b83f-6aaac245efe8)

The output indicates that we have permission to run the `/usr/bin/look` command (binary) as any user, including *`root`*, using `sudo`. The `look` command searches a dictionary file (default is `/usr/share/dict/words`) for words that start with a given string. If `look` can be run with `sudo`, it may be exploitable, especially if it allows you to invoke other commands or escape into a `shell`.

To better understand how to exploit this, we can refer to `GTFOBins`, a valuable resource for identifying privilege escalation techniques using common binaries. Upon researching the <a href="https://gtfobins.github.io/gtfobins/look/">`Look`</a> binary , we discover that it can be used to read data from files, perform privileged reads, and even disclose files outside restricted file systems.

![image](https://github.com/user-attachments/assets/4f24b4b5-d05a-47e1-a7b2-e000590b3414)

Given this information, we can potentially leverage the `/usr/bin/look` binary to access sensitive files such as `/etc/shadow` and `/root/.ssh/id_rsa`, which contains the private key for the *`root`* user.

**🔹 Access *`Root’s`* Private SSH Key:** *`sudo /user/bin/look ‘‘ /root/.ssh/id_rsa`*

| **Part** | **Explanation** |
|-|-|
| sudo | Runs the command with elevated `root` privileges |
| /usr/bin/look | This is the *`look`* command. It searches for lines in a file that begin with a specified string. |
| ‘‘ (a space character) | This is the search string being passed to *`look`*. The single quotes mean a single space, but the characters have no space in between them during the command. 
| /root/.ssh/id_rsa | This is the file being searched. In this case, the private `SSH` key for the *`root`* user |

This command tries to read lines in   /root/.ssh/id_rsa   that begin with a space, using the *`look`* command — and it does this with `sudo`, which means it can bypass regular file permissions. Using an empty string `''` as the search term with the *`look`* command is a clever trick to bypass the intended usage and force the command to display the entire contents of a file, one line at a time. This method allows the user to leverage permitted `sudo` access to read a file indirectly. Here’s why: The *`look`* command searches for lines that start with the provided string. If the string is empty, then every line starts with an empty string, so it matches all lines.

![image](https://github.com/user-attachments/assets/f8ef0f39-5d6f-42d3-99fe-a077872409b2)

Copy, paste, and save the entire `SSH Private Key` to a `[filename.txt]` in your `Kali Linux VM` and set the appropriate permissions. 

**Note:** Copy from the first line `BEGIN OPENSSH PRIVATE KEY` to the last line `END OPENSSH PRIVATE KEY`.

**🔹 Set File Permissions:** *`chmod 600 [filename.txt]`*

**6 (rw-) for the owner:** The owner can read/write the file.

**0 (---) for the group:** no permissions for the group.

**0 (---) for others:** no permissions for others.

![image](https://github.com/user-attachments/assets/998d8519-f5ac-4594-8979-a88a74a17c94)

Now let’s initiate a `SSH` session into the *`root`* user using the file containing its private `SSH key`.

**🔹 Initiate SSH Session to Root:** *`ssh -i [filename.txt] root@lookup.thm`*

**Note:** You can use the `Target IP Address` instead of `lookup.thm`.

![image](https://github.com/user-attachments/assets/bd6269bb-8ec4-4e16-8dfa-eef11c34b114)

We are `ROOT`!!! 

Let’s explore the current working directory to see what we have access to. 

**🔹 List Directory Contents:** *`ls`*

**🔹 Read File Contents:** *`cat root.txt`*

After listing the directory contents, we discover a file named `root.txt`. Reading its contents reveals the final piece of our challenge!!!

Congratulation!!! The `root flag` has been captured!!! 🎉

![image](https://github.com/user-attachments/assets/18f1dc74-1a39-4c9a-88b1-9bc396c6ba5e)

## 🔶 Conclusion

`Lookup` is more than just a challenge — it’s a hands-on journey that sharpens your skills as an ethical hacker. From the very beginning, you’re pushed to master the fundamentals of `enumeration`, `reconnaissance`, and `vulnerability analysis`. By identifying hidden subdomains and services, exploiting web application flaws, and escalating privileges through misconfigurations, you experience the full cycle of a real-world penetration test.

This lab doesn’t just teach you how to exploit — it trains you to `think critically`, `automate smartly`, and `act strategically`. The lessons learned here reinforce core concepts in `web exploitation`, `system enumeration`, and `privilege escalation`, preparing you for advanced challenges ahead. `Lookup` is a must for anyone serious about building a solid foundation in offensive security.







