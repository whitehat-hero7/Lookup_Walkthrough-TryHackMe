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
| jxxx | `Username` (verify case-sensitivity) |
| -P /usr/share/wordlists/rockyou.txt | Path to your `password` list |
| lookup.thm | Target domain (make sure it’s resolved or in /etc/hosts) |
| http-post-form | Protocol/module to use |
| /login.php | Form path |
| username=^USER^&password=^PASS^ | `POST` parameters (`Hydra` swaps `^USER^` and `^PASS^`) |
| Wrong password | Response string to detect failure (`Wrong password`) |
| -t 4 | Number of parallel tasks (adjust as needed) |
| -f | Stop after finding the first valid `password` for the `username` |

**Note:** After executing the `Hydra` command, it will take approximately `10 minutes` to complete.


