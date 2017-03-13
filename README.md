# Double Agent
Double Agent is a new Zero-Day technique for injecting code and maintaining persistencty on a machine (i.e. auto-run).

Double Agent can exploit:

* Every Windows version (Windows XP to Windows 10)
* Every Windows architecture (x86 and x64)
* Every Windows user (SYSTEM\Admin\etc.)
* Every target process, including priveleged processes (OS\Antivirus\etc.)

Double Agent exploits a 15 years old undocumented legit feature of Windows and therefore cannot be patched.

## Code Injection

Double Agent gives an attacker the abiility to inject any DLL into any process.

The code injection occurs extremely early during the victim's process boot, giving the attacker full control over the process and no way for the process to protect itself.

The code injection technique is so revolutionary that it's not detected or blocked by any antivirus.

Even more severe, antiviruses aren't able to detect when an attacker is using this technique against them, giving the attacker the ability to inject code into the antivirus and taking full control over it.

## Persistencty

Double Agent can be used as a persistencty technique to "survive" reboots and continue injecting code even after reboot.

Once a DLL has been injected into a process, the DLL would be forcefully bounded to the process forever. "Surviving" reboots\updates\patches\etc.

## Attack Vectors

* Attacking the Antivirus - Take full control of any antivirus bypassing its self protection mechanism.
  The attack has been verified on any major anti virus today, including: XXX
  
* Hijack Process Permissions - Hijack the permissions of an existing trusted process to perform malicious operations in disguise of the trusted process. e.g. Exfiltrating data over the interent, communication with C&C, stealing and decrypting sensitive data.

* Altering Process Behaviour - Modifiying the behaviour of the process. e.g. Weakening encryption algorithms, installing backdoors, etc.

* Infecting Other Users\Sessions - Inject code to processes of other users\sessions (SYSTEM\Admin\etc.).

## Authors
Cybellum Technologies LTD (http://cybellum.com/)
