# Bugs

Public proof of concepts/bugs/weaponized exploits/etc. etc.

## CVE-2015-5090
Adobe Reader/Acrobat Pro privilege escalation in <= 11.0.10.

## CVE-2018-11072
Dell Digital Delivery LPE. Using the PoC, you'll need to drop a DLL under the appropriate entitlement folder in %ProgramData%. The included PoC simply triggers the entitlement reinstallation (see ExampleProject project in the solution). Note I use SharpNeedle project to do the code injection, and had to hack around a few bugs. 

## dell-support-assist
CVE-2018-XXX LPE in Dell/PC-Doctor SupportAssist kernel driver < 2.2
http://hatriot.github.io/2018/05/17/dell-supportassist-local-privilege-escalation/
