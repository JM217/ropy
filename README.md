# InfoLeak-ROPchain
This is an exploit I developed for the Malware and Exploit Analysis module on my course.

The task was to create an exploit, either fully or semi automoted, for an echo server. The exploit had to use information leaks and a R.O.P chain (return oriented programming). Once the exploit had run, the server was not allowed to crash, so it was important to keep this in mind when developing the exploit.
The script is written in python, where any hexadecimal values are converted into bytes automatically by the script.
This script is the fully automated version, meaning ASLR can be enabled and the exploit is still successful.
Future development could include changning the purpose of the exploit, from it printing a message to returning a reverse shell or to perform data exfiltration against a taret.
