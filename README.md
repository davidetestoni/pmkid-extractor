## PMKID Extractor
This is an alternative to [hcxpcaptool](https://github.com/ZerBea/hcxtools) written in python using [pyshark](https://github.com/KimiNewt/pyshark).
It's slower but it achieves the same output while being very easy to understand. I wrote this script for the Wireless Internet course.

# About the vulnerability
The PMKID is calculated like this
`PMKID = HMAC-SHA1-128(PMK, "PMK Name" | MAC_AP | MAC_STA)`
so once you get the output of this program it's really easy to obtain the PMK (Secret Key) via hashcat. You can follow one of the many guides available on the internet but remember to only use this for security research or for testing if your own network is vulnerable to this type of attack.

The easiest way to prevent the attack is to enable Enterprise mode on your AP.