'''
This script parses a PCAPNG file and outputs all the data required for a
PMKID-based attack in a hashcat-readable format.

Authors:
Davide Testoni
Emanuele Gallone
'''

import pyshark

capture = pyshark.FileCapture('capture.pcapng')
output = open('output.pmkid', 'w+')

# We need both EAPOL frames and Beacon frames (in order to get the SSID)

# This array will contain data like [MAC_AP, MAC_STA, PMKID]
eapols = []

# This array will contain data like [MAC_AP, SSID]
beacons = []

for packet in capture:

	try:

		subtype = packet.wlan.fc_type_subtype.showname_value

		# If we have a beacon frame
		if 'Beacon' in subtype:
			info = [packet.wlan.sa.replace(':', ''), packet.layers[3].ssid.showname_value.encode("utf-8").hex()]
			if info not in beacons:
				beacons.append(info)

		# If we have a QoS frame
		if 'QoS Data' in subtype:
			info = [packet.wlan.sa.replace(':', ''), packet.wlan.da.replace(':', ''), packet.eapol.wlan_rsn_ie_pmkid.replace(':', '')]
			if info not in eapols:
				eapols.append(info)

	except:
		pass

print('Found %d beacons and %d eapols' % (len(beacons), len(eapols)))

# Hashcat wants the format PMKID*MAC_AP*MAC_STA*SSID
pmkids = []
for eapol in eapols:
	for beacon in beacons:
		if eapol[0] == beacon[0]:
			pmkid = '%s*%s*%s*%s' % (eapol[2], eapol[0], eapol[1], beacon[1])
			if pmkid not in pmkids:
				pmkids.append(pmkid)
				print(pmkid)

output.writelines(pmkids)
output.close()

print('Wrote %d PMKIDs' % len(pmkids))
