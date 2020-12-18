# The Cat (Forensics 359, 56 solves)

Looking through the provided pcap, there's very little unecrypted traffic, but there is one instance where some data is POSTed which looks like a TLS secret log. We can load that into wireshark to try to decode some TLS data. Although I couldn't get Wireshark to show me the decrypted data, checking the TLS debug log we can see an uploaded file called "nyan.zip". Extracting it produces a shell script which contains the base64 encoded flag.

Flag: `X-MAS{yeah_nyan_is_cool_but_have_you_ever_Y3VybCAtcyAtTCBiaXQubHkvMTBoQThpQyB8IGJhc2gK-ea8f6adb7605962d}`