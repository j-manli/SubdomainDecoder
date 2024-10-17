import sys
from scapy.all import rdpcap, DNS
import base64
import zipfile
import io
import re

def extract_subdomains(pcap_file):
    # Read packets from the pcap file
    packets = rdpcap(pcap_file)
    subdomains = []

    # Loop through each packet
    for packet in packets:
        # Check if the packet contains a DNS layer
        if packet.haslayer(DNS):
            dns_layer = packet[DNS]
            # Check if it's a DNS query (qr == 0 means query)
            if dns_layer.qr == 0:
                # Get the queried domain name (qname)
                qname = dns_layer.qd.qname.decode(errors='ignore').strip('.')
                # Remove all occurrences of '.ponder' from qname
                qname = qname.replace('.ponder', '')
                # Split the domain name into labels
                labels = qname.split('.')
                # Extract subdomain labels (excluding the last two labels)
                if len(labels) > 2:
                    subdomain_labels = labels[:-2]
                else:
                    subdomain_labels = labels
                # Join the subdomain labels into a single string
                subdomain = ''.join(subdomain_labels)
                # Add the subdomain to our list
                subdomains.append(subdomain)

    # Concatenate all subdomains into one string
    concatenated_subdomains = ''.join(subdomains)
    return concatenated_subdomains

def decode_and_extract(b64_string):
    # Replace URL-safe Base64 characters with standard ones
    b64_string = b64_string.replace('-', '+').replace('_', '/')
    # Remove any characters not in the Base64 character set
    b64_string = re.sub(r'[^A-Za-z0-9+/=]', '', b64_string)
    # Add padding if necessary to make the length a multiple of 4
    while len(b64_string) % 4 != 0:
        b64_string += '='

    try:
        # Decode the Base64 string into bytes
        zip_data = base64.b64decode(b64_string)
        print("Base64 decoding successful.")
    except Exception as e:
        print("Error decoding Base64:", e)
        sys.exit(1)

    # Save the decoded data to a zip file
    with open('decoded_data.zip', 'wb') as f:
        f.write(zip_data)

    try:
        # Open the zip file from the decoded bytes
        zip_file = zipfile.ZipFile(io.BytesIO(zip_data))
        # Read the contents of 'flag.txt' from the zip file
        flag_content = zip_file.read('flag.txt')
        # Print the contents of 'flag.txt'
        print("Contents of flag.txt:")
        print(flag_content.decode())
    except zipfile.BadZipFile:
        print("The decoded data is not a valid zip file.")
    except KeyError:
        print("'flag.txt' not found in the zip file.")
    except Exception as e:
        print("An error occurred while processing the zip file:", e)

if __name__ == "__main__":
    # Check if the user provided the correct number of arguments
    if len(sys.argv) != 2:
        print("Usage: python script.py <pcap_file>")
        sys.exit(1)
    # Get the pcap file name from the arguments
    pcap_file = sys.argv[1]
    # Extract the Base64 string from the subdomains
    b64_string = extract_subdomains(pcap_file)
    print("Extracted Base64 string:")
    print(b64_string)
    # Decode the Base64 string and extract the flag
    decode_and_extract(b64_string)
