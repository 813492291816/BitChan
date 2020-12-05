Install
	- In terminal
		sudo apt update
		sudo apt install gnupg
	- Check to see if it's installed
		gpg --help

Create a key pair
	- In terminal
		gpg --full-gen-key
	- Select algorithm
		RSA & RSA
	- Bit length
		4096
	- Expiration
		2y
	- Name

	- Email

	- Comment

	- Use very long, random password ~120 char

output:
gpg --output /home/name/Desktop/public.key --armor --export [email or name]

gpg --output /home/name/Desktop/private.pgp --armor --export-secret-key [email or name]

delete keys:
gpg --list-keys

gpg --delete-secret-keys [email or name]

gpg --delete-key [email or name]

sudo apt install secure-delete

srm -vz /home/name/Desktop/private.pgp

srm -vz /home/name/Desktop/public.key