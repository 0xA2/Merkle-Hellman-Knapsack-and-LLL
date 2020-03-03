import binascii
import sys

banner = '''-------------------------------
    Merkle-Hellman Knapsack
-------------------------------'''

# Encryption related functions - start

def verify_publickey(pt,public_key):
	return len("".join(format(ord(c),'b') for c in pt).rjust(8,"0")) == len(public_key)

def encrypt(pt,public_key):
	return str(sum([(int(bin(int(binascii.hexlify(pt.encode()),16))[2:].rjust(len(pt*8),"0")[i])*public_key[i]) for i in range(0,len(public_key))]))

def gen_key_pair(pt_len):
	pass


# Encryption related functions - end

# ----------------------------------

# Decryption related functions - start

def verify_privatekey(ct,private_key):
	pass

def egcd(a,b):
	if a == 0:
		return (b,0,1)
	g,y,x = egcd(b%a,a)
	return (g,x-(b//a)*y,y)

def modinverse(a,m):
	g,x,y = egcd(a,m)
	if g != 1:
		raise Exception('Something went wrong, inverse modulo does not exist')
	return x%m

def decrypt(ct,private_key):
	base = (ct*modinverse(private_key[2],private_key[1]))%private_key[1]
	

def break_cipher(ct,public_key):
	pass

# Decryption related functions - end

def main():
	while True:
		print (banner)
		print ("1) Encrypt\n2) Decrypt\n3) Generate Key Pair\n4) Exit")
		op = input("> ")


		#Main menu option 1
		if op == "1":
			pt = input("Plaintext to encrypt > ")
			print ("Public key:\n1) Enter key manually\n2) Have key generated\n> ", end = "")
			op1 = input()

			#Encrypt menu option 1
			if op1 == "1":
				print ("Enter the numbers for public sequence B with a space in between:")
				public_key = [int(n) for n in input("> ").split()]
				if not verify_publickey(pt,public_key):
					print("Invalid key lenght error!")
					continue

			#Encrypt menu option 2
			elif op1 == "2":
				public_key = gen_key_pair(len(pt))[0]
			else:
				print ("Invalid option!")
				continue
			ct = encrypt(pt,public_key)
			print ("\nCiphertext > " + ct + "\n") 


		#Main menu option 2
		elif op == "2":
			ct = input("Ciphertext to decrypt (in decimal) > ")
			print ("Private key:\n1) Enter key manually\n2) Break Cipher(no private key required)\n> ", end = "")
			op2 = input()

			#Decrypt menu option 1
			if op2 == "1":
				print ("Enter the numbers for private sequence w with a space in between")
				w = [int(n) for n in input().split()]
				q = input("Enter the value for q (number greater than the sum of elements of w) > ")
				r = input("Enter the value for r (number coprime to q) > ")
				private_key = (w,q,r)
				if not verify_privatekey(ct,private_key):
					print("Invalid key lenght error!")
					continue
				pt = decrypt(ct,private_key)

			#Decrypt menu option 2
			elif op2 == "2":
				print ("Public key required to break cipher:\nEnter the numbers for public sequence B with a space in between")
				public_key = [int(n) for n in input().split()]
				if not verify_publickey(pt,key):
					print("Invalid key lenght error!")
					continue
				pt = break_cipher(ct,public_key)
			else:
				print ("Invalid option!")
				continue
			print (pt) #Add better printing


		#Main menu option 3
		elif op == "3":
			size = input("Key size:\n(NOTE: key size must be equal to plaintext size IN BITS for the cipher to work properly)\n> ")
			print (gen_key(size)) #Add better printing


		#Main menu option 4 (exit)
		elif op == "4":
			sys.exit(0)
		else:
			print ("Invalid option!")

if __name__ == "__main__":
	main()
