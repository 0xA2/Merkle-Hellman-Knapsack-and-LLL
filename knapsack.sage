####################################################################
#                                                                  #
#         ### Merkle-Hellman Knapsack Sage 9.0 Version ###         #
#                                                                  #
#  WARNING: I wrote this program to be compatible with Python 3,   #
#	    however the 'break cipher' feature is only fully       #
#	    availiable when ran with sagemath.                     #
#                                                                  #
#	    Always keep in mind cryptosystem can be easily         #
#	    broken and should in no circumstance be                #
#            considered for any serious cryptographic use.         #
#                                                                  #
####################################################################

from random import SystemRandom
import binascii

# Private key randomness coefficients
# (NOTE: For demonstration purposes I kept these values very low in order to artificially increase the program's efficiency, in an ideal scenario they should be much higher!)
W_RANGE = 10
Q_RANGE = 10

banner = '''-------------------------------
    Merkle-Hellman Knapsack
-------------------------------'''

# Encryption related functions - start

# Verify if public key has a valid length
# (NOTE: in this implementation key-size is always equal to plaintext length in bits)
def verify_publickey(pt,public_key):
	return len("".join(format(ord(c),'b') for c in pt).rjust(len(pt)*8,"0")) == len(public_key)

def encrypt(pt,public_key):
	return str(sum([(int(bin(int(binascii.hexlify(pt.encode()),16))[2:].rjust(len(pt)*8,"0")[i])*public_key[i]) for i in range(0,len(public_key))]))

# (NOTE: in this implementation public key is not permutated)
def gen_keypair(pt_len):
	# Generating Private Key:
	# Generating random superincreasing set w
	w = []
	s = 2
	for _ in range(0,pt_len):
		value = SystemRandom().randrange(s,s+W_RANGE)
		w.append(value)
		s += value
	# Generating q such that q > sum
	q = SystemRandom().randrange(s,s+Q_RANGE)
	# Generating r such that r and q are coprime
	while True:
		r = SystemRandom().randrange(2,q)
		if egcd(r,q)[0] == 1:
			break
	private_key = (w,q,r)
	#Calculating Public Key:
	public_key = [(n*r)%q for n in w]
	return (public_key, private_key)

# Encryption related functions - end


# Auxiliary functions for gcd and modulo inverse calculations

def egcd(a,b):
	if a == 0:
		return (b,0,1)
	g,y,x = egcd(b%a,a)
	return (g,x-(b//a)*y,y)

def modinverse(a,m):
	g,x,y = egcd(a,m)
	if g != 1:
		raise Exception('Something went wrong, modular inverse does not exist')
	return x%m


# Decryption related functions - start

def verify_privatekey(private_key):
	if egcd(private_key[1],private_key[2])[0] != 1:
		print ("\nError: q and r are not coprime!\n")
		return False
	sum = 0
	for i in range(0,len(private_key[0])):
		if private_key[0][i] <= sum:
			print (private_key[0])
			print ("\nError: w is not a superincreasing sequence!\n")
			return False
		sum += private_key[0][i]
	if sum >= private_key[1]:
		print ("\nError: q is not greater than the sum of all elements of w!\n")
		return False
	return True

def decrypt(ct,private_key):
	s = (ct*modinverse(private_key[2],private_key[1]))%private_key[1]
	pt = ""
	for i in range(len(private_key[0])-1,-1,-1):
		if private_key[0][i] <= s:
			s -= private_key[0][i]
			pt += "1"
		else:
			pt += "0"
	return binascii.unhexlify(hex((int(pt[::-1],2)))[2:].encode()).decode()

# Auxiliary functions for vector operations

def vsum(u,v):
	try:
		ret = []
		for i in range(0,len(v)):
			ret.append(v[i]+u[i])
		return ret
	except:
		print ("\nError in vector sum calculation!\n")

def scalar_product(n,v):
	try:
		ret = []
		for i in range(0,len(v)):
			ret.append(n*v[i])
		return ret
	except:
		print ("\nError in vector scalar product calculation!\n")

def dot_product(u,v):
	try:
		ret = 0
		for i in range(0,len(v)):
			ret += v[i]*u[i]
		return ret
	except:
		print ("\nError in vector dot product calculation!\n")

# Cryptanalysis related functions

def GramSchmidt(M):
	try:
		orthG = [M[0]]
		projection_coefficients = {}
		for j in range(1,len(M)):
			orthG.append(M[j])
			for i in range(0,j):
				projection_coefficients[str(i)+str(j)] = (dot_product(orthG[i],M[j]))/(dot_product(orthG[i],orthG[i]))
				orthG[j] = vsum(orthG[j],scalar_product(-1*projection_coefficients[str(i)+str(j)],orthG[i]))
		return (orthG,projection_coefficients)
	except:
		print ("\nError in Gram-Schmidt orthogonalization process!\n")

def LLL(M,d):
	try:
		while True:
			GSoG, GSpc = GramSchmidt(M)
			for j in range(1,len(M)):
				for i in range(j-1,-1,-1):
					if abs(GSpc[str(i)+str(j)]) > 1/2:
						M[j] = vsum(M[j],scalar_product(-1*round(GSpc[str(i)+str(j)]),M[i]))
			GSoG, GSpc = GramSchmidt(M)
			try:
				for j in range(0,len(M)-1):
					tmp0 = vsum(GSoG[j+1],scalar_product(GSpc[str(j)+str(j+1)],GSoG[j]))
					if dot_product(tmp0,tmp0) < d*(dot_product(GSoG[j],GSoG[j])):
						tmp1 = M[j]
						M[j] = M[j+1]
						M[j+1] = tmp1
						raise Exception()
				return M
			except:
				continue
	except:
		print ("\nError in LLL reduction calculations!\n")


def break_cipher(ct,public_key):
	try:
		#Converting the knapsack problem into a lattice problem
		#Initializing and setting up the matrix M
		M = [[1 if i==j else 0 for i in range(0,len(public_key))] for j in range(0,len(public_key))]
		for i in range(0,len(public_key)):
			M[i].append(public_key[i])
		M.append([0 for _ in range(0,len(public_key))])
		M[len(public_key)].append(-ct)
		#Find short vectors in the lattice spanned by the columns of M
		short_vectors = LLL(M,0.99)
		print ("\nShort vectors found > " + str(short_vectors))
		flag = 0
		for vector in short_vectors:
			try:
				cur = ""
				for n in vector:
					cur += str(n)
					if n != 1 and n != 0:
						raise Exception()
				print ("\nPossible plaitext found > " + binascii.unhexlify(hex(int(cur[:-1],2))[2:].encode()).decode() + "\n" )
				flag = 1
			except:
				continue

		if not flag:
			print ("\nNo possible plaintexts found using LLL reduction!\n")

	except:
		print ("\nFailed to break Merkle-Hellman knapsack encryption for desired ciphertext!\n")

# Decryption related functions - end


# The Main Function handles user input, menu conditions and the retrieval of information from provided text files

def main():
	while True:
		print (banner)
		try:
			print ("1) Encrypt\n2) Decrypt\n3) Generate Key Pair\n4) Exit")
			op = str(input("> "))
		except:
			print ("Input Error!")

		# Main menu option 1
		if op == "1":
			try:
				pt = str(input("Plaintext to encrypt > "))
				print ("Public key:\n1) Use your own key\n2) Have key files generated for you")
				op1 = str(input("> "))
			except:
				print ("Input Error!")
				continue

			# Encrypt menu option 1
			if op1 == "1":
				try:
					pub_file =  str(input("Enter the name of your public key file(file should have one number per line)\n> "))
					public_key = []
					with open(pub_file,"r") as f:
						for line in f:
							if int(line[:-1]) <= 0:
								raise Exception()
							public_key.append(int(line[:-1]))
				except:
					print ("Invalid key error!")
					continue
				if not verify_publickey(pt,public_key):
					print("\nInvalid key error!\n")
					continue

			# Encrypt menu option 2
			elif op1 == "2":
				try:
					key = gen_keypair(len(pt)*8)
					print ("\nKey pair generated to encrypt your plaintext:\n\nPublic Key > " + str(key[0]) + "\n\nPrivate Key(w,q,r) > " + str(key[1]))
					with open("publickey.txt","w") as pub:
						for n in key[0]:
							pub.write(str(n) + "\n")
					with open("privatekey.txt","w") as prv:
						prv.write("w:\n")
						for n in key[1][0]:
							prv.write(str(n) + "\n")
						prv.write("q:\n")
						prv.write(str(key[1][1]) + "\n")
						prv.write("r:\n")
						prv.write(str(key[1][2]) + "\n")
					public_key = key[0]
					print ("\nPublic and Private keys have been saved to 'publickey.txt' and 'privatekey.txt' respectively.\n")
				except:
					print ("\nInput Error!\n")
			else:
				print ("\nInvalid option!\n")
				continue
			ct = encrypt(pt,public_key)
			print ("\nCiphertext > " + ct + "\n") 


		# Main menu option 2
		elif op == "2":
			try:
				ct = int(input("Ciphertext to decrypt (in decimal) > "))
			except:
				print ("\nInput error!\n")
				continue
			print ("\nPrivate key:\n1) Use your own key\n2) Break Cipher (no private key required)")
			op2 = str(input("> "))

			# Decrypt menu option 1
			if op2 == "1":
				try:
					prv_file = str(input("\nEnter the name of a private key file:\n> "))
					values = []
					with open(prv_file,"r") as prv:
						for line in prv:
							if "w:" in line or "q:" in line or "r:" in line:
								continue
							if int(line[:-1]) <= 0:
								raise Exception()
							values.append(int(line[:-1]))
					w = values[:-2]
					q = values[-2:-1][0]
					r = values[-1:][0]
					private_key = (w,q,r)
					if not verify_privatekey(private_key):
						print ("\nInvalid key error!\n")
						continue
					pt = decrypt(ct,private_key)
					print ("\nPlaintext > " + pt + "\n")
				except:
					print ("\nInvalid key error!\n")
					continue


			# Decrypt menu option 2
			elif op2 == "2":
				try:
					pub_file =  str(input("Enter the name of a public key file\n> "))
					public_key = []
					with open(pub_file,"r") as pub:
						for line in pub:
							if int(line[:-1]) <= 0:
								raise Exception()
							public_key.append(int(line[:-1]))
				except:
					print ("\nInvalid key error!\n")
					continue
				break_cipher(ct,public_key)
			else:
				print ("\nInvalid option!\n")
				continue


		# Main menu option 3
		elif op == "3":
			try:
				size = int(input("Enter key size(in bytes):\n> "))
				key = gen_keypair(size*8)
				print ("\nKey pair generated to encrypt your plaintext:\n\nPublic Key > " + str(key[0]) + "\n\nPrivate Key(w,q,r) > " + str(key[1]))
				with open("publickey.txt","w") as pub:
					for n in key[0]:
						pub.write(str(n) + "\n")
				with open("privatekey.txt","w") as prv:
					prv.write("w:\n")
					for n in key[1][0]:
						prv.write(str(n) + "\n")
					prv.write("q:\n")
					prv.write(str(key[1][1]) + "\n")
					prv.write("r:\n")
					prv.write(str(key[1][2]) + "\n")
				print ("\nPublic and Private keys have been saved to 'publickey.txt' and 'privatekey.txt' respectively.\n")
			except:
				print ("\nInput error!\n")
				continue


		# Main menu option 4
		elif op == "4":
			return 0
		else:
			print ("\nInvalid option!\n")

if __name__ == "__main__":
	main()
