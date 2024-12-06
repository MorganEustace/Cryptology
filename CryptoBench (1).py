from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, dsa, ec
import os
import time

###############KEYPAIR RSA##################
#1024 - 80bit 

counter = 0
for i in range(10): 
    counter += 1
    before = time.perf_counter()
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024
    )

    message = os.urandom(1024)

    after = time.perf_counter()
    
    #####################################
    
    public_key = private_key.public_key()

    before2 = time.perf_counter()

    short_plaintext = os.urandom(50)
# We can encrypt a small plaintext message directly.
    short_ciphertext = public_key.encrypt(
    short_plaintext,
    padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
    )
    )

    after2 = time.perf_counter()

    before3 = time.perf_counter()

# We can decrypt the ciphertext.
    short_plaintext_2 = private_key.decrypt(
    short_ciphertext,
    padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
    )
    )

    after3 = time.perf_counter()

    before4 = time.perf_counter()

    signature = private_key.sign(
    message,
    padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
    )
    
    after4 = time.perf_counter()

    before5 = time.perf_counter()

    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    after5 = time.perf_counter()

    one = after-before
    print(f"{one:0.4f} seconds")
    print(f"{counter} time generating 80bit RSA KeyPair")

    two = after2-before2
    print(f"{two:0.4f} seconds")
    print(f"{counter} time encrypting 80bit RSA")

    three = after3-before3
    print(f"{three:0.4f} seconds")
    print(f"{counter} time decrypting 80bit RSA")

    four = after4-before4
    print(f"{four:0.4f} seconds")
    print(f"{counter} time digital signing 80bit RSA")

    five = after5-before5
    print(f"{five:0.4f} seconds")
    print(f"{counter} time verifying signature 80bit RSA")

    # 2048 - 112bit  
    
counter = 0
for i in range(10): 
    counter += 1
    before = time.perf_counter()
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    message = os.urandom(2048)

    after = time.perf_counter()
    
    #####################################
    
    public_key = private_key.public_key()

    before2 = time.perf_counter()

    short_plaintext = os.urandom(50)
# We can encrypt a small plaintext message directly.
    short_ciphertext = public_key.encrypt(
    short_plaintext,
    padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
    )
    )

    after2 = time.perf_counter()

    before3 = time.perf_counter()

# We can decrypt the ciphertext.
    short_plaintext_2 = private_key.decrypt(
    short_ciphertext,
    padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
    )
    )

    after3 = time.perf_counter()

    before4 = time.perf_counter()

    signature = private_key.sign(
    message,
    padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
    )
    
    after4 = time.perf_counter()

    before5 = time.perf_counter()

    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    after5 = time.perf_counter()

    one = after-before
    print(f"{one:0.4f} seconds")
    print(f"{counter} time generating 112bit RSA KeyPair")

    two = after2-before2
    print(f"{two:0.4f} seconds")
    print(f"{counter} time encrypting 112bit RSA")

    three = after3-before3
    print(f"{three:0.4f} seconds")
    print(f"{counter} time decrypting 112bit RSA")

    four = after4-before4
    print(f"{four:0.4f} seconds")
    print(f"{counter} time digital signing 112bit RSA")

    five = after5-before5
    print(f"{five:0.4f} seconds")
    print(f"{counter} time verifying signature 112bit RSA")

# 3072 - 128bit 
counter = 0
for i in range(10): 
    counter += 1
    before = time.perf_counter()
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )

    message = os.urandom(3072)

    after = time.perf_counter()
    
    #####################################
    
    public_key = private_key.public_key()

    before2 = time.perf_counter()

    short_plaintext = os.urandom(50)
# We can encrypt a small plaintext message directly.
    short_ciphertext = public_key.encrypt(
    short_plaintext,
    padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
    )
    )

    after2 = time.perf_counter()

    before3 = time.perf_counter()

# We can decrypt the ciphertext.
    short_plaintext_2 = private_key.decrypt(
    short_ciphertext,
    padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
    )
    )

    after3 = time.perf_counter()

    before4 = time.perf_counter()

    signature = private_key.sign(
    message,
    padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
    )
    
    after4 = time.perf_counter()

    before5 = time.perf_counter()

    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    after5 = time.perf_counter()

    one = after-before
    print(f"{one:0.4f} seconds")
    print(f"{counter} time generating 128bit RSA KeyPair")

    two = after2-before2
    print(f"{two:0.4f} seconds")
    print(f"{counter} time encrypting 128bit RSA")

    three = after3-before3
    print(f"{three:0.4f} seconds")
    print(f"{counter} time decrypting 128bit RSA")

    four = after4-before4
    print(f"{four:0.4f} seconds")
    print(f"{counter} time digital signing 128bit RSA")

    five = after5-before5
    print(f"{five:0.4f} seconds")
    print(f"{counter} time verifying signature 128bit RSA")
    
    # 7680 - 192bit
counter = 0
for i in range(10): 
    counter += 1
    before = time.perf_counter()
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=7680
    )

    message = os.urandom(7680)

    after = time.perf_counter()
    
    #####################################
    
    public_key = private_key.public_key()

    before2 = time.perf_counter()

    short_plaintext = os.urandom(50)
# We can encrypt a small plaintext message directly.
    short_ciphertext = public_key.encrypt(
    short_plaintext,
    padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
    )
    )

    after2 = time.perf_counter()

    before3 = time.perf_counter()

# We can decrypt the ciphertext.
    short_plaintext_2 = private_key.decrypt(
    short_ciphertext,
    padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
    )
    )

    after3 = time.perf_counter()

    before4 = time.perf_counter()

    signature = private_key.sign(
    message,
    padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
    )
    
    after4 = time.perf_counter()

    before5 = time.perf_counter()

    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    after5 = time.perf_counter()

    one = after-before
    print(f"{one:0.4f} seconds")
    print(f"{counter} time generating 192bit RSA KeyPair")

    two = after2-before2
    print(f"{two:0.4f} seconds")
    print(f"{counter} time encrypting 192bit RSA")

    three = after3-before3
    print(f"{three:0.4f} seconds")
    print(f"{counter} time decrypting 192bit RSA")

    four = after4-before4
    print(f"{four:0.4f} seconds")
    print(f"{counter} time digital signing 192bit RSA")

    five = after5-before5
    print(f"{five:0.4f} seconds")
    print(f"{counter} time verifying signature 192bit RSA")
    
    # 15360- 256bit
counter = 0
for i in range(10): 
    counter += 1
    before = time.perf_counter()
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=15360
    )

    message = os.urandom(15360)

    after = time.perf_counter()
    
    #####################################
    
    public_key = private_key.public_key()

    before2 = time.perf_counter()

    short_plaintext = os.urandom(50)
# We can encrypt a small plaintext message directly.
    short_ciphertext = public_key.encrypt(
    short_plaintext,
    padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
    )
    )

    after2 = time.perf_counter()

    before3 = time.perf_counter()

# We can decrypt the ciphertext.
    short_plaintext_2 = private_key.decrypt(
    short_ciphertext,
    padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
    )
    )

    after3 = time.perf_counter()

    before4 = time.perf_counter()

    signature = private_key.sign(
    message,
    padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
    )
    
    after4 = time.perf_counter()

    before5 = time.perf_counter()

    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    after5 = time.perf_counter()

    one = after-before
    print(f"{one:0.4f} seconds")
    print(f"{counter} time generating 256bit RSA KeyPair")

    two = after2-before2
    print(f"{two:0.4f} seconds")
    print(f"{counter} time encrypting 256bit RSA")

    three = after3-before3
    print(f"{three:0.4f} seconds")
    print(f"{counter} time decrypting 256bit RSA")

    four = after4-before4
    print(f"{four:0.4f} seconds")
    print(f"{counter} time digital signing 256bit RSA")

    five = after5-before5
    print(f"{five:0.4f} seconds")
    print(f"{counter} time verifying signature 256bit RSA")





    #######KeyPair DSA##########
    ###### 1024 80bit ##########

counter = 0
for i in range(10): 
    counter += 1
    before = time.perf_counter()
    
    private_key = dsa.generate_private_key(

        key_size=1024
    )

    message = os.urandom(1024)

    after = time.perf_counter()
    
    #####################################
    
    public_key = private_key.public_key()


    before4 = time.perf_counter()

    signature = private_key.sign(
         message, 
         hashes.SHA256() 
         )
    
    after4 = time.perf_counter()

    before5 = time.perf_counter()

    public_key.verify(
         signature, 
         message, 
         hashes.SHA256() 
         )


    after5 = time.perf_counter()

    one = after-before
    print(f"{one:0.4f} seconds")
    print(f"{counter} time generating 80bit DSA KeyPair")

    four = after4-before4
    print(f"{four:0.4f} seconds")
    print(f"{counter} time digital signing 80bit DSA")

    five = after5-before5
    print(f"{five:0.4f} seconds")
    print(f"{counter} time verifying signature 80bit DSA")
 
#112bit - 2048

counter = 0
for i in range(10): 
    counter += 1
    before = time.perf_counter()
    
    private_key = dsa.generate_private_key(

        key_size=2048
    )

    message = os.urandom(2048)

    after = time.perf_counter()
    
    #####################################
    
    public_key = private_key.public_key()


    before4 = time.perf_counter()

    signature = private_key.sign(
         message, 
         hashes.SHA256() 
         )
    
    after4 = time.perf_counter()

    before5 = time.perf_counter()

    public_key.verify(
         signature, 
         message, 
         hashes.SHA256() 
         )


    after5 = time.perf_counter()

    one = after-before
    print(f"{one:0.4f} seconds")
    print(f"{counter} time generating 112bit DSA KeyPair")

    four = after4-before4
    print(f"{four:0.4f} seconds")
    print(f"{counter} time digital signing 112bit DSA")

    five = after5-before5
    print(f"{five:0.4f} seconds")
    print(f"{counter} time verifying signature 112bit DSA")

#128bit 3072bit
counter = 0
for i in range(10): 
    counter += 1
    before = time.perf_counter()
    
    private_key = dsa.generate_private_key(

        key_size=3072
    )

    message = os.urandom(3072)

    after = time.perf_counter()
    
    #####################################
    
    public_key = private_key.public_key()


    before4 = time.perf_counter()

    signature = private_key.sign(
         message, 
         hashes.SHA256() 
         )
    
    after4 = time.perf_counter()

    before5 = time.perf_counter()

    public_key.verify(
         signature, 
         message, 
         hashes.SHA256() 
         )


    after5 = time.perf_counter()

    one = after-before
    print(f"{one:0.4f} seconds")
    print(f"{counter} time generating 128bit DSA KeyPair")

    four = after4-before4
    print(f"{four:0.4f} seconds")
    print(f"{counter} time digital signing 128bit DSA")

    five = after5-before5
    print(f"{five:0.4f} seconds")
    print(f"{counter} time verifying signature 128bit DSA")
    
#4096 - 192bit  

counter = 0
for i in range(10): 
    counter += 1
    before = time.perf_counter()
    
    private_key = dsa.generate_private_key(

        key_size=4096
    )

    message = os.urandom(4096)

    after = time.perf_counter()
    
    #####################################
    
    public_key = private_key.public_key()


    before4 = time.perf_counter()

    signature = private_key.sign(
         message, 
         hashes.SHA256() 
         )
    
    after4 = time.perf_counter()

    before5 = time.perf_counter()

    public_key.verify(
         signature, 
         message, 
         hashes.SHA256() 
         )


    after5 = time.perf_counter()

    one = after-before
    print(f"{one:0.4f} seconds")
    print(f"{counter} time generating 192bit DSA KeyPair")

    four = after4-before4
    print(f"{four:0.4f} seconds")
    print(f"{counter} time digital signing 192bit DSA")

    five = after5-before5
    print(f"{five:0.4f} seconds")
    print(f"{counter} time verifying signature 192bit DSA")

#########ECC Key generation##############################

counter = 0
for i in range(10): 
    counter += 1
    before = time.perf_counter()
    
    private_key = ec.generate_private_key(
        ec.SECT163R2() # key size 163
)

    message = os.urandom(163)

    after = time.perf_counter()
    
    #####################################
    
    public_key = private_key.public_key()

    before4 = time.perf_counter()

    signature = private_key.sign(
         message, 
         ec.ECDSA(hashes.SHA256())
         )
    
    after4 = time.perf_counter()

    before5 = time.perf_counter()

    public_key.verify(
         signature, 
         message, 
         ec.ECDSA(hashes.SHA256())
         )


    after5 = time.perf_counter()

    one = after-before
    print(f"{one:0.4f} seconds")
    print(f"{counter} time generating 80bit ECC KeyPair")

    four = after4-before4
    print(f"{four:0.4f} seconds")
    print(f"{counter} time digital signing 80bit ECC")

    five = after5-before5
    print(f"{five:0.4f} seconds")
    print(f"{counter} time verifying signature 80bit ECC")

counter = 0
for i in range(10): 
    counter += 1
    before = time.perf_counter()
    
    private_key = ec.generate_private_key(
        ec.SECP224R1() # key size 224
)

    message = os.urandom(224)

    after = time.perf_counter()
    
    #####################################
    
    public_key = private_key.public_key()

    before4 = time.perf_counter()

    signature = private_key.sign(
         message, 
         ec.ECDSA(hashes.SHA256())
         )
    
    after4 = time.perf_counter()

    before5 = time.perf_counter()

    public_key.verify(
         signature, 
         message, 
         ec.ECDSA(hashes.SHA256())
         )


    after5 = time.perf_counter()

    one = after-before
    print(f"{one:0.4f} seconds")
    print(f"{counter} time generating 112bit ECC KeyPair")

    four = after4-before4
    print(f"{four:0.4f} seconds")
    print(f"{counter} time digital signing 112bit ECC")

    five = after5-before5
    print(f"{five:0.4f} seconds")
    print(f"{counter} time verifying signature 112bit ECC")

counter = 0
for i in range(10): 
    counter += 1
    before = time.perf_counter()
    
    private_key = ec.generate_private_key(
        ec.SECP256R1() # key size 256
)

    message = os.urandom(256)

    after = time.perf_counter()
    
    #####################################
    
    public_key = private_key.public_key()

    before4 = time.perf_counter()

    signature = private_key.sign(
         message, 
         ec.ECDSA(hashes.SHA256())
         )
    
    after4 = time.perf_counter()

    before5 = time.perf_counter()

    public_key.verify(
         signature, 
         message, 
         ec.ECDSA(hashes.SHA256())
         )


    after5 = time.perf_counter()

    one = after-before
    print(f"{one:0.4f} seconds")
    print(f"{counter} time generating 128bit ECC KeyPair")

    four = after4-before4
    print(f"{four:0.4f} seconds")
    print(f"{counter} time digital signing 128bit ECC")

    five = after5-before5
    print(f"{five:0.4f} seconds")
    print(f"{counter} time verifying signature 128bit ECC")

counter = 0
for i in range(10): 
    counter += 1
    before = time.perf_counter()
    
    private_key = ec.generate_private_key(
        ec.SECP384R1() # key size 384
)

    message = os.urandom(384)

    after = time.perf_counter()
    
    #####################################
    
    public_key = private_key.public_key()

    before4 = time.perf_counter()

    signature = private_key.sign(
         message, 
         ec.ECDSA(hashes.SHA256())
         )
    
    after4 = time.perf_counter()

    before5 = time.perf_counter()

    public_key.verify(
         signature, 
         message, 
         ec.ECDSA(hashes.SHA256())
         )


    after5 = time.perf_counter()

    one = after-before
    print(f"{one:0.4f} seconds")
    print(f"{counter} time generating 192bit ECC KeyPair")

    four = after4-before4
    print(f"{four:0.4f} seconds")
    print(f"{counter} time digital signing 192bit ECC")

    five = after5-before5
    print(f"{five:0.4f} seconds")
    print(f"{counter} time verifying signature 192bit ECC")

counter = 0
for i in range(10): 
    counter += 1
    before = time.perf_counter()
    
    private_key = ec.generate_private_key(
        ec.SECP521R1() # key size 521
)

    message = os.urandom(521)

    after = time.perf_counter()
    
    #####################################
    
    public_key = private_key.public_key()

    before4 = time.perf_counter()

    signature = private_key.sign(
         message, 
         ec.ECDSA(hashes.SHA256())
         )
    
    after4 = time.perf_counter()

    before5 = time.perf_counter()

    public_key.verify(
         signature, 
         message, 
         ec.ECDSA(hashes.SHA256())
         )


    after5 = time.perf_counter()

    one = after-before
    print(f"{one:0.4f} seconds")
    print(f"{counter} time generating 256bit ECC KeyPair")

    four = after4-before4
    print(f"{four:0.4f} seconds")
    print(f"{counter} time digital signing 256bit ECC")

    five = after5-before5
    print(f"{five:0.4f} seconds")
    print(f"{counter} time verifying signature 256bit ECC")


