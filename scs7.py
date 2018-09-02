from pwn import *
from Levenshtein import distance
import string

for char in list("a"): #change len(list) to try more symbols
    #connecting to the server, getting the enc_flag
    r = remote("crypto.chal.ctf.westerns.tokyo",14791)
    mask = 'TWCTF{67ced5346146c105075443add26fd7efd72763dd}'  # change for your needs
    # mask +=char # uncomment to apply more symbols in list
    enc_flag = str(r.recvline()[16:80])
    print enc_flag + "\n\r" + "  with mask",mask+"\n" #get enc_flag
    r.recvuntil('\n',drop=True) # just skipping the line

    #setting up the charset lower-case + numbers
    chars = list("abcdefg") + list(range(0,10)) # list(string.ascii_uppercase)

    #here we generate const string
    #coz last symbols doesn't really matter
    def gen_temp_const(fchar):
        #fchar = 0 by default
        global tmp_const
        tmp_const=''
        for i in range(0,39-fchar):
            tmp_const+='z'

    #sending msg with a specified string
    def msg_send(mask,const,foreach):
        # print mask+const+"}\n" + "DEBUG"
        r.send(mask+const+"}\n")
        enc_msg = r.recvline()[21:85]
        #print enc_msg,curret character and Levenshtein distance
        print enc_msg,chars[foreach],distance(enc_flag,enc_msg) #compare strings with Lev distance enc_msg,

    #creating the - "const[0]" - first char from charset
    def gen_const(foreach,tmp_const): # consts generated
        global const
        const = ''
        #print(chars[foreach])
        const+=str(chars[foreach])
        const+=tmp_const 
    def main():

        gen_temp_const(len(mask)-6) #cheking "known" symbols with cut
        for i in range(0,len(chars)):
            gen_const(i,tmp_const)
            msg_send(mask,const,i)

    main()
