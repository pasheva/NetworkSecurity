def utf8len(s):
    return len(s.encode('utf-8'))

a = utf8len("5d41402abc4b2a76b9719d911017c592")/8;
print(a)