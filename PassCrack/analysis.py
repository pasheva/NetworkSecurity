"""
Mariya Pasheva
Homework 2

TASK 2
^^^^^^

Freq. of letters in English in decreasing order:
e t a o i n s r h l d c u m f p g w y b v k x j q z

Freq. of letters in Englsih begin with:
t a i s o w h b c m f p d r l e g n y u k v j q x z

Freq of letters in English end with:
e s t d n r y f l o g h a k m p u w


One Letter
a I

Digraph
of, to, in, it, is, be, as, at, so, we, he, by, or, on, do, if, me, my, up, an, go, no, us, am

Trigraph Freq.
the and tha ent ion tio for nde has nce tis oft men
"""


def tokenize_file_into_letters() -> dict:
    letter_freq = {} # <char,int>
    with open("encrypted.txt", "r") as file:
        while True:
            char = file.read(1)
            if not char:
                break
            if not(char == " " or char == "," or char == "."):
                if char in letter_freq:
                    letter_freq[char] += 1
                else:
                    letter_freq[char] = 1
    # Sorting chars in descending order by num of occurances.
    letter_freq = {k: v for k, v in sorted(letter_freq.items(), key=lambda c: c[1], reverse=True)}
    return letter_freq;

def tokenize_file_words() -> list:
    word_list = []
    with open("encrypted.txt", "r") as file:
        for row in file:
            for word in row.split():
                word_list.append(word)
    return word_list


"""
Separating the one word letters from the text.
They could either be A or I
A is more used than I. 
"""
def one_letter(encrypted_text)->dict:
    one_letters = {}  #<letter,freq>
    for i in encrypted_text:
        if len(i) == 1:
            if i in one_letters:
                one_letters[i] += 1
            else:
                one_letters[i] = 1
    # Sorting chars in descending order by num of occurances.
    one_letters = {k: v for k, v in sorted(one_letters.items(), key=lambda c: c[1], reverse=True)}
    return one_letters

def two_letter(encrypted_text)->dict:
    two_letters = {}
    for i in encrypted_text:
        if len(i) == 2:
            if i in two_letters:
                two_letters[i] += 1
            else:
                two_letters[i] = 1
    # Sorting chars in descending order by num of occurances.
    two_letters = {k: v for k, v in sorted(two_letters.items(), key=lambda c: c[1], reverse=True)}
    return two_letters


def three_letter(encrypted_text)->dict:
    three_letters = {}
    for i in encrypted_text:
        if len(i) == 3:
            if i in three_letters:
                three_letters[i] += 1
            else:
                three_letters[i] = 1
    # Sorting chars in descending order by num of occurances.
    three_letters = {k: v for k, v in sorted(three_letters.items(), key=lambda c: c[1], reverse=True)}
    return three_letters

def main():

    # Map which stores the char as a key and value, number of occurances,
    # in the encrypted.
    encrypted_letter_freq = tokenize_file_into_letters()
    print(encrypted_letter_freq)

    # Words in the encrypted file.
    encrypted_text = tokenize_file_words()

    #The most commonly used one letters in the text
    one_letters = one_letter(encrypted_text)
    print(one_letters)
    # A -> S
    # I -> D


    #The most commonly used digraphs.
    two_letters = two_letter(encrypted_text)
    print(two_letters)



    # The most commonly used trigraphs.
    three_letters = three_letter(encrypted_text)
    print(three_letters)
    #the and tha ent ion tio for nde has nce tis oft men




#Run
main()