import time
import datetime
import uuid
import Crypto.Random
from Crypto.Cipher import AES
import hashlib

# counter to provide node_number
GLOBAL_COUNTER = 0

# salt size in bytes
SALT_SIZE = 16

# number of iterations in the key generation
NUMBER_OF_ITERATIONS = 20

# the size multiple required for AES
AES_MULTIPLE = 16

# global dictionary containing all the parent nodes
multiset = dict()

"""
MakeSet(x) initializes disjoint set for object x
Find(x) returns representative object of the set containing x
Union(x,y) makes two sets containing x and y respectively into one set
"""


def make_set(x):
    global GLOBAL_COUNTER
    global multiset
    GLOBAL_COUNTER += 1

    x.parent = x
    x.length = 0
    x.node_number = GLOBAL_COUNTER
    multiset[str(GLOBAL_COUNTER)] = x


def union(x, y):
    global multiset

    xroot = find(x)
    yroot = find(y)
    if xroot != yroot:
        if xroot.length >= yroot.length:
            yroot.parent = xroot
            xroot.child_node_id = yroot.node_id
            yroot.reference_node_id = xroot.node_id
            xroot.length = xroot.length + 1
            if multiset[str(yroot.node_number)] is not None:
                del multiset[str(yroot.node_number)]
        elif xroot.length < yroot.length:
            xroot.parent = yroot
            yroot.child_node_id = xroot.node_id
            xroot.reference_node_id = yroot.node_id
            yroot.length = yroot.length + 1
            if multiset[str(xroot.node_number)] is not None:
                del multiset[str(xroot.node_number)]


def find(x):
    if x.parent == x:
        return x
    else:
        x.parent = find(x.parent)
    return x.parent


class Node:
    """
    Defines the basic structure of Node
    """
    def __init__(self):
        self.timestamp = None
        self.data = None
        self.node_number = None
        self.node_id = None
        self.reference_node_id = None
        self.child_node_id = None
        self.reference_node_id = None

    def make_new_set(self, _name, _address, _mobile, _phone, _value, _password):
        self.timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
        self.data = Node.encrypt(_name + "," + _address + "," + str(_mobile) + "," + str(_phone) + "," + str(_value), _password)
        self.node_id = uuid.uuid4()
        make_set(self)

    @staticmethod
    def generate_key(password, salt, iterations):
        assert iterations > 0
        key = password + salt
        for i in range(iterations):
            key = hashlib.sha256(key).digest()
        return key

    @staticmethod
    def pad_text(text, multiple):
        extra_bytes = len(text) % multiple
        padding_size = multiple - extra_bytes
        padding = chr(padding_size) * padding_size
        padded_text = text + padding
        return padded_text

    @staticmethod
    def unpad_text(padded_text):
        padding_size = ord(padded_text[-1])
        text = padded_text[:-padding_size]
        return text

    @staticmethod
    def encrypt(plaintext, password):
        salt = Crypto.Random.get_random_bytes(SALT_SIZE)
        key = Node.generate_key(password, salt, NUMBER_OF_ITERATIONS)
        cipher = AES.new(key, AES.MODE_ECB)
        padded_plaintext = Node.pad_text(plaintext, AES_MULTIPLE)
        ciphertext = cipher.encrypt(padded_plaintext)
        ciphertext_with_salt = salt + ciphertext
        return ciphertext_with_salt

    @staticmethod
    def decrypt(ciphertext, password):
        salt = ciphertext[0:SALT_SIZE]
        ciphertext_sans_salt = ciphertext[SALT_SIZE:]
        key = Node.generate_key(password, salt, NUMBER_OF_ITERATIONS)
        cipher = AES.new(key, AES.MODE_ECB)
        padded_plaintext = cipher.decrypt(ciphertext_sans_salt)
        plaintext = Node.unpad_text(padded_plaintext)
        return plaintext


if __name__ == "__main__":
    node1 = Node()
    node1.make_new_set("node1", "address1", 9999999999, 2222222, 1, "pass1")
    print(node1.node_id)

    node2 = Node()
    node2.make_new_set("node2", "address2", 9999999999, 2222222, 2, "pass2")
    print(node2.node_id)

    node3 = Node()
    node3.make_new_set("node3", "address3", 9999999999, 2222222, 3, "pass3")
    print(node3.node_id)

    union(node1, node2)
    print(node1.child_node_id)




