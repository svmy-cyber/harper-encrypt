import os
from datetime import datetime
from time import perf_counter_ns


# Load from File
def load_from_file(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
    return content


# Save Key to File
def save_to_file(text, filename):
    with open(filename, 'w') as file:
        file.write(text)
    return filename

class CharacterContainer:
    def __init__(self, character):
        assert isinstance(character, str)
        self.character_ascii_char = character
        self.character_unicode_int = ord(self.character_ascii_char)[2:]
        self.character_binary_int = bin(self.character_unicode_int)
        self.character_binary_string = str(self.character_binary_int)

class StandardEquation:
    def __init__(self, coefficients, constant):
        assert isinstance(coefficients, list)
        assert isinstance(constant, int)
        self.coefficients = coefficients
        self.constant = constant

    def produce_blueprint(self):
        coefficients = tuple(self.coefficients)
        constant = self.constant
        return coefficients, constant


class PrivateKey:
    def __init__(self, mod_value, file_path):
        assert isinstance(mod_value, int)
        assert isinstance(file_path, str)
        self.mod_value = mod_value
        self.file_path = file_path
        # calculate random vectors
        self.vectors = [34, 23, 76]
        # calculate random errors
        self.errors = [2, -1, 0]


class PublicKey:
    def __init__(self, private_key, file_path):
        assert isinstance(private_key, PrivateKey)
        assert isinstance(file_path, str)
        self.private_key = private_key
        self.file_path = file_path
        self.standard_equations = []
        for index, vector in self.private_key.vectors:
            # create random vectors, calculate constant, and apply the private key's errors
            coefficients = [1, 2, 3]
            constant = 45 + private_key.errors[index]
            equation = StandardEquation(coefficients, constant)
            self.standard_equations.append(equation)
    def produce_blueprint(self):
        # turn the standard_equations list into a tuple


class EncapsulationEquation:
    def __init__(self, public_key):
        assert isinstance(public_key, PublicKey)
        self.component_standard_equations = []
        self.coefficients = []
        self.constant = 0
        self.component_limit = public_key.private_key.mod_value // 23
        for component in range(self.component_limit):
            self.component_standard_equations.append(select_random_equation(public_key))


def select_random_equation(public_key: PublicKey):
    nanoseconds = perf_counter_ns()
    factor = 1
    for digit in str(nanoseconds):
        if int(digit) != 0:
            factor = (factor + int(digit)) * int(digit)
    factor = factor % public_key.private_key.mod_value
    return public_key.standard_equations[factor]

if __name__ == '__main__':
    for i in range(30):
        print(perf_counter_ns())

