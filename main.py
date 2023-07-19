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


class EncryptedCharacterContainer:
    def __init__(self, public_key, character):
        assert isinstance(public_key, PublicKey)
        assert isinstance(character, str)
        self.public_key = public_key
        self.character_ascii_char = character
        self.character_unicode_int = ord(self.character_ascii_char)[2:]
        self.character_binary_int = bin(self.character_unicode_int)
        self.character_binary_string = str(self.character_binary_int)
        self.character_encrypted = []
        for binary_character in self.character_binary_string:
            encapsulation_equation = EncapsulationEquation(self.public_key, binary_character == "1")
            self.character_encrypted.append(encapsulation_equation)


class StandardEquation:
    def __init__(self, coefficients, constant):
        assert isinstance(coefficients, list)
        assert isinstance(constant, int)
        self.coefficients = coefficients
        self.constant = constant

    def embed_data(self, data):
        assert isinstance(data, int)
        self.constant = self.constant + data

    def add_equation(self, standard_equation):
        assert isinstance(standard_equation, StandardEquation)
        for index, coefficient in enumerate(standard_equation.coefficients):
            self.coefficients[index] = self.coefficients[index] + coefficient
        self.constant = self.constant + standard_equation.constant

    def extract_data(self, vectors, mod_value):
        assert isinstance(vectors, list)
        assert isinstance(mod_value, int)
        tolerance = (mod_value // 4)
        affirmative = mod_value // 2
        affirmative_lower_boundary = affirmative - tolerance
        affirmative_upper_boundary = affirmative + tolerance
        negative = 0
        negative_lower_boundary = negative - tolerance
        negative_upper_boundary = negative + tolerance
        actual_solution = 0
        for index, vector in vectors:
            product = vector * self.coefficients[index]
            actual_solution = actual_solution + product
        difference = self.constant - actual_solution
        if affirmative_upper_boundary > difference > affirmative_lower_boundary:
            data = 1
        elif negative_upper_boundary > difference > negative_lower_boundary:
            data = 0
        else:
            raise Exception("Invalid data detected") # replace with random generated data later
        return data


class EncapsulationEquation:
    def __init__(self, public_key, data):
        assert isinstance(public_key, PublicKey)
        self.component_standard_equations = []
        self.encapsulation_equation = StandardEquation([], 0)
        self.component_limit = public_key.private_key.mod_value // 23
        for component in range(self.component_limit):
            self.component_standard_equations.append(select_random_equation(public_key))
        for equation in self.component_standard_equations:
            self.encapsulation_equation.add_equation(equation)
        self.processed_data = ((public_key.private_key.mod_value // 2) * data)
        self.encapsulation_equation.embed_data(self.processed_data)


class EncryptedBlock:
    def __init__(self, public_key, plain_string):
        assert isinstance(public_key, PublicKey)
        assert isinstance(plain_string, str)
        self.public_key = public_key
        self.plain_string = plain_string
        self.encrypted_object = []
        self.encrypted_string = ""
        for letter in plain_string:
            encrypted_character = EncryptedCharacterContainer(self.public_key, letter)
            self.encrypted_object.append(encrypted_character.character_encrypted)


class DecryptedBlock:
    def __init__(self, public_key, private_key, encrypted_string):
        assert isinstance(public_key, PublicKey)
        assert isinstance(private_key, PrivateKey)
        assert isinstance(encrypted_string, str)
        self.public_key = public_key
        self.private_key = private_key
        self.encrypted_string = encrypted_string
        self.encrypted_object = list(encrypted_string)
        self.plain_string = ""
        for character_encrypted in self.encrypted_object:
            character_decrypted = DecryptedCharacterContainer(self.public_key, self.private_key, character_encrypted)
            self.plain_string = self.plain_string + character_decrypted.character_ascii_char


class DecryptedCharacterContainer:
    def __init__(self, public_key, private_key, character_encrypted):
        assert isinstance(public_key, PublicKey)
        assert isinstance(private_key, PrivateKey)
        assert isinstance(character_encrypted, list)
        self.public_key = public_key
        self.private_key = private_key
        self.character_encrypted = character_encrypted
        self.character_binary_string = ""
        for equation_string in character_encrypted:
            equation_list = list(equation_string)
            equation_coefficient_list = list(equation_list[0])
            equation_constant = equation_list[1]
            equation = StandardEquation(equation_coefficient_list, equation_constant)
            self.character_binary_string = self.character_binary_string + equation.extract_data(self.private_key.vectors, self.private_key.mod_value)
        self.character_unicode_int = int(self.character_binary_string, 2)
        self.character_ascii_char = chr(self.character_unicode_int)


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


def select_random_equation(public_key: PublicKey):
    index = return_random_int(public_key.private_key.mod_value)
    return public_key.standard_equations[index]


def return_random_int(mod_value: int):
    nanoseconds = perf_counter_ns()
    factor = 1
    for digit in str(nanoseconds):
        if int(digit) != 0:
            factor = (factor + int(digit)) * int(digit)
    factor = factor % mod_value
    return factor


def show_menu():
    print("1. Configure New Key Pair")
    print("2. Encrypt Text")
    print("3. Decrypt Text")
    print("4. Exit")


def handle_option(selected_option):
    if selected_option == 1:
        print("Configure Key Pair")

    elif selected_option == 2:
        print("Encrypt Text")

    elif selected_option == 3:
        print("Decrypt Text")

    elif selected_option == 4:
        print("Exiting the program...")
        exit()
    else:
        print("Invalid option. Please try again.")

if __name__ == '__main__':

    while True:
        show_menu()
        user_input = input("Select an option: ")
        try:
            option = int(user_input)
            handle_option(option)
        except ValueError:
            print("Invalid input. Please enter a number.")
