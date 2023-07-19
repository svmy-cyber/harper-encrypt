import os
from time import perf_counter_ns


def load_from_file(file_path):
    path_with_extension = file_path + ".txt"
    with open(file_path, 'r') as file:
        content = file.read()
    return content


def save_to_file(text, file_path):
    path_with_extension = file_path + ".txt"
    with open(path_with_extension, 'w') as file:
        file.write(text)
    return file_path


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
        self.component_limit = 5
        for component in range(self.component_limit):
            self.component_standard_equations.append(select_random_equation(public_key))
        for equation in self.component_standard_equations:
            self.encapsulation_equation.add_equation(equation)
        self.processed_data = ((public_key.mod_value // 2) * data)
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
    def __init__(self, file_path, mod_value):
        assert isinstance(file_path, str)
        assert isinstance(mod_value, int)
        self.mod_value = mod_value
        self.max_error = 3
        self.vectors = []
        path_with_extension = file_path + ".txt"
        if os.path.isfile(path_with_extension):
            self.vectors = eval(load_from_file(path_with_extension))
        else:
            for i in range(self.mod_value):
                self.vectors.append(return_random_int(self.mod_value, True))
            save_to_file(str(self.vectors), file_path)


class PublicKey:
    def __init__(self, file_path, mod_value):
        assert isinstance(file_path, str)
        assert isinstance(mod_value, int)
        self.file_path = file_path
        self.mod_value = mod_value
        self.standard_equations = []
        path_with_extension = file_path + ".txt"
        if os.path.isfile(path_with_extension):
            self.standard_equations = eval(load_from_file(path_with_extension))
        else:
            private_key = PrivateKey(file_path + "_PrivateKey", self.mod_value)
            for equation_index in range(self.mod_value):
                coefficients = []
                constant = return_random_int(3, False)
                for coefficient_index in range(self.mod_value):
                    random_coefficient = return_random_int(self.mod_value, True)
                    coefficients.append(random_coefficient)
                    product = (coefficients[coefficient_index] * private_key.vectors[coefficient_index])
                    constant = constant + product
                new_standard_equation = StandardEquation(coefficients, constant)
                self.standard_equations.append(new_standard_equation)
            save_to_file(str(self.standard_equations), file_path)


def select_random_equation(public_key: PublicKey):
    index = return_random_int(public_key.mod_value, False)
    return public_key.standard_equations[index]


def return_random_int(mod_value: int, non_zero: bool):
    nanoseconds = perf_counter_ns()
    factor = 1
    for digit in str(nanoseconds):
        if int(digit) != 0:
            factor = (factor + int(digit)) * int(digit)
    factor = factor % mod_value
    if factor == 0 and non_zero:
        return 1
    return factor


def show_menu():
    print("1. Configure New Key Pair")
    print("2. Encrypt Text")
    print("3. Decrypt Text")
    print("4. Exit")


def handle_option(selected_option):
    if selected_option == 1:
        print("Configure Key Pair")
        identifier_input = input("Enter a Key Pair identifier string: ")
        path = os.getcwd() + "\\" + identifier_input
        PublicKey(path, 89)
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
