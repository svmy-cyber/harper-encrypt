import os
from time import perf_counter_ns


def load_from_file(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
    return content


def save_to_file(item_list, file_path):
    with open(file_path, 'w') as file:
        file.write(str(item_list))
    return file_path


class EncryptedCharacterContainer:
    def __init__(self, public_key, character):
        assert isinstance(public_key, PublicKey)
        assert isinstance(character, str)
        self.public_key = public_key
        self.character_ascii_char = character
        self.character_unicode_int = ord(self.character_ascii_char)
        self.character_binary_string = bin(self.character_unicode_int)[2:].zfill(8)
        self.encapsulation_equations_stringified = []
        self.encapsulation_equations_structured = []
        for binary_character in self.character_binary_string:
            encapsulation_equation = EncapsulationEquation(self.public_key, binary_character == "1")
            self.encapsulation_equations_structured.append(encapsulation_equation)
            self.encapsulation_equations_stringified.append(encapsulation_equation.stringify())


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
            if len(self.coefficients) < len(standard_equation.coefficients):
                self.coefficients.append(coefficient)
            else:
                self.coefficients[index] = self.coefficients[index] + coefficient
        self.constant = self.constant + standard_equation.constant

    def stringify(self):
        return [self.coefficients, self.constant]

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
        for index, vector in enumerate(vectors):
            product = vector * self.coefficients[index]
            actual_solution = actual_solution + product
        difference = self.constant - actual_solution
        if affirmative_upper_boundary > difference > affirmative_lower_boundary:
            data = str(1)
        elif negative_upper_boundary > difference > negative_lower_boundary:
            data = str(0)
        else:
            data = str(return_random_int(2, False))
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

    def stringify(self):
        return [self.encapsulation_equation.coefficients, self.encapsulation_equation.constant]


class EncryptedString:
    def __init__(self, public_key, plain_string, encrypted_string_file_path):
        assert isinstance(public_key, PublicKey)
        assert isinstance(plain_string, str)
        assert isinstance(encrypted_string_file_path, str)
        self.public_key = public_key
        self.plain_string = plain_string
        self.encrypted_string_structured = []
        self.encrypted_string_stringified = []
        self.encrypted_string_file_path = encrypted_string_file_path
        for letter in self.plain_string:
            encrypted_character = EncryptedCharacterContainer(self.public_key, letter)
            self.encrypted_string_structured.append(encrypted_character.encapsulation_equations_structured)
            self.encrypted_string_stringified.append(encrypted_character.encapsulation_equations_stringified)
        save_to_file(self.encrypted_string_stringified, self.encrypted_string_file_path)


class DecryptedString:
    def __init__(self, public_key, private_key, encrypted_string, decrypted_string_file_path):
        assert isinstance(public_key, PublicKey)
        assert isinstance(private_key, PrivateKey)
        assert isinstance(encrypted_string, str)
        assert isinstance(decrypted_string_file_path, str)
        self.public_key = public_key
        self.private_key = private_key
        self.decrypted_string_file_path = decrypted_string_file_path
        self.encrypted_string_stringified = eval(encrypted_string)
        self.decrypted_string = ""
        for character_encrypted in self.encrypted_string_stringified:
            character_decrypted = DecryptedCharacterContainer(self.public_key, self.private_key, character_encrypted)
            self.decrypted_string = self.decrypted_string + character_decrypted.character_ascii_char
        save_to_file(self.decrypted_string, self.decrypted_string_file_path)


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
            self.character_binary_string = self.character_binary_string + equation.extract_data(
                self.private_key.vectors, self.private_key.mod_value)
        self.character_unicode_int = int(self.character_binary_string, 2)
        self.character_ascii_char = chr(self.character_unicode_int)


class PrivateKey:
    def __init__(self, file_path, mod_value):
        assert isinstance(file_path, str)
        assert isinstance(mod_value, int)
        self.file_path = file_path
        self.mod_value = mod_value
        self.max_error = 3
        self.vectors = []
        if os.path.isfile(self.file_path):
            self.vectors = eval(load_from_file(self.file_path))
        else:
            for i in range(self.mod_value):
                self.vectors.append(return_random_int(self.mod_value, True))
            save_to_file(str(self.vectors), self.file_path)


class PublicKey:
    def __init__(self, file_path, mod_value):
        assert isinstance(file_path, str)
        assert isinstance(mod_value, int)
        self.file_path = file_path
        self.mod_value = mod_value
        self.standard_equations_stringified = []
        self.standard_equations_structured = []
        if os.path.isfile(self.file_path):
            self.standard_equations_stringified = eval(load_from_file(self.file_path))
            for index, equation in enumerate(self.standard_equations_stringified):
                coefficient_list = list(equation[0])
                constant = equation[1]
                self.standard_equations_structured.append(StandardEquation(coefficient_list, constant))
        else:
            private_key = PrivateKey(self.file_path.replace("public", "private"), self.mod_value)
            for equation_index in range(self.mod_value):
                coefficients = []
                constant = 0
                for coefficient_index in range(self.mod_value):
                    random_coefficient = return_random_int(self.mod_value, True)
                    coefficients.append(random_coefficient)
                    product = (coefficients[coefficient_index] * private_key.vectors[coefficient_index])
                    constant = constant + product
                constant = constant + generate_error(4)
                new_standard_equation = StandardEquation(coefficients, constant)
                self.standard_equations_structured.append(new_standard_equation)
                self.standard_equations_stringified.append(new_standard_equation.stringify())
            save_to_file(self.standard_equations_stringified, self.file_path)


def generate_error(max_error: int):
    negative = return_random_int(2, False)
    error = return_random_int(max_error, True)
    if negative:
        return error * -1
    return error


def select_random_equation(public_key: PublicKey):
    index = return_random_int(public_key.mod_value, False)
    return public_key.standard_equations_structured[index]


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


def generate_or_load_public_key(mod_value: int):
    key_pair_identifier_input = input("Enter a Key Pair identifier string: ")
    public_key_file_path = os.getcwd() + "\\" + key_pair_identifier_input + "_public_key.txt"
    public_key = PublicKey(public_key_file_path, mod_value)
    return public_key


def request_and_process_cipher_identifier(planned_action: str):
    identifier = input("Enter an identifier string: ")
    proposed_path = os.getcwd() + "\\" + identifier
    if planned_action == "encrypt":
        return preflight_checks_encrypt(proposed_path)
    else:
        return preflight_checks_decrypt(proposed_path)


def preflight_checks_decrypt(proposed_path: str):
    full_path_decrypted = proposed_path + "_decrypted.txt"
    full_path_encrypted = proposed_path + "_encrypted.txt"
    if not os.path.isfile(full_path_encrypted):
        raise Exception("The specified file does not exist.")
    if os.path.isfile(full_path_decrypted):
        raise Exception("The proposed action would overwrite an existing file.")
    return [full_path_encrypted, full_path_decrypted]


def preflight_checks_encrypt(proposed_path: str):
    full_path_encrypted = proposed_path + "_encrypted.txt"
    if os.path.isfile(full_path_encrypted):
        raise Exception("The proposed action would overwrite an existing file.")
    return full_path_encrypted


def show_menu():
    print("1. Configure New Key Pair")
    print("2. Encrypt Text")
    print("3. Decrypt Text")
    print("4. Exit")


def handle_option(selected_option):
    if selected_option == 1:
        print("Configure Key Pair")
        generate_or_load_public_key(89)
    elif selected_option == 2:
        print("Encrypt Text")
        public_key = generate_or_load_public_key(89)
        encrypted_string_path = request_and_process_cipher_identifier("encrypt")
        text_to_encrypt_input = input("Enter text to encrypt: ")
        EncryptedString(public_key, text_to_encrypt_input, encrypted_string_path)
        print("Text Successfully Encrypted")
    elif selected_option == 3:
        print("Decrypt Text")
        public_key = generate_or_load_public_key(89)
        private_key = PrivateKey(public_key.file_path.replace("public", "private"), 89)
        encrypted_and_decrypted_full_paths = request_and_process_cipher_identifier("decrypt")
        encrypted_text = load_from_file(encrypted_and_decrypted_full_paths[0])
        decrypted_string = DecryptedString(public_key, private_key, encrypted_text, encrypted_and_decrypted_full_paths[1])
        print("Decrypted Text: " + decrypted_string.decrypted_string)
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
