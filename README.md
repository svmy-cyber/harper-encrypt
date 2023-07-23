# harper-encrypt
A Python app built with the aim of building a reasonably secure encryption system that maintains some degree of quantum resistance.
<br/>
Building on the foundations already laid by Oded Regev in developing the Learning with Errors problem and explained brilliantly by [Kelsey Houston-Edwards](https://youtu.be/K026C5YaB3A) and [Veritasium](https://youtu.be/-UrdExQW0cs), among others.
<br/>
It uses a single seed prime number as the basis for all consequential variables of the algorithm.
Here are three possible examples:
<br/>
#### Example 1 - Seed Modulus: 23<br/>
a. Count of unique variables per equation: 23 (Seed Modulus)<br/>
b. Count of equations per Public Key: 11 (Seed Modulus // 2)<br/>
c. Max Public Key equation error: 1 (0.05 * Seed Modulus)<br/>
d. Max Encapsulation Equation error: 4 (Seed Modulus // 4<br/>
e. Max operations per Encapsulation Equation: 4 (d // c)<br/>
<br/>
#### Example 2 - Seed Modulus: 89<br/>
a. Count of unique variables per Public Key equation: 89<br/>
b. Count of equations per Public Key: 44<br/>
c. Max Public Key equation error: 4<br/>
d. Max Encapsulation Equation error: 21<br/>
3. Max operations per Encapsulation Equation: 5<br/>
<br/>
#### Example 3 - Seed Modulus: 499<br/>
a. Count of unique variables per equation: 499<br/>
b. Count of equations per Public Key: 249<br/>
c. Max Public Key equation error: 24<br/>
d. Max Encapsulation Equation error: 123<br/>
e. Max operations per Encapsulation Equation: 4<br/>
<br/>
With the count of Public Key equations (b) being half the count of variables to solve for (a), the system remains under-determined.
<br/>
The max error per Public Key constant (c) and max Encapsulation Equation error (d) are both used to limit the number of operations allowed per Encapsulation Equation (e).

As you can see, all that's required to increase the cryptographic strength of the algorithm is increasing the size of the seed modulus prime number.

In my testing, I've found values between 89 and 499 provide a good balance of performance and strength.

As a source of entropy, I decided to use the imperfect timing of computation operations within the app, using the total nanoseconds at various points of processing to make selections.

ASCII text characters are transformed to and from 8-bit binary values, which are then encrypted into their own unique equation.

The binary values can then be decrypted with the Private Key by solving the equations and determining the encoded bit in each encapsulation equation.
