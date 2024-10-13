#include <iostream> 
#include <stdlib.h> 
#include <math.h> 
using namespace std; 

// Function to compute the greatest common divisor (GCD) using Euclid's algorithm
int gcd(int a, int b)
{
    if (b == 0)
        return a;
    return gcd(b, a % b); 
}

int main() {
  // Declaration of variables for message, prime numbers, public/private keys, etc.
  double m, p, q, e, i, d;
  int flag;
  
  // Prompt user to enter the message (number) to be encrypted and decrypted
  cout<<"Enter the number to be encrypted and decryted\n";
  cin>>m;
  
  // Prompt user to enter the first prime number
  cout<<"Enter first prime number\n";
  cin>>p;
  
  // Prompt user to enter the second prime number
  cout<<"Enter second prime number\n\n";
  cin>>q;
  
  // Compute n as the product of the two prime numbers p and q
  // n is part of the public and private keys
  int n = p * q;
  
  // Compute Euler's totient function φ (phi), which is (p-1)*(q-1)
  // φ is used to help determine the public and private keys
  int phi = (p-1) * (q-1);
  
  // Choose an integer e such that 1 < e < phi and gcd(e, phi) = 1
  // e is the public key exponent
  for(i = 2; i < phi; i++)
  {
    // Ensure that e is co-prime with φ by checking if gcd(e, phi) is 1
    if(gcd(i, phi) == 1)
    {
      e = i;
      break;  // Once a valid e is found, exit the loop
    }
  }
  
  // Now, we need to find the private key exponent d
  // d is chosen such that (d * e) % phi = 1 (i.e., d is the modular inverse of e mod φ)
  // We iterate over possible values of i to find a suitable d
  i = 1;
  while(true)
  {
    // j is calculated as (phi * i) + 1
    // We are looking for the smallest integer d such that (j / e) is an integer
    int j = (phi * i) + 1;
    if(fmod(j, e) == 0)  // Check if j is divisible by e
    {
      d = j / e;  // If true, assign d
      break;  // Exit the loop once a valid d is found
    }
    i++;  // Increment i and continue searching for a valid d
  }
  
  // Display the computed values of φ, d, and e
  cout<<"The value of phi: "<<phi<<endl;
  cout<<"The value of d: "<<d<<endl;
  cout<<"The value of e: "<<e<<endl;
  
  // Display the public encryption key (e, n) and the private decryption key (d, n)
  cout<<"Public encryption key: (" <<e<<" , " <<n<< ") "<<endl;
  cout<<"Private dencryption key: (" <<d<<" , " <<n<< ") "<<endl;
  
  // Encryption: Compute the ciphertext c = (m^e) % n
  // We use the message m, raised to the power of e, then modulo n
  int cipher = fmod(pow(m, e), n);
  cout<<"Encrypted Ciphertext : "<<cipher<<endl;
  
  // Decryption: Compute the plaintext m = (c^d) % n
  // We use the ciphertext c, raised to the power of d, then modulo n
  int plain = fmod(pow(cipher, d), n);
  cout<<"Decrypted Plaintext : "<<plain<<endl;
  
  return 0;
}
