#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <numeric> // For std::iota

using namespace std;
using namespace seal;

void print_example_banner(string title) {
    if (!title.empty()) {
        size_t title_size = title.size();
        size_t bar_size = max(2UL, 79UL - title_size);
        string bar_top(bar_size, '=');
        string bar_bottom(bar_size, '-');
        cout << endl;
        cout << "==" << bar_top << endl;
        cout << "= " << title << endl;
        cout << "==" << bar_bottom << endl;
    }
}

// Helper function to print a vector of integers
template<typename T>
void print_vector(const vector<T>& vec, const string& name = "") {
    if (!name.empty()) {
        cout << name << ": ";
    }
    cout << "[";
    for (size_t i = 0; i < vec.size(); ++i) {
        cout << vec[i] << (i == vec.size() - 1 ? "" : ", ");
    }
    cout << "]" << endl;
}

int main() {
    print_example_banner("Encrypted Financial Planning Tool - FHE Basics (BFV)");

    // 1. Setup SEAL context for BFV scheme
    // We need to choose appropriate encryption parameters.
    // For BFV, we need:
    // - poly_modulus_degree: Determines the size of the ciphertext and the complexity of operations.
    //   A larger degree allows for more complex computations but increases ciphertext size and computation time.
    // - coeff_modulus: A product of prime numbers. The size of this product determines the security level
    //   and the number of homomorphic operations possible.
    // - plain_modulus: The modulus for the plaintext space. This determines the range of integers
    //   that can be encoded and operated on. For exact integer arithmetic, this is crucial.

    EncryptionParameters parms(scheme_type::bfv);

    // Choose a polynomial modulus degree. 8192 is a common choice for initial examples.
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    // Select a coefficient modulus. `CoeffModulus::BFVDefault` provides a good default set
    // of primes for the chosen `poly_modulus_degree`.
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    // Set the plaintext modulus. For financial calculations, we often deal with integers.
    // A plain_modulus of 256 allows for computations on integers up to 255.
    // For larger numbers, you'd need a larger plain_modulus or use batching more effectively.
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20)); // Example: numbers from 0 to 255

    // Create the SEALContext. This object validates the parameters and
    // holds all necessary information for encryption, decryption, and homomorphic operations.
    SEALContext context(parms);
    cout << "SEALContext created with parameters:" << endl;
    cout << "  Scheme: BFV" << endl;
    cout << "  Poly Modulus Degree: " << parms.poly_modulus_degree() << endl;
    cout << "  Coeff Modulus Size: " << context.first_context_data()->total_coeff_modulus_bit_count() << " bits" << endl;
    cout << "  Plain Modulus: " << parms.plain_modulus().value() << endl;
    cout << "  Parameters are " << (context.parameters_set() ? "valid" : "invalid") << endl;

    // 2. Key Generation
    // KeyGenerator: Generates public, secret, and relinearization keys.
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys); // Required for multiplication

    cout << "\nKeys generated (public, secret, relinearization)." << endl;

    // Encryptor: Uses the public key to encrypt plaintexts.
    Encryptor encryptor(context, public_key);
    // Decryptor: Uses the secret key to decrypt ciphertexts.
    Decryptor decryptor(context, secret_key);
    // Evaluator: Performs homomorphic operations on ciphertexts.
    Evaluator evaluator(context);
    // BatchEncoder: Encodes/decodes vectors of integers into/from plaintexts.
    // This is crucial for efficient operations on multiple data points.
    BatchEncoder batch_encoder(context);

    // The number of slots available for batching is equal to the poly_modulus_degree.
    size_t slot_count = batch_encoder.slot_count();
    cout << "Number of slots for batching: " << slot_count << endl;

    // 3. Encoding and Encryption
    // Let's simulate some financial data: income and expenses.
    // We'll use a vector of integers to represent these.
    // For simplicity, we'll fill the first few slots with meaningful data.
    vector<uint64_t> income_data(slot_count, 0ULL);
    income_data[0] = 100; // Monthly income
    income_data[1] = 50;  // Bonus
    income_data[2] = 20;  // Side hustle

    vector<uint64_t> expense_data(slot_count, 0ULL);
    expense_data[0] = 30; // Rent
    expense_data[1] = 15; // Groceries
    expense_data[2] = 5;  // Transportation

    print_vector(income_data, "Original Income Data");
    print_vector(expense_data, "Original Expense Data");

    // Encode the integer vectors into Plaintext objects
    Plaintext encoded_income;
    batch_encoder.encode(income_data, encoded_income);
    cout << "Income data encoded to plaintext." << endl;

    Plaintext encoded_expense;
    batch_encoder.encode(expense_data, encoded_expense);
    cout << "Expense data encoded to plaintext." << endl;

    // Encrypt the Plaintext objects into Ciphertext objects
    Ciphertext encrypted_income;
    encryptor.encrypt(encoded_income, encrypted_income);
    cout << "Income plaintext encrypted to ciphertext." << endl;

    Ciphertext encrypted_expense;
    encryptor.encrypt(encoded_expense, encrypted_expense);
    cout << "Expense plaintext encrypted to ciphertext." << endl;

    // 4. Homomorphic Operation: Subtraction (Income - Expenses)
    // This is where the magic happens: we perform operations on encrypted data!
    Ciphertext encrypted_net_income;
    evaluator.sub(encrypted_income, encrypted_expense, encrypted_net_income);
    cout << "\nHomomorphic subtraction performed: Encrypted Income - Encrypted Expense." << endl;

    // 5. Decryption
    Plaintext decrypted_net_income;
    decryptor.decrypt(encrypted_net_income, decrypted_net_income);
    cout << "Encrypted net income decrypted to plaintext." << endl;

    // 6. Decoding
    vector<uint64_t> decoded_net_income;
    batch_encoder.decode(decrypted_net_income, decoded_net_income);

    print_vector(decoded_net_income, "Decoded Net Income Data");

    // Verification
    cout << "\nVerification:" << endl;
    cout << "Expected Net Income (first slot): " << income_data[0] - expense_data[0] << endl;
    cout << "Actual Decoded Net Income (first slot): " << decoded_net_income[0] << endl;

    cout << "\nFHE BFV 'Hello World' example complete!" << endl;

    return 0;
}
