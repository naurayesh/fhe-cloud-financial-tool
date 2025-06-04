#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <numeric> // For std::iota
#include <cmath>   // For std::round

using namespace std;
using namespace seal;

void print_example_banner(string title) {
    if (!title.empty()) {
        size_t title_size = title.size();
        // Corrected: changed size_size_t to size_t
        size_t bar_size = max(2UL, 79UL - title_size);
        string bar_top(bar_size, '=');
        string bar_bottom(bar_size, '-');
        cout << endl;
        cout << "==" << bar_top << endl;
        cout << "= " << title << endl;
        cout << "==" << bar_bottom << endl;
    }
}

// Helper function to print a vector of integers/doubles
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
    print_example_banner("Encrypted Financial Planning Tool - Fixed-Point BFV with Multiplication");

    // 1. Setup SEAL context for BFV scheme
    EncryptionParameters parms(scheme_type::bfv);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    // Select a coefficient modulus.
    // BFVDefault(poly_modulus_degree) provides a good starting point.
    // For many multiplications, you might need to manually select primes or use larger poly_modulus_degree.
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    // Set the plaintext modulus.
    // A 30-bit prime allows for values up to approx 1 billion (2^30).
    // This is sufficient for financial values scaled by 100 (for cents).
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 30));

    SEALContext context(parms);
    cout << "SEALContext created with parameters:" << endl;
    cout << "  Scheme: BFV" << endl;
    cout << "  Poly Modulus Degree: " << parms.poly_modulus_degree() << endl;
    cout << "  Coeff Modulus Size: " << context.first_context_data()->total_coeff_modulus_bit_count() << " bits" << endl;
    cout << "  Plain Modulus: " << parms.plain_modulus().value() << endl;
    cout << "  Parameters are " << (context.parameters_set() ? "valid" : "invalid") << endl;

    // 2. Key Generation
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    // Relinearization keys are needed for ciphertext-ciphertext multiplication.
    // For ciphertext-plaintext multiplication (multiply_plain), they are not strictly needed,
    // but it's good practice to generate them if you anticipate any ciphertext-ciphertext ops.
    keygen.create_relin_keys(relin_keys);

    cout << "\nKeys generated (public, secret, relinearization)." << endl;

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);

    size_t slot_count = batch_encoder.slot_count();
    cout << "Number of slots for batching: " << slot_count << endl;

    // Define a scaling factor for fixed-point arithmetic (e.g., 100 for 2 decimal places)
    const double SCALE_FACTOR = 100.0;
    cout << "Using fixed-point scaling factor: " << SCALE_FACTOR << endl;

    // 3. Encoding and Encryption with fixed-point
    // Simulate some financial data with decimals
    vector<double> income_double_data = { 1500.75, 250.00, 75.20 }; // Example incomes
    vector<double> expense_double_data = { 450.50, 120.00, 30.80 }; // Example expenses

    vector<int64_t> income_scaled_data(slot_count, 0LL);
    for (size_t i = 0; i < income_double_data.size(); ++i) {
        income_scaled_data[i] = static_cast<int64_t>(round(income_double_data[i] * SCALE_FACTOR));
    }

    vector<int64_t> expense_scaled_data(slot_count, 0LL);
    for (size_t i = 0; i < expense_double_data.size(); ++i) {
        expense_scaled_data[i] = static_cast<int64_t>(round(expense_double_data[i] * SCALE_FACTOR));
    }

    print_vector(income_double_data, "Original Income Data (double)");
    print_vector(income_scaled_data, "Scaled Income Data (int64_t)");
    print_vector(expense_double_data, "Original Expense Data (double)");
    print_vector(expense_scaled_data, "Scaled Expense Data (int64_t)");

    // Encode and encrypt income and expense
    Plaintext encoded_income;
    batch_encoder.encode(income_scaled_data, encoded_income);
    cout << "Income data encoded to plaintext." << endl;

    Plaintext encoded_expense;
    batch_encoder.encode(expense_scaled_data, encoded_expense);
    cout << "Expense data encoded to plaintext." << endl;

    Ciphertext encrypted_income;
    encryptor.encrypt(encoded_income, encrypted_income);
    cout << "Income plaintext encrypted to ciphertext." << endl;

    Ciphertext encrypted_expense;
    encryptor.encrypt(encoded_expense, encrypted_expense);
    cout << "Expense plaintext encrypted to ciphertext." << endl;

    // 4. Homomorphic Operation: Subtraction (Income - Expenses)
    Ciphertext encrypted_net_income;
    evaluator.sub(encrypted_income, encrypted_expense, encrypted_net_income);
    cout << "\nHomomorphic subtraction performed: Encrypted Income - Encrypted Expense." << endl;

    // 5. Homomorphic Operation: Multiplication (e.g., calculate 15% of income for savings)
    // We need to encode the percentage (0.15) as a scaled integer.
    // 0.15 * SCALE_FACTOR = 15.0. So, we'll use 15.
    double savings_rate_double = 0.15; // 15%
    int64_t savings_rate_scaled = static_cast<int64_t>(round(savings_rate_double * SCALE_FACTOR));

    // We need to encode this constant into a plaintext.
    vector<int64_t> savings_rate_vector(slot_count, savings_rate_scaled);
    Plaintext encoded_savings_rate;
    batch_encoder.encode(savings_rate_vector, encoded_savings_rate);
    cout << "Savings rate (" << savings_rate_double * 100 << "%) encoded to plaintext." << endl;

    Ciphertext encrypted_savings_contribution;
    // Corrected: Use multiply_plain for ciphertext-plaintext multiplication.
    // Relinearization is not strictly needed after multiply_plain, but if you
    // anticipate chaining with ciphertext-ciphertext multiplications, it's good to know.
    evaluator.multiply_plain(encrypted_income, encoded_savings_rate, encrypted_savings_contribution);
    cout << "Homomorphic multiplication (ciphertext-plaintext) performed: Encrypted Income * Encoded Savings Rate." << endl;

    // Relinearization is typically needed after ciphertext-ciphertext multiplication.
    // For multiply_plain, it's less critical for noise, but can be used to reduce size if needed.
    // We'll keep it here for demonstration, but note it's less essential for multiply_plain.
    evaluator.relinearize(encrypted_savings_contribution, relin_keys, encrypted_savings_contribution);
    cout << "Relinearization performed on encrypted savings contribution (optional for multiply_plain)." << endl;

    // 6. Decryption of Net Income and Savings Contribution
    Plaintext decrypted_net_income;
    decryptor.decrypt(encrypted_net_income, decrypted_net_income);
    cout << "Encrypted net income decrypted to plaintext." << endl;

    Plaintext decrypted_savings_contribution;
    decryptor.decrypt(encrypted_savings_contribution, decrypted_savings_contribution);
    cout << "Encrypted savings contribution decrypted to plaintext." << endl;

    // 7. Decoding and Descaling
    vector<int64_t> decoded_net_income_scaled;
    batch_encoder.decode(decrypted_net_income, decoded_net_income_scaled);

    vector<double> decoded_net_income_double(decoded_net_income_scaled.size());
    for (size_t i = 0; i < decoded_net_income_scaled.size(); ++i) {
        decoded_net_income_double[i] = static_cast<double>(decoded_net_income_scaled[i]) / SCALE_FACTOR;
    }
    print_vector(decoded_net_income_double, "Decoded Net Income Data (double)");

    vector<int64_t> decoded_savings_contribution_scaled;
    batch_encoder.decode(decrypted_savings_contribution, decoded_savings_contribution_scaled);

    vector<double> decoded_savings_contribution_double(decoded_savings_contribution_scaled.size());
    for (size_t i = 0; i < decoded_savings_contribution_scaled.size(); ++i) {
        // Note: When multiplying a scaled number by a scaled constant, the result is scaled by SCALE_FACTOR^2.
        // So, we divide by SCALE_FACTOR * SCALE_FACTOR to get the correct decimal.
        decoded_savings_contribution_double[i] = static_cast<double>(decoded_savings_contribution_scaled[i]) / (SCALE_FACTOR * SCALE_FACTOR);
    }
    print_vector(decoded_savings_contribution_double, "Decoded Savings Contribution Data (double)");


    // Verification (for the first slot)
    cout << "\nVerification (first slot):" << endl;
    double expected_net_income = income_double_data[0] - expense_double_data[0];
    cout << "Expected Net Income: " << expected_net_income << endl;
    cout << "Actual Decoded Net Income: " << decoded_net_income_double[0] << endl;

    double expected_savings_contribution = income_double_data[0] * savings_rate_double;
    cout << "Expected Savings Contribution: " << expected_savings_contribution << endl;
    cout << "Actual Decoded Savings Contribution: " << decoded_savings_contribution_double[0] << endl;


    cout << "\nFHE BFV Fixed-Point with Multiplication example complete!" << endl;

    return 0;
}
