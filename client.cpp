#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <numeric>
#include <cmath>
#include <fstream>
#include <sstream>

// Headers for socket programming
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;
using namespace seal;

// Function to send data over a socket with a size prefix
bool send_data(int sock, const string& data) {
    size_t data_size = data.size();
    if (send(sock, &data_size, sizeof(data_size), 0) == -1) {
        cerr << "Error sending data size." << endl;
        return false;
    }
    if (send(sock, data.c_str(), data_size, 0) == -1) {
        cerr << "Error sending data." << endl;
        return false;
    }
    return true;
}

// Function to receive data over a socket with a size prefix
string receive_data(int sock) {
    size_t data_size;
    if (recv(sock, &data_size, sizeof(data_size), MSG_WAITALL) == -1) {
        cerr << "Error receiving data size." << endl;
        return "";
    }

    vector<char> buffer(data_size);
    if (recv(sock, buffer.data(), data_size, MSG_WAITALL) == -1) {
        cerr << "Error receiving data." << endl;
        return "";
    }
    return string(buffer.begin(), buffer.end());
}

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
    print_example_banner("Encrypted Financial Planning Tool - Client-Side Network Logic (User Input)");

    // --- Network Setup (Client) ---
    int sock = 0;
    struct sockaddr_in serv_addr;
    const int PORT = 8080; // Must match server's port
    const char* SERVER_IP = "127.0.0.1"; // Server IP: localhost for now (same machine)

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        cerr << "Socket creation error" << endl;
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        cerr << "Invalid address/ Address not supported" << endl;
        return -1;
    }

    cout << "Attempting to connect to server at " << SERVER_IP << ":" << PORT << "..." << endl;
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        cerr << "Connection Failed. Ensure server_app is running first.\n";
        return -1;
    }
    cout << "Connected to server!" << endl;

    // --- FHE Setup (Client) ---
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 30));

    SEALContext context(parms);
    cout << "\nSEALContext created on client with parameters:" << endl;
    cout << "  Scheme: BFV" << endl;
    cout << "  Poly Modulus Degree: " << parms.poly_modulus_degree() << endl;
    cout << "  Coeff Modulus Size: " << context.first_context_data()->total_coeff_modulus_bit_count() << " bits" << endl;
    cout << "  Plain Modulus: " << parms.plain_modulus().value() << endl;
    cout << "  Parameters are " << (context.parameters_set() ? "valid" : "invalid") << endl;

    // 2. Key Generation (Client-side)
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    cout << "\nKeys generated on client (public, secret, relinearization)." << endl;

    // --- Send Keys and Parameters to Server ---
    stringstream parms_ss;
    parms.save(parms_ss);
    if (!send_data(sock, parms_ss.str())) return 1;
    cout << "Encryption parameters sent to server." << endl;

    stringstream pk_ss;
    public_key.save(pk_ss);
    if (!send_data(sock, pk_ss.str())) return 1;
    cout << "Public key sent to server." << endl;

    stringstream rlk_ss;
    relin_keys.save(rlk_ss);
    if (!send_data(sock, rlk_ss.str())) return 1;
    cout << "Relinearization keys sent to server." << endl;

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    size_t slot_count = batch_encoder.slot_count();
    cout << "Number of slots for batching: " << slot_count << endl;

    const double SCALE_FACTOR = 100.0;
    cout << "Using fixed-point scaling factor: " << SCALE_FACTOR << endl;

    // 3. Prepare and Encrypt Financial Data (Client-side - User Input)
    vector<double> income_double_data;
    vector<double> expense_double_data;
    double value;
    string input_line;

    cout << "\n--- Enter your financial data ---" << endl;
    cout << "Enter income sources (e.g., 1500.75, 250.00, 75.20). Type 'done' when finished:" << endl;
    while (true) {
        cout << "Income amount (or 'done'): ";
        cin >> input_line;
        if (input_line == "done") break;
        try {
            value = stod(input_line);
            income_double_data.push_back(value);
        } catch (const std::invalid_argument& e) {
            cerr << "Invalid input. Please enter a number or 'done'." << endl;
        }
    }
    // Clear the newline character left by cin
    cin.ignore(numeric_limits<streamsize>::max(), '\n');

    cout << "\nEnter expense categories (e.g., 450.50, 120.00, 30.80). Type 'done' when finished:" << endl;
    while (true) {
        cout << "Expense amount (or 'done'): ";
        cin >> input_line;
        if (input_line == "done") break;
        try {
            value = stod(input_line);
            expense_double_data.push_back(value);
        } catch (const std::invalid_argument& e) {
            cerr << "Invalid input. Please enter a number or 'done'." << endl;
        }
    }
    // Clear the newline character left by cin
    cin.ignore(numeric_limits<streamsize>::max(), '\n');

    // Ensure vectors are not empty to avoid issues with scaling/encoding
    if (income_double_data.empty()) income_double_data.push_back(0.0);
    if (expense_double_data.empty()) expense_double_data.push_back(0.0);


    // Pad data to fill slots if necessary, or just use the actual size
    // For simplicity, we'll use the minimum size required to encode the data.
    // Ensure the data vectors are at least as large as the maximum count of actual inputs
    size_t max_data_size = max(income_double_data.size(), expense_double_data.size());
    // Ensure max_data_size doesn't exceed slot_count
    if (max_data_size > slot_count) {
        cerr << "Warning: Too many inputs for available slots. Truncating data." << endl;
        income_double_data.resize(slot_count);
        expense_double_data.resize(slot_count);
        max_data_size = slot_count; // Update max_data_size to actual processed size
    }


    vector<int64_t> income_scaled_data(slot_count, 0LL); // Initialize with zeros
    for (size_t i = 0; i < income_double_data.size(); ++i) {
        income_scaled_data[i] = static_cast<int64_t>(round(income_double_data[i] * SCALE_FACTOR));
    }

    vector<int64_t> expense_scaled_data(slot_count, 0LL); // Initialize with zeros
    for (size_t i = 0; i < expense_double_data.size(); ++i) {
        expense_scaled_data[i] = static_cast<int64_t>(round(expense_double_data[i] * SCALE_FACTOR));
    }

    print_vector(income_double_data, "Original Income Data (double)");
    print_vector(expense_double_data, "Original Expense Data (double)");

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

    // --- Send Encrypted Data to Server ---
    stringstream enc_income_ss;
    encrypted_income.save(enc_income_ss);
    if (!send_data(sock, enc_income_ss.str())) return 1;
    cout << "Encrypted income sent to server." << endl;

    stringstream enc_expense_ss;
    encrypted_expense.save(enc_expense_ss);
    if (!send_data(sock, enc_expense_ss.str())) return 1;
    cout << "Encrypted expense sent to server." << endl;

    cout << "\nClient-side encryption and data transfer complete. Waiting for results..." << endl;

    // --- Receive Encrypted Results from Server ---
    Ciphertext encrypted_net_income_from_server;
    string enc_net_income_str = receive_data(sock);
    if (enc_net_income_str.empty()) return 1;
    stringstream enc_net_income_ss(enc_net_income_str);
    encrypted_net_income_from_server.load(context, enc_net_income_ss);
    cout << "Encrypted net income received from server." << endl;

    Ciphertext encrypted_savings_contribution_from_server;
    string enc_savings_contribution_str = receive_data(sock);
    if (enc_savings_contribution_str.empty()) return 1;
    stringstream enc_savings_contribution_ss(enc_savings_contribution_str);
    encrypted_savings_contribution_from_server.load(context, enc_savings_contribution_ss);
    cout << "Encrypted savings contribution received from server." << endl;

    // 5. Decrypt and Decode Results (Client-side)
    Plaintext decrypted_net_income;
    decryptor.decrypt(encrypted_net_income_from_server, decrypted_net_income);
    cout << "Encrypted net income decrypted." << endl;

    Plaintext decrypted_savings_contribution;
    decryptor.decrypt(encrypted_savings_contribution_from_server, decrypted_savings_contribution);
    cout << "Encrypted savings contribution decrypted." << endl;

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
        decoded_savings_contribution_double[i] = static_cast<double>(decoded_savings_contribution_scaled[i]) / (SCALE_FACTOR * SCALE_FACTOR);
    }
    print_vector(decoded_savings_contribution_double, "Decoded Savings Contribution Data (double)");

    // 6. Verification (Client-side)
    // For verification, we can sum up the original input data.
    double total_income_original = 0.0;
    for(double val : income_double_data) total_income_original += val;
    double total_expense_original = 0.0;
    for(double val : expense_double_data) total_expense_original += val;

    cout << "\n--- Verification of Totals ---" << endl;
    cout << "Total Income (original): " << total_income_original << endl;
    cout << "Total Expense (original): " << total_expense_original << endl;

    // Note: The FHE operations are on the first slot of the batched data.
    // If you want to verify totals, you'd need to sum the encrypted vectors homomorphically.
    // For this simple example, we'll verify the first slot as before.
    cout << "\nVerification (first slot of input data):" << endl;
    if (!income_double_data.empty() && !expense_double_data.empty()) {
        double expected_net_income = income_double_data[0] - expense_double_data[0];
        cout << "Expected Net Income (first slot): " << expected_net_income << endl;
        cout << "Actual Decoded Net Income (first slot): " << decoded_net_income_double[0] << endl;

        double savings_rate_double = 0.15;
        double expected_savings_contribution = income_double_data[0] * savings_rate_double;
        cout << "Expected Savings Contribution (first slot): " << expected_savings_contribution << endl;
        cout << "Actual Decoded Savings Contribution (first slot): " << decoded_savings_contribution_double[0] << endl;
    } else {
        cout << "Not enough input data for first slot verification." << endl;
    }

    cout << "\nClient-side decryption and verification complete. Full FHE cycle demonstrated!" << endl;

    // Close socket
    close(sock);

    return 0;
}
