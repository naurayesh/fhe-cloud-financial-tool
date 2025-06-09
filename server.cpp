#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <numeric>
#include <cmath>
#include <sstream> // For stringstream for network serialization

// Headers for socket programming
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h> // For close()

using namespace std;
using namespace seal;

// --- Networking Helper Functions ---
// Function to send data over a socket with a size prefix
bool send_data(int sock, const string& data) {
    size_t data_size = data.size();
    // Send the size of the data first
    if (send(sock, &data_size, sizeof(data_size), 0) == -1) {
        cerr << "Error sending data size." << endl;
        return false;
    }
    // Send the actual data
    if (send(sock, data.c_str(), data_size, 0) == -1) {
        cerr << "Error sending data." << endl;
        return false;
    }
    return true;
}

// Function to receive data over a socket with a size prefix
string receive_data(int sock) {
    size_t data_size;
    // Receive the size of the data first
    if (recv(sock, &data_size, sizeof(data_size), MSG_WAITALL) == -1) {
        cerr << "Error receiving data size." << endl;
        return "";
    }

    // Allocate buffer for the actual data
    vector<char> buffer(data_size);
    // Receive the actual data
    if (recv(sock, buffer.data(), data_size, MSG_WAITALL) == -1) {
        cerr << "Error receiving data." << endl;
        return "";
    }
    return string(buffer.begin(), buffer.end());
}


int main() {
    // --- Network Setup (Server) ---
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    const int PORT = 8080; // Choose an available port

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; // Listen on all available interfaces
    address.sin_port = htons(PORT);

    // Bind the socket to the specified IP and port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 3) < 0) { // 3 is the backlog queue size
        perror("listen");
        exit(EXIT_FAILURE);
    }
    cout << "Server listening on port " << PORT << endl;
    cout << "Waiting for client connection..." << endl;

    // Accept a client connection
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    cout << "Client connected!" << endl << endl;

    // --- FHE Setup (Server) ---
    // 1. Receive and Load Encryption Parameters
    string parms_str = receive_data(new_socket);
    if (parms_str.empty()) { cerr << "Error: Failed to receive parameters." << endl; return 1; }
    stringstream parms_ss(parms_str);
    EncryptionParameters parms;
    parms.load(parms_ss);
    cout << "Encryption parameters loaded from network." << endl;
    cout << endl;

    SEALContext context(parms);
    cout << "SEALContext created on server with parameters:" << endl;
    cout << "  Scheme: BFV" << endl;
    cout << "  Poly Modulus Degree: " << parms.poly_modulus_degree() << endl;
    cout << "  Coeff Modulus Size: " << context.first_context_data()->total_coeff_modulus_bit_count() << " bits" << endl;
    cout << "  Plain Modulus: " << parms.plain_modulus().value() << endl;
    cout << "  Parameters are " << (context.parameters_set() ? "valid" : "invalid") << endl;
    cout << endl;

    // 2. Receive and Load Public, Relinearization, and Galois Keys
    PublicKey public_key;
    string pk_str = receive_data(new_socket);
    if (pk_str.empty()) { cerr << "Error: Failed to receive public key." << endl; return 1; }
    stringstream pk_ss(pk_str);
    public_key.load(context, pk_ss);
    cout << "Public key loaded from network." << endl;

    RelinKeys relin_keys;
    string rlk_str = receive_data(new_socket);
    if (rlk_str.empty()) { cerr << "Error: Failed to receive relinearization keys." << endl; return 1; }
    stringstream rlk_ss(rlk_str);
    relin_keys.load(context, rlk_ss);
    cout << "Relinearization keys loaded from network." << endl;

    GaloisKeys galois_keys;
    string glk_str = receive_data(new_socket);
    if (glk_str.empty()) { cerr << "Error: Failed to receive Galois keys." << endl; return 1; }
    stringstream glk_ss(glk_str);
    galois_keys.load(context, glk_ss);
    cout << "Galois keys loaded from network." << endl;

    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    Encryptor encryptor(context, public_key); 

    size_t slot_count = batch_encoder.slot_count();
    cout << "Number of slots for batching: " << slot_count << endl;

    const double SCALE_FACTOR = 100.0;
    cout << "Using fixed-point scaling factor: " << SCALE_FACTOR << endl;
    cout << endl;

    // --- 3. Receive Encrypted Data from Client ---
    Ciphertext encrypted_total_income;
    string enc_total_income_str = receive_data(new_socket);
    if (enc_total_income_str.empty()) { cerr << "Error: Failed to receive encrypted total income." << endl; return 1; }
    stringstream enc_total_income_ss(enc_total_income_str);
    encrypted_total_income.load(context, enc_total_income_ss);
    cout << "Encrypted Total Income loaded from network." << endl;
    cout << endl;

    Plaintext encoded_monthly_savings_goal;
    string enc_monthly_savings_goal_str = receive_data(new_socket);
    if (enc_monthly_savings_goal_str.empty()) { cerr << "Error: Failed to receive encoded monthly savings goal." << endl; return 1; }
    stringstream enc_monthly_savings_goal_ss(enc_monthly_savings_goal_str);
    encoded_monthly_savings_goal.load(context, enc_monthly_savings_goal_ss);
    cout << "Encoded Monthly Savings Goal loaded from network." << endl;
    cout << endl;

    // Receive encrypted essential expenses sum
    Ciphertext encrypted_essential_expenses_received;
    string enc_essential_str = receive_data(new_socket);
    if (enc_essential_str.empty()) { cerr << "Error: Failed to receive encrypted essential expenses." << endl; return 1; }
    stringstream enc_essential_ss(enc_essential_str);
    encrypted_essential_expenses_received.load(context, enc_essential_ss);
    cout << "Encrypted Total ESSENTIAL Expenses loaded from network." << endl;

    // Receive encrypted non-essential expenses sum
    Ciphertext encrypted_non_essential_expenses_received;
    string enc_non_essential_str = receive_data(new_socket);
    if (enc_non_essential_str.empty()) { cerr << "Error: Failed to receive encrypted non-essential expenses." << endl; return 1; }
    stringstream enc_non_essential_ss(enc_non_essential_str);
    encrypted_non_essential_expenses_received.load(context, enc_non_essential_ss);
    cout << "Encrypted Total NON-ESSENTIAL Expenses loaded from network." << endl;
    cout << endl;

    // --- 4. Perform Homomorphic Operations (Server-side) ---
    // Homomorphic Sum of all Encrypted Category Expenses (Essentials + Non-Essentials)
    Ciphertext encrypted_total_expenses;
    evaluator.add(encrypted_essential_expenses_received, encrypted_non_essential_expenses_received, encrypted_total_expenses);
    cout << "\nHomomorphic summation performed: Encrypted Total Expenses (Essentials + Non-Essentials) calculated." << endl;

    // Homomorphic Net Income Calculation: Total Income - Total Expenses
    Ciphertext encrypted_net_income;
    evaluator.sub(encrypted_total_income, encrypted_total_expenses, encrypted_net_income);
    cout << "Homomorphic subtraction performed: Encrypted Total Income - Encrypted Total Expenses." << endl;

    // Homomorphic Difference from Monthly Savings Goal: Net Income - Savings Goal
    Ciphertext encrypted_goal_difference;
    evaluator.sub_plain(encrypted_net_income, encoded_monthly_savings_goal, encrypted_goal_difference);
    cout << "Homomorphic subtraction performed: Encrypted Net Income - Encoded Monthly Savings Goal." << endl;
    cout << endl;

    // --- 5. Send Encrypted Results back to Client ---
    // Send calculated encrypted totals
    stringstream enc_total_expenses_ss;
    encrypted_total_expenses.save(enc_total_expenses_ss);
    if (!send_data(new_socket, enc_total_expenses_ss.str())) { cerr << "Error: Failed to send encrypted total expenses." << endl; return 1; }
    cout << "Encrypted Total Expenses sent to client." << endl;

    stringstream enc_net_income_ss;
    encrypted_net_income.save(enc_net_income_ss);
    if (!send_data(new_socket, enc_net_income_ss.str())) { cerr << "Error: Failed to send encrypted net income." << endl; return 1; }
    cout << "Encrypted Net Income sent to client." << endl;

    stringstream enc_goal_difference_ss;
    encrypted_goal_difference.save(enc_goal_difference_ss);
    if (!send_data(new_socket, enc_goal_difference_ss.str())) { cerr << "Error: Failed to send encrypted goal difference." << endl; return 1; }
    cout << "Encrypted Difference from Savings Goal sent to client." << endl;
    cout << endl;

    // Send back the individual encrypted category sums (for client to decrypt and show breakdown)
    stringstream enc_essential_recd_ss;
    encrypted_essential_expenses_received.save(enc_essential_recd_ss);
    if (!send_data(new_socket, enc_essential_recd_ss.str())) { cerr << "Error: Failed to send encrypted essential expenses back." << endl; return 1; }
    cout << "Encrypted ESSENTIAL Expenses sum sent back to client." << endl;

    stringstream enc_non_essential_recd_ss;
    encrypted_non_essential_expenses_received.save(enc_non_essential_recd_ss);
    if (!send_data(new_socket, enc_non_essential_recd_ss.str())) { cerr << "Error: Failed to send encrypted non-essential expenses back." << endl; return 1; }
    cout << "Encrypted NON-ESSENTIAL Expenses sum sent back to client." << endl;

    cout << "\nServer-side operations complete. Encrypted results sent to client." << endl;

    // Close sockets
    close(new_socket);
    close(server_fd);

    return 0;
}
