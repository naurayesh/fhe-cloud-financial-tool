#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <numeric>
#include <cmath>
#include <fstream>
#include <sstream> // For stringstream for network serialization

// Headers for socket programming
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h> // For close()

using namespace std;
using namespace seal;

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

int main() {
    print_example_banner("Encrypted Financial Planning Tool - Server-Side Network Logic");

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

    // Forcefully attaching socket to the port 8080
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
    cout << "Client connected!" << endl;

    // --- FHE Setup (Server) ---
    // 1. Receive and Load Encryption Parameters
    string parms_str = receive_data(new_socket);
    if (parms_str.empty()) return 1;
    stringstream parms_ss(parms_str);
    EncryptionParameters parms;
    parms.load(parms_ss);
    cout << "Encryption parameters loaded from network." << endl;

    SEALContext context(parms);
    cout << "SEALContext created on server with parameters:" << endl;
    cout << "  Scheme: BFV" << endl;
    cout << "  Poly Modulus Degree: " << parms.poly_modulus_degree() << endl;
    cout << "  Coeff Modulus Size: " << context.first_context_data()->total_coeff_modulus_bit_count() << " bits" << endl;
    cout << "  Plain Modulus: " << parms.plain_modulus().value() << endl;
    cout << "  Parameters are " << (context.parameters_set() ? "valid" : "invalid") << endl;

    // 2. Receive and Load Public and Relinearization Keys
    PublicKey public_key;
    string pk_str = receive_data(new_socket);
    if (pk_str.empty()) return 1;
    stringstream pk_ss(pk_str);
    public_key.load(context, pk_ss);
    cout << "Public key loaded from network." << endl;

    RelinKeys relin_keys;
    string rlk_str = receive_data(new_socket);
    if (rlk_str.empty()) return 1;
    stringstream rlk_ss(rlk_str);
    relin_keys.load(context, rlk_ss);
    cout << "Relinearization keys loaded from network." << endl;

    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);

    size_t slot_count = batch_encoder.slot_count();
    cout << "Number of slots for batching: " << slot_count << endl;

    const double SCALE_FACTOR = 100.0;
    cout << "Using fixed-point scaling factor: " << SCALE_FACTOR << endl;

    // 3. Receive and Load Encrypted Data
    Ciphertext encrypted_income;
    string enc_income_str = receive_data(new_socket);
    if (enc_income_str.empty()) return 1;
    stringstream enc_income_ss(enc_income_str);
    encrypted_income.load(context, enc_income_ss);
    cout << "Encrypted income loaded from network." << endl;

    Ciphertext encrypted_expense;
    string enc_expense_str = receive_data(new_socket);
    if (enc_expense_str.empty()) return 1;
    stringstream enc_expense_ss(enc_expense_str);
    encrypted_expense.load(context, enc_expense_ss);
    cout << "Encrypted expense loaded from network." << endl;

    // 4. Perform Homomorphic Operations (Server-side)
    Ciphertext encrypted_net_income;
    evaluator.sub(encrypted_income, encrypted_expense, encrypted_net_income);
    cout << "\nHomomorphic subtraction performed: Encrypted Income - Encrypted Expense." << endl;

    double savings_rate_double = 0.15;
    int64_t savings_rate_scaled = static_cast<int64_t>(round(savings_rate_double * SCALE_FACTOR));
    vector<int64_t> savings_rate_vector(slot_count, savings_rate_scaled);
    Plaintext encoded_savings_rate;
    batch_encoder.encode(savings_rate_vector, encoded_savings_rate);
    cout << "Savings rate (" << savings_rate_double * 100 << "%) encoded to plaintext (on server)." << endl;

    Ciphertext encrypted_savings_contribution;
    evaluator.multiply_plain(encrypted_income, encoded_savings_rate, encrypted_savings_contribution);
    cout << "Homomorphic multiplication (ciphertext-plaintext) performed: Encrypted Income * Encoded Savings Rate." << endl;
    evaluator.relinearize(encrypted_savings_contribution, relin_keys, encrypted_savings_contribution);
    cout << "Relinearization performed on encrypted savings contribution." << endl;

    // 5. Send Encrypted Results back to Client
    stringstream enc_net_income_ss;
    encrypted_net_income.save(enc_net_income_ss);
    if (!send_data(new_socket, enc_net_income_ss.str())) return 1;
    cout << "Encrypted net income sent to client." << endl;

    stringstream enc_savings_contribution_ss;
    encrypted_savings_contribution.save(enc_savings_contribution_ss);
    if (!send_data(new_socket, enc_savings_contribution_ss.str())) return 1;
    cout << "Encrypted savings contribution sent to client." << endl;

    cout << "\nServer-side operations complete. Encrypted results sent to client." << endl;

    // Close sockets
    close(new_socket);
    close(server_fd);

    return 0;
}
