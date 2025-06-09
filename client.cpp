#include "seal/seal.h" //For Microsoft SEAL library
#include <iostream>
#include <vector> 
#include <numeric> // For std::accumulate
#include <cmath>
#include <sstream> //To save and load SEAL objects
#include <limits> // For numeric_limits
#include <map>    // For storing category sums
#include <algorithm> // For std::sort

// Headers for socket programming
#include <sys/socket.h> //core socket functions
#include <netinet/in.h> //internet address
#include <arpa/inet.h> //manipulating IP addresses
#include <unistd.h> //closes socket

using namespace std;
using namespace seal;

// --- Networking Helper Functions ---
// Function to send data over a socket with a size prefix
bool send_data(int sock, const string& data) {
    size_t data_size = data.size();
    if (send(sock, &data_size, sizeof(data_size), 0) == -1) {
        return false;
    }
    if (send(sock, data.c_str(), data_size, 0) == -1) {
        return false;
    }
    return true;
}

// Function to receive data over a socket with a size prefix
string receive_data(int sock) {
    size_t data_size;
    if (recv(sock, &data_size, sizeof(data_size), MSG_WAITALL) == -1) {
        return "";
    }

    vector<char> buffer(data_size);
    if (recv(sock, buffer.data(), data_size, MSG_WAITALL) == -1) {
        return "";
    }
    return string(buffer.begin(), buffer.end());
}

// Helper function to get multiple double inputs from user
vector<double> get_user_doubles(const string& prompt_name) {
    vector<double> data;
    double value;
    string input_line;
    cout << "Enter " << prompt_name << " amounts (e.g., 1500.75, 250.00). Type 'done' when finished:" << endl;
    while (true) {
        cout << prompt_name << " amount (or 'done'): ";
        cin >> input_line;
        if (input_line == "done") {
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            break;
        }
        try {
            value = stod(input_line);
            data.push_back(value);
        } catch (const std::invalid_argument& e) {
            cerr << "Invalid input. Please enter a number or 'done'." << endl;
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
        }
    }
    return data;
}

// Helper function to get a single double input from user
double get_single_double_input(const string& prompt_name) {
    double value;
    string input_line;
    cout << prompt_name << ": ";
    while (!(cin >> value)) {
        cerr << "Invalid input. Please enter a number: ";
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        cout << prompt_name << ": ";
    }
    cin.ignore(numeric_limits<streamsize>::max(), '\n'); // Clear newline
    return value;
}

int main() {
    // --- Network Setup (Client) ---
    int sock = 0;
    struct sockaddr_in serv_addr;
    const int PORT = 8080; // Must match server's port
    const char* SERVER_IP = "127.0.0.1"; // Server IP: localhost for now

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

    // 2. Key Generation (Client-side)
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    // --- Send Keys and Parameters to Server ---
    stringstream parms_ss;
    parms.save(parms_ss);
    if (!send_data(sock, parms_ss.str())) return 1;

    stringstream pk_ss;
    public_key.save(pk_ss);
    if (!send_data(sock, pk_ss.str())) return 1;

    stringstream rlk_ss;
    relin_keys.save(rlk_ss);
    if (!send_data(sock, rlk_ss.str())) return 1;

    stringstream glk_ss;
    galois_keys.save(glk_ss);
    if (!send_data(sock, glk_ss.str())) return 1;

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    size_t slot_count = batch_encoder.slot_count();

    const double SCALE_FACTOR = 100.0;

    // --- 3. Prepare and Encrypt Financial Data (Client-side - User Input) ---
    cout << "\n--- Enter your financial data (Monthly) ---" << endl;

    // --- Income Input ---
    vector<double> income_sources_raw;
    double income_value;
    string input_line;
    cout << "Enter monthly income (e.g., 1500.75, 250.00). Type 'done' when finished:" << endl;
    while (true) {
        cout << "Income (or 'done'): ";
        cin >> input_line;
        if (input_line == "done") {
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            break;
        }
        try {
            income_value = stod(input_line);
            income_sources_raw.push_back(income_value);
        } catch (const std::invalid_argument& e) {
            cerr << "Invalid input. Please enter a number or 'done'." << endl;
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
        }
    }

    double total_income_plaintext_sum = std::accumulate(income_sources_raw.begin(), income_sources_raw.end(), 0.0);
    cout << "Total Monthly Income (calculated locally): " << total_income_plaintext_sum << endl;

    if (income_sources_raw.empty()) {
        total_income_plaintext_sum = 0.0;
    }

    // Scale and encode total income (filling all slots)
    int64_t total_income_scaled = static_cast<int64_t>(round(total_income_plaintext_sum * SCALE_FACTOR));
    Plaintext encoded_total_income;
    batch_encoder.encode(vector<int64_t>(slot_count, total_income_scaled), encoded_total_income);
    
    // Encrypt total income
    Ciphertext encrypted_total_income;
    encryptor.encrypt(encoded_total_income, encrypted_total_income);

    // --- Categorized Expense Input (Direct Totals) ---
    cout << "\n--- Enter your monthly expenses ---" << endl;
    
    // Get total Essential Expenses directly
    double essential_expenses_sum_plaintext = get_single_double_input("Total ESSENTIAL Expenses (e.g., Housing, Food, Utilities, Transportation)");
    cout << "Total ESSENTIAL Expenses: " << essential_expenses_sum_plaintext << endl;

    // Get total Non-Essential Expenses directly
    double non_essential_expenses_sum_plaintext = get_single_double_input("Total NON-ESSENTIAL Expenses (e.g., Dining Out, Entertainment, Shopping)");
    cout << "Total NON-ESSENTIAL Expenses: " << non_essential_expenses_sum_plaintext << endl;
    
    // Store plaintext sums for client-side verification
    map<string, double> client_local_category_sums;
    client_local_category_sums["Essentials"] = essential_expenses_sum_plaintext;
    client_local_category_sums["Non-Essentials"] = non_essential_expenses_sum_plaintext;

    // Scale and encode essential expenses total
    int64_t essential_expenses_scaled = static_cast<int64_t>(round(essential_expenses_sum_plaintext * SCALE_FACTOR));
    Plaintext encoded_essential_expenses;
    batch_encoder.encode(vector<int64_t>(slot_count, essential_expenses_scaled), encoded_essential_expenses);

    // Encrypt essential expenses total
    Ciphertext encrypted_essential_expenses;
    encryptor.encrypt(encoded_essential_expenses, encrypted_essential_expenses);

    // Scale and encode non-essential expenses total
    int64_t non_essential_expenses_scaled = static_cast<int64_t>(round(non_essential_expenses_sum_plaintext * SCALE_FACTOR));
    Plaintext encoded_non_essential_expenses;
    batch_encoder.encode(vector<int64_t>(slot_count, non_essential_expenses_scaled), encoded_non_essential_expenses);

    // Encrypt non-essential expenses total
    Ciphertext encrypted_non_essential_expenses;
    encryptor.encrypt(encoded_non_essential_expenses, encrypted_non_essential_expenses);

    // --- Monthly Savings Goal Input ---
    double monthly_savings_goal_double;
    cout << "\n--- Enter your monthly savings goal ---" << endl;
    monthly_savings_goal_double = get_single_double_input("Enter your target monthly savings (e.g., 500.00)");
    cout << "Monthly Savings Goal: " << monthly_savings_goal_double << endl;

    // Scale and encode monthly savings goal
    int64_t monthly_savings_goal_scaled = static_cast<int64_t>(round(monthly_savings_goal_double * SCALE_FACTOR));
    Plaintext encoded_monthly_savings_goal;
    batch_encoder.encode(vector<int64_t>(slot_count, monthly_savings_goal_scaled), encoded_monthly_savings_goal);

    // --- Send Encrypted Data to Server ---
    // Send encrypted total income
    stringstream enc_total_income_ss;
    encrypted_total_income.save(enc_total_income_ss);
    if (!send_data(sock, enc_total_income_ss.str())) return 1;

    // Send encoded monthly savings goal
    stringstream enc_monthly_savings_goal_ss;
    encoded_monthly_savings_goal.save(enc_monthly_savings_goal_ss);
    if (!send_data(sock, enc_monthly_savings_goal_ss.str())) return 1;
    
    // Send encrypted essential expenses sum
    stringstream enc_essential_ss;
    encrypted_essential_expenses.save(enc_essential_ss);
    if (!send_data(sock, enc_essential_ss.str())) return 1;

    // Send encrypted non-essential expenses sum
    stringstream enc_non_essential_ss;
    encrypted_non_essential_expenses.save(enc_non_essential_ss);
    if (!send_data(sock, enc_non_essential_ss.str())) return 1;

    cout << "\nClient-side data transfer complete. Waiting for results..." << endl;

    // --- Receive Encrypted Results from Server ---
    Ciphertext encrypted_total_expenses_from_server;
    string enc_total_expenses_str = receive_data(sock);
    if (enc_total_expenses_str.empty()) return 1;
    stringstream enc_total_expenses_ss(enc_total_expenses_str);
    encrypted_total_expenses_from_server.load(context, enc_total_expenses_ss);

    Ciphertext encrypted_net_income_from_server;
    string enc_net_income_str = receive_data(sock);
    if (enc_net_income_str.empty()) return 1;
    stringstream enc_net_income_ss(enc_net_income_str);
    encrypted_net_income_from_server.load(context, enc_net_income_ss);

    Ciphertext encrypted_goal_difference_from_server;
    string enc_goal_difference_str = receive_data(sock);
    if (enc_goal_difference_str.empty()) return 1;
    stringstream enc_goal_difference_ss(enc_goal_difference_str);
    encrypted_goal_difference_from_server.load(context, enc_goal_difference_ss);

    // Receive and decrypt individual encrypted category sums (sent back by server)
    Ciphertext encrypted_essential_expenses_from_server_recd;
    string enc_essential_recd_str = receive_data(sock);
    if (enc_essential_recd_str.empty()) return 1;
    stringstream enc_essential_recd_ss(enc_essential_recd_str);
    encrypted_essential_expenses_from_server_recd.load(context, enc_essential_recd_ss);

    Ciphertext encrypted_non_essential_expenses_from_server_recd;
    string enc_non_essential_recd_str = receive_data(sock);
    if (enc_non_essential_recd_str.empty()) return 1;
    stringstream enc_non_essential_recd_ss(enc_non_essential_recd_str);
    encrypted_non_essential_expenses_from_server_recd.load(context, enc_non_essential_recd_ss);

    // --- 5. Decrypt and Decode Results (Client-side) ---
    Plaintext decrypted_total_expenses;
    decryptor.decrypt(encrypted_total_expenses_from_server, decrypted_total_expenses);
    vector<int64_t> decoded_total_expenses_scaled;
    batch_encoder.decode(decrypted_total_expenses, decoded_total_expenses_scaled);
    double decoded_total_expenses_double = static_cast<double>(decoded_total_expenses_scaled[0]) / SCALE_FACTOR;
    cout << "\nDecrypted Total Expenses: " << decoded_total_expenses_double << endl;

    Plaintext decrypted_net_income;
    decryptor.decrypt(encrypted_net_income_from_server, decrypted_net_income);
    vector<int64_t> decoded_net_income_scaled;
    batch_encoder.decode(decrypted_net_income, decoded_net_income_scaled);
    double decoded_net_income_double = static_cast<double>(decoded_net_income_scaled[0]) / SCALE_FACTOR;
    cout << "Decrypted Net Income: " << decoded_net_income_double << endl;

    Plaintext decrypted_goal_difference;
    decryptor.decrypt(encrypted_goal_difference_from_server, decrypted_goal_difference);
    vector<int64_t> decoded_goal_difference_scaled;
    batch_encoder.decode(decrypted_goal_difference, decoded_goal_difference_scaled);
    double decoded_goal_difference_double = static_cast<double>(decoded_goal_difference_scaled[0]) / SCALE_FACTOR;
    cout << "Decrypted Difference from Monthly Savings Goal: " << decoded_goal_difference_double << endl;

    // Decrypt and decode individual category sums for display
    Plaintext decrypted_essential_expenses;
    decryptor.decrypt(encrypted_essential_expenses_from_server_recd, decrypted_essential_expenses);
    vector<int64_t> decoded_essential_expenses_scaled;
    batch_encoder.decode(decrypted_essential_expenses, decoded_essential_expenses_scaled);
    double decoded_essential_expenses_double = static_cast<double>(decoded_essential_expenses_scaled[0]) / SCALE_FACTOR;

    Plaintext decrypted_non_essential_expenses;
    decryptor.decrypt(encrypted_non_essential_expenses_from_server_recd, decrypted_non_essential_expenses);
    vector<int64_t> decoded_non_essential_expenses_scaled;
    batch_encoder.decode(decrypted_non_essential_expenses, decoded_non_essential_expenses_scaled);
    double decoded_non_essential_expenses_double = static_cast<double>(decoded_non_essential_expenses_scaled[0]) / SCALE_FACTOR;

    cout << "\n--- Decrypted Expense Breakdown ---" << endl;
    cout << "Total ESSENTIAL Expenses: " << decoded_essential_expenses_double << endl;
    cout << "Total NON-ESSENTIAL Expenses: " << decoded_non_essential_expenses_double << endl;


    // --- 6. Verification and Adjustments (Client-side) ---

    cout << "\n--- Financial Recommendations ---" << endl;
    if (decoded_goal_difference_double >= 0) {
        cout << "Congratulations! You are on track to meet or exceed your monthly savings goal of " << monthly_savings_goal_double << "!" << endl;
        if (decoded_goal_difference_double > 0) {
            cout << "You have an additional " << decoded_goal_difference_double << " beyond your goal that you could save or allocate." << endl;
        }
    } else {
        cout << "To reach your monthly savings goal of " << monthly_savings_goal_double << ", you need to save an additional " << abs(decoded_goal_difference_double) << "." << endl;
        if (decoded_non_essential_expenses_double > 0) {
            cout << "Consider adjusting spending in NON-ESSENTIALS (current total: " << decoded_non_essential_expenses_double << ")." << endl;
            cout << "Review categories like Dining Out, Entertainment, Shopping, etc., to find areas for reduction." << endl;
        } else {
            cout << "Even with zero non-essential spending, you are still below your goal. Consider increasing income or reviewing essential expenses carefully." << endl;
        }
        cout << "Revisit your budget and see where you can make changes to achieve your goal." << endl;
    }

    // Close socket
    close(sock);

    return 0;
}
