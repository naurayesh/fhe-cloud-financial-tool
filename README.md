Project: Encrypted Financial Planning Tool (FHE Private Cloud Application)
Group Members:


Project Theme:
A private cloud application utilizing Fully Homomorphic Encryption (FHE).

Core Idea:
This application demonstrates a privacy-preserving financial planning tool. Users input their financial data (income, expenses) on their local machine (client), which is then encrypted. This encrypted data is sent over a network to a private cloud server. The server performs budgeting and planning calculations (e.g., net income, savings contribution) directly on the encrypted data, ensuring that the sensitive financial information remains confidential. The encrypted results are then sent back to the user's machine for decryption and display.

Key Technologies Used:
Fully Homomorphic Encryption (FHE): Specifically, the BFV (Brakerski/Fan-Vercauteren) scheme is employed for its exact integer arithmetic, which is crucial for precise financial calculations.

Microsoft SEAL Library: A powerful, open-source C++ library that provides the cryptographic primitives for FHE.

C++: Used for implementing both the client-side and server-side application logic.

TCP Sockets: Facilitate secure and reliable network communication between the client (user's machine) and the private cloud server.

Fixed-Point Encoding: A technique implemented to represent and compute with decimal values (e.g., cents) and larger numerical ranges within the integer-based BFV scheme.

Batching: Leverages SEAL's efficient batching capabilities to perform operations on multiple financial data points simultaneously, optimizing performance.

How to Run the Application:
Prerequisites:
Linux Environment (e.g., Windows Subsystem for Linux - WSL): The application is developed and tested in a Linux environment.

Microsoft SEAL Library (Version 4.1 or compatible): Ensure SEAL is properly built and installed on your system. The compilation commands below assume SEAL's headers are accessible via specific include paths and its library via a specific library path. Adjust these paths if your SEAL installation differs from the /root/SEAL structure.

Project Files:
client.cpp: Contains the client-side logic, including FHE key generation, data encryption, network transmission of encrypted data, reception of encrypted results, and final decryption and verification. It also handles user input for financial data.

server.cpp: Contains the server-side logic (representing the "private cloud"), responsible for receiving FHE parameters, keys, and encrypted data, performing homomorphic computations, and sending back encrypted results.

Steps to Compile and Run:
Navigate to the Project Directory:
Open your Linux terminal (e.g., WSL) and navigate to the directory containing client.cpp and server.cpp.

cd ~/SEAL/native/examples/

Compile the Server Application:

g++ -std=c++17 server.cpp -o server_app -I/root/SEAL/build/native/src -I/root/SEAL/native/src -I/root/SEAL/build/thirdparty/msgsl-src/include -L/root/SEAL/build/lib -lseal-4.1

This command compiles server.cpp into an executable named server_app.

Compile the Client Application:

g++ -std=c++17 client.cpp -o client_app -I/root/SEAL/build/native/src -I/root/SEAL/native/src -I/root/SEAL/build/thirdparty/msgsl-src/include -L/root/SEAL/build/lib -lseal-4.1

This command compiles client.cpp into an executable named client_app.

Run the Applications (Crucial Order):
You will need two separate terminal windows/tabs for this demonstration.

Terminal 1 (Server):

cd ~/SEAL/native/examples/
./server_app

The server will start listening on port 8080 and wait for a client connection. You will see "Server listening on port 8080" and "Waiting for client connection...".

Terminal 2 (Client):

cd ~/SEAL/native/examples/
./client_app

The client will connect to the server. It will then prompt you to enter income and expense amounts directly in the terminal. Type each amount and press Enter, then type done and press Enter when you're finished with a category.

After input, the client will perform encryption, send data over the network, receive encrypted results, decrypt them, and display the verification. You will see output in both terminals as the communication and computation proceed.

Expected Output:
You will observe detailed logs in both client and server terminals, demonstrating the full FHE lifecycle:

FHE parameter setup and key generation (client).

Encrypted data transfer from client to server via TCP sockets.

Homomorphic operations (subtraction for net income, multiplication for savings contribution) performed on the server without ever decrypting the sensitive data.

Encrypted results transfer from the server back to the client.

Decryption and verification of results on the client, confirming the calculations were performed correctly on encrypted data.

Future Enhancements:
Full Cloud Deployment: Deploy the server_app to an actual Virtual Private Server (VPS) with a public IP address, allowing clients from anywhere to connect.

Robust Network Communication: Implement more advanced network features like error handling for disconnections, and potentially use HTTPS for encrypted communication over the internet.

Enhanced User Interface: Develop a graphical user interface (e.g., a simple web application or desktop app) for more intuitive data input and result visualization.

More Complex Financial Models: Integrate additional financial calculations such as compound interest, loan amortization, or more detailed budget analysis.

Security Hardening: Further secure the VPS environment and implement robust key management practices for the client.
