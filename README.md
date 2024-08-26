# see_function
See_Function is a simple tool designed to help you detect key Windows API calls within a binary file. These API calls are often used by malware to perform actions like process injection, file manipulation, network communication, and more.

# Features
Identify Key API Calls: Detects critical Windows API calls used in malware, including process creation, memory manipulation, and network activities.
Easy to Use: Simply provide a binary file, and the tool will do the rest!
Quick Insights: Outputs detected API calls to help you understand the program's behavior.

🛠 Requirements
Before you get started, make sure you have Python installed on your machine along with Capstone, a disassembly engine that the tool relies on for analyzing binary code.

Capstone Library: Install it by running the following command:

        pip install capstone

# Getting Started

Download the Tool: Clone or download the script see_function.py to your local machine.
Prepare Your Binary: Obtain the binary file you want to analyze. It could be a malware sample, a suspicious executable, or any other binary.

Run the Tool: Use the following command to analyze your binary file:

          python see_function.py <path_to_binary>

Replace <path_to_binary> with the actual path to the file you want to analyze.

View Results: The tool will output any detected API calls, giving you insight into what actions the program is attempting to perform.

