# Password Strength Analyzer 🛡️

A robust Python-based tool designed to evaluate the security of passwords. This analyzer goes beyond simple length checks by calculating the **Entropy** and estimating the **Time to Crack** using brute-force scenarios.

## ✨ Features
* **Comprehensive Detection:** Analyzes lowercase, uppercase, digits, and special characters.
* **Entropy Calculation:** Measures password strength in bits for mathematical precision.
* **Brute-Force Estimation:** Provides a human-readable estimate of how long it would take to crack the password (from seconds to billions of years).
* **Overflow Protection:** Uses logarithmic calculations to handle extremely large combinations without crashing.
* **Smart Scoring:** Categorizes strength into 5 levels: Very Weak, Weak, Moderate, Strong, and Very Strong.

## 🛠️ Tech Stack
* **Language:** Python 3.x
* **Modules:** `math`, `string` (Built-in libraries)

## 🚀 Installation & Usage

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/YossofAlmadhagi/password-strength-checker.git](https://github.com/YossofAlmadhagi/password-strength-checker.git)
    ```
2.  **Navigate to the project folder:**
    ```bash
    cd password-strength-checker
    ```
3.  **Run the script:**
    ```bash
    python password.py
    ```

## 📊 Sample Output
When you run the script, you will see an output similar to this:
```text
Enter password to evaluate: P@ssw0rd2025!

Length: 12
Charset_size: 94
Entropy_(bits): 78.66
Combinations: None
Estimeted_time_to_crack: 15091334 years, 67 days
Score: 85 (Strong)
