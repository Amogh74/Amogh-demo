/*
 * ============================================================
 *   BANK MANAGEMENT SYSTEM  -  C++ OOP Project (terminal)
 * ============================================================
 *  Features:
 *    - Open Savings / Current accounts, PIN login (PIN stored hashed)
 *    - Deposit, withdraw, transfer, mini statement, account details
 *    - Monthly interest, close account, admin panel, file saving
 *    - FRAUD ALERTS      - every withdrawal / transfer is checked by 3 rule
 *                          classes. Suspicious payments are held until the
 *                          customer confirms. (rule based, not machine learning)
 *    - SPENDING INSIGHTS - each payment has a category; a bar chart shows
 *                          where the money goes.
 *
 *  OOP concepts used (and where to find them):
 *    1. Encapsulation       -> private data in Account, Transaction
 *    2. Abstraction         -> Account and FraudRule are abstract classes
 *    3. Inheritance         -> SavingsAccount, CurrentAccount : Account
 *                              LargeAmountRule, RapidSpendingRule,
 *                              SpikeRule : FraudRule
 *    4. Polymorphism        -> FraudDetector calls rule->isSuspicious() on
 *                              each rule; Account types differ in
 *                              availableToWithdraw()
 *    5. Constructors / Destructors (virtual destructors)
 *    6. Static members      -> Account::nextAccNo
 *    7. Operator overloading + friend -> operator<< for Account
 *    8. Exception handling  -> BankException hierarchy
 *    9. Composition         -> Account has Transactions,
 *                              FraudDetector has FraudRules
 *   10. Template Method     -> Account::withdraw() uses virtual
 *                              availableToWithdraw()
 *   11. File handling       -> data saved to bank_data.txt
 *
 *  Compile :  g++ -std=c++11 -Wall -Wextra bank_management.cpp -o bank
 *  Run     :  ./bank        (Windows: bank.exe)
 *  Admin password: admin123
 * ============================================================
 */

#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace std;

// ============================================================
//  CONFIG  -  all business rules in one place
// ============================================================
namespace Config {
    // accounts
    const double SAVINGS_MIN_BALANCE     = 500.0;
    const double SAVINGS_INTEREST_RATE   = 4.0;      // % per year
    const double CURRENT_MIN_OPENING     = 5000.0;
    const double CURRENT_OVERDRAFT_LIMIT = 10000.0;
    const int    MAX_PIN_ATTEMPTS        = 3;
    const string ADMIN_PASSWORD          = "admin123";
    const string DATA_FILE               = "bank_data.txt";

    // fraud rules
    const double LARGE_AMOUNT      = 20000.0;  // payment this big is flagged
    const int    RAPID_WINDOW_SEC  = 60;       // look-back window
    const int    RAPID_COUNT       = 3;        // 3rd payment inside the window is flagged
    const double SPIKE_FACTOR      = 5.0;      // 5x the usual spend is flagged

    // spending categories
    const char* const CATEGORIES[] = {"Food", "Travel", "Shopping", "Bills",
                                      "Entertainment", "Health", "Other"};
    const int CATEGORY_COUNT = 7;
}

// ============================================================
//  UTILITY HELPERS
// ============================================================
namespace Util {
    string money(double v) {
        ostringstream o;
        o << "Rs. " << fixed << setprecision(2) << v;
        return o.str();
    }

    string formatTime(time_t t) {
        if (t == 0) return "-";                       // old records have no time
        char buf[32];
        strftime(buf, sizeof(buf), "%d-%b-%Y %H:%M", localtime(&t));
        return string(buf);
    }

    string trim(const string& s) {
        size_t a = s.find_first_not_of(" \t\r\n");
        if (a == string::npos) return "";
        size_t b = s.find_last_not_of(" \t\r\n");
        return s.substr(a, b - a + 1);
    }

    vector<string> split(const string& s, char delim) {
        vector<string> parts;
        string item;
        istringstream in(s);
        while (getline(in, item, delim)) parts.push_back(item);
        return parts;
    }

    // Simple djb2 hash so the PIN is never stored as plain text
    string hashPin(const string& pin) {
        unsigned long h = 5381;
        for (size_t i = 0; i < pin.size(); i++) h = h * 33 + (unsigned char)pin[i];
        return to_string(h);
    }

    string upper(string s) {
        transform(s.begin(), s.end(), s.begin(), ::toupper);
        return s;
    }
}

// ============================================================
//  TERMINAL UI  -  colours, banners, messages
// ============================================================
namespace UI {
    const string RESET = "\033[0m", BOLD = "\033[1m", RED = "\033[31m",
                 GREEN = "\033[32m", YELLOW = "\033[33m", CYAN = "\033[36m",
                 DIM = "\033[2m";
    const int WIDTH = 64;

    void init() {
#ifdef _WIN32
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        if (GetConsoleMode(h, &mode)) SetConsoleMode(h, mode | 0x0004); // enable ANSI colours
#endif
    }

    void clear() { cout << "\033[2J\033[H"; }

    void rule(char c = '-') { cout << CYAN << string(WIDTH, c) << RESET << "\n"; }

    void title(const string& text) {
        int pad = (WIDTH - 2 - (int)text.size()) / 2;
        if (pad < 0) pad = 0;
        cout << CYAN << "+" << string(WIDTH - 2, '=') << "+\n";
        cout << "|" << string(pad, ' ') << BOLD << text << RESET << CYAN
             << string(WIDTH - 2 - pad - text.size(), ' ') << "|\n";
        cout << "+" << string(WIDTH - 2, '=') << "+" << RESET << "\n\n";
    }

    void menuItem(int n, const string& text) {
        cout << "   " << YELLOW << "[" << n << "]" << RESET << " " << text << "\n";
    }

    void success(const string& m) { cout << "\n " << GREEN << "[OK] " << m << RESET << "\n"; }
    void error(const string& m)   { cout << "\n " << RED << "[ERROR] " << m << RESET << "\n"; }
    void info(const string& m)    { cout << " " << CYAN << m << RESET << "\n"; }
}

// ============================================================
//  INPUT HELPERS  -  safe input (no cin >> bugs)
// ============================================================
namespace Input {
    string line(const string& prompt) {
        string s;
        cout << prompt;
        if (!getline(cin, s)) { cout << "\n"; exit(0); }  // Ctrl+D / end of input
        return s;
    }

    void pause() { line(UI::DIM + "\n Press ENTER to continue..." + UI::RESET); }

    string text(const string& prompt) {
        while (true) {
            string s = Util::trim(line(prompt));
            if (!s.empty()) return s;
            UI::error("This field cannot be empty.");
        }
    }

    int integer(const string& prompt, int lo, int hi) {
        while (true) {
            string s = Util::trim(line(prompt));
            try {
                size_t pos;
                int v = stoi(s, &pos);
                if (pos == s.size() && v >= lo && v <= hi) return v;
            } catch (...) {}
            UI::error("Enter a whole number between " + to_string(lo) + " and " + to_string(hi) + ".");
        }
    }

    double amount(const string& prompt) {
        while (true) {
            string s = Util::trim(line(prompt));
            try {
                size_t pos;
                double v = stod(s, &pos);
                if (pos == s.size() && v > 0 && v <= 100000000.0) return v;
            } catch (...) {}
            UI::error("Enter a valid positive amount.");
        }
    }

    string pin(const string& prompt) {
        while (true) {
            string s = Util::trim(line(prompt));
            bool ok = (s.size() == 4) && all_of(s.begin(), s.end(), ::isdigit);
            if (ok) return s;
            UI::error("PIN must be exactly 4 digits.");
        }
    }

    bool confirm(const string& prompt) {
        string s = Util::upper(Util::trim(line(prompt + " (y/n): ")));
        return s == "Y" || s == "YES";
    }
}

// ============================================================
//  EXCEPTIONS  -  custom error types
// ============================================================
class BankException : public runtime_error {
public:
    explicit BankException(const string& msg) : runtime_error(msg) {}
};

class InsufficientFundsException : public BankException {
public:
    explicit InsufficientFundsException(double available)
        : BankException("Insufficient funds. Maximum you can withdraw: " + Util::money(available)) {}
};

// ============================================================
//  TRANSACTION  -  one line of the passbook
// ============================================================
class Transaction {
private:
    string type;          // "Deposit", "Withdrawal", ...
    double amount;        // +ve = money in, -ve = money out
    double balanceAfter;
    time_t when;          // real time, so fraud rules can measure gaps
    string category;      // Food, Travel, Income, ...
    string flagReason;    // empty = normal, otherwise why it was flagged

public:
    Transaction(const string& t, double amt, double balAfter, time_t w = time(nullptr),
                const string& cat = "Other", const string& flag = "")
        : type(t), amount(amt), balanceAfter(balAfter), when(w), category(cat), flagReason(flag) {}

    string getType() const         { return type; }
    double getAmount() const       { return amount; }
    double getBalanceAfter() const { return balanceAfter; }
    time_t getTime() const         { return when; }
    string getCategory() const     { return category; }
    string getFlagReason() const   { return flagReason; }
    bool   isDebit() const         { return amount < 0; }
    bool   isFlagged() const       { return !flagReason.empty(); }
    double spent() const           { return amount < 0 ? -amount : 0; }

    string serialize() const {
        string safeReason = flagReason;
        replace(safeReason.begin(), safeReason.end(), '|', '/');
        ostringstream o;
        o << "T|" << type << "|" << fixed << setprecision(2) << amount << "|"
          << balanceAfter << "|" << (long long)when << "|" << category << "|" << safeReason;
        return o.str();
    }
};

// ============================================================
//  ACCOUNT  -  ABSTRACT base class
// ============================================================
class Account {
private:                       // ENCAPSULATION: outside code cannot touch these directly
    int    accNo;
    string holderName;
    string pinHash;

protected:                     // visible to child classes only
    double balance;
    vector<Transaction> history;                 // COMPOSITION
    static int nextAccNo;                        // STATIC: shared by all accounts

    void record(const string& type, double signedAmount, const string& category,
                const string& flag, time_t when) {
        history.push_back(Transaction(type, signedAmount, balance, when, category, flag));
    }

public:
    Account(int no, const string& name, const string& hash, double bal)
        : accNo(no), holderName(name), pinHash(hash), balance(bal) {}

    virtual ~Account() {}                        // virtual destructor (needed for polymorphism)

    // ---- ABSTRACTION: every account type MUST define these ----
    virtual double availableToWithdraw() const = 0;
    virtual double monthlyInterest() const = 0;
    virtual string getType() const = 0;
    virtual string rulesInfo() const = 0;

    // ---- Common behaviour shared by all accounts ----
    void deposit(double amt, const string& desc = "Deposit", time_t when = time(nullptr)) {
        if (amt <= 0) throw BankException("Deposit amount must be greater than zero.");
        balance += amt;
        record(desc, amt, "Income", "", when);
    }

    // throws if the withdrawal is not allowed (used before the fraud check)
    void ensureCanWithdraw(double amt) const {
        if (amt <= 0) throw BankException("Withdrawal amount must be greater than zero.");
        if (amt > availableToWithdraw()) throw InsufficientFundsException(availableToWithdraw());
    }

    // TEMPLATE METHOD: same steps for everyone, but the *limit* comes from the child class
    void withdraw(double amt, const string& desc = "Withdrawal", const string& category = "Other",
                  const string& flagReason = "", time_t when = time(nullptr)) {
        ensureCanWithdraw(amt);
        balance -= amt;
        record(desc, -amt, category, flagReason, when);
    }

    // POLYMORPHISM in action: Savings pays interest, Current pays 0
    void applyInterest() {
        double interest = monthlyInterest();
        if (interest > 0) deposit(interest, "Interest Credit");
    }

    bool verifyPin(const string& pin) const { return Util::hashPin(pin) == pinHash; }

    void changePin(const string& newPin) { pinHash = Util::hashPin(newPin); }

    // Getters (read-only access to private data)
    int    getAccNo() const   { return accNo; }
    string getName() const    { return holderName; }
    double getBalance() const { return balance; }
    const vector<Transaction>& getHistory() const { return history; }

    void loadTransaction(const Transaction& t) { history.push_back(t); }  // used when reading file

    string serialize() const {
        ostringstream o;
        o << "A|" << getType() << "|" << accNo << "|" << holderName << "|"
          << pinHash << "|" << fixed << setprecision(2) << balance;
        return o.str();
    }

    // static helpers
    static int  generateAccNo()      { return nextAccNo++; }
    static void setNextAccNo(int n)  { nextAccNo = n; }

    // OPERATOR OVERLOADING + FRIEND: lets us write  cout << account;
    friend ostream& operator<<(ostream& os, const Account& a);
};

int Account::nextAccNo = 1001;     // static member must be defined outside the class

ostream& operator<<(ostream& os, const Account& a) {
    os << "| " << left << setw(6) << a.accNo
       << "| " << setw(9) << a.getType()
       << "| " << setw(22) << a.holderName.substr(0, 21)
       << "| " << right << setw(16) << Util::money(a.balance) << " |";
    return os;
}

// ============================================================
//  SAVINGS ACCOUNT  -  INHERITS Account
// ============================================================
class SavingsAccount : public Account {
public:
    SavingsAccount(int no, const string& name, const string& hash, double bal)
        : Account(no, name, hash, bal) {}

    double availableToWithdraw() const override {
        double free = balance - Config::SAVINGS_MIN_BALANCE;   // must keep minimum balance
        return free > 0 ? free : 0;
    }
    double monthlyInterest() const override {
        return balance * (Config::SAVINGS_INTEREST_RATE / 100.0) / 12.0;
    }
    string getType() const override { return "Savings"; }
    string rulesInfo() const override {
        ostringstream o;
        o << fixed << setprecision(1) << Config::SAVINGS_INTEREST_RATE << "% interest p.a. | Min balance "
          << Util::money(Config::SAVINGS_MIN_BALANCE);
        return o.str();
    }
};

// ============================================================
//  CURRENT ACCOUNT  -  INHERITS Account
// ============================================================
class CurrentAccount : public Account {
public:
    CurrentAccount(int no, const string& name, const string& hash, double bal)
        : Account(no, name, hash, bal) {}

    double availableToWithdraw() const override {
        return balance + Config::CURRENT_OVERDRAFT_LIMIT;      // overdraft allowed
    }
    double monthlyInterest() const override { return 0.0; }   // no interest
    string getType() const override { return "Current"; }
    string rulesInfo() const override {
        return "No interest | Overdraft up to " + Util::money(Config::CURRENT_OVERDRAFT_LIMIT);
    }
};

// ============================================================
//  FRAUD DETECTION - one abstract rule, three real rules
// ============================================================
class FraudRule {
public:
    virtual ~FraudRule() {}
    // returns true if the payment looks suspicious and fills in the reason
    virtual bool isSuspicious(const Account& acc, double amount, string& reason) const = 0;
};

// Rule 1: one very large payment
class LargeAmountRule : public FraudRule {
public:
    bool isSuspicious(const Account&, double amount, string& reason) const override {
        if (amount >= Config::LARGE_AMOUNT) {
            reason = "Large payment: " + Util::money(amount) + " is above the "
                   + Util::money(Config::LARGE_AMOUNT) + " safety limit.";
            return true;
        }
        return false;
    }
};

// Rule 2: many payments in a very short time
class RapidSpendingRule : public FraudRule {
public:
    bool isSuspicious(const Account& acc, double, string& reason) const override {
        time_t now = time(nullptr);
        int recent = 0;
        const vector<Transaction>& h = acc.getHistory();
        for (size_t i = 0; i < h.size(); i++)
            if (h[i].isDebit() && difftime(now, h[i].getTime()) <= Config::RAPID_WINDOW_SEC) recent++;

        if (recent >= Config::RAPID_COUNT - 1) {
            reason = "Rapid spending: " + to_string(recent + 1) + " payments within "
                   + to_string(Config::RAPID_WINDOW_SEC) + " seconds.";
            return true;
        }
        return false;
    }
};

// Rule 3: payment far bigger than this customer's usual spending
class SpikeRule : public FraudRule {
public:
    bool isSuspicious(const Account& acc, double amount, string& reason) const override {
        double total = 0;
        int count = 0;
        const vector<Transaction>& h = acc.getHistory();
        for (size_t i = 0; i < h.size(); i++)
            if (h[i].isDebit()) { total += h[i].spent(); count++; }

        if (count < 3) return false;                 // not enough history to judge
        double average = total / count;
        if (amount > average * Config::SPIKE_FACTOR) {
            reason = "Unusual amount: " + Util::money(amount) + " is over "
                   + to_string((int)Config::SPIKE_FACTOR) + "x your average spend of "
                   + Util::money(average) + ".";
            return true;
        }
        return false;
    }
};

// The detector owns all rules and checks a payment against each one.
// POLYMORPHISM: same call (isSuspicious), different behaviour per rule.
class FraudDetector {
private:
    vector<unique_ptr<FraudRule>> rules;

public:
    FraudDetector() {
        rules.push_back(unique_ptr<FraudRule>(new LargeAmountRule()));
        rules.push_back(unique_ptr<FraudRule>(new RapidSpendingRule()));
        rules.push_back(unique_ptr<FraudRule>(new SpikeRule()));
    }

    vector<string> scan(const Account& acc, double amount) const {
        vector<string> reasons;
        for (size_t i = 0; i < rules.size(); i++) {
            string reason;
            if (rules[i]->isSuspicious(acc, amount, reason)) reasons.push_back(reason);
        }
        return reasons;
    }
};

// ============================================================
//  SPENDING ANALYZER - totals and bar chart per category
// ============================================================
class SpendingAnalyzer {
public:
    void print(const Account& acc) const {
        map<string, double> totals;
        double sum = 0, biggest = 0;
        int count = 0;
        string biggestCategory;

        const vector<Transaction>& h = acc.getHistory();
        for (size_t i = 0; i < h.size(); i++) {
            if (!h[i].isDebit()) continue;
            totals[h[i].getCategory()] += h[i].spent();
            sum += h[i].spent();
            count++;
            if (h[i].spent() > biggest) { biggest = h[i].spent(); biggestCategory = h[i].getCategory(); }
        }

        if (count == 0) { UI::info("No spending recorded yet."); return; }

        vector<pair<string, double> > sorted(totals.begin(), totals.end());
        sort(sorted.begin(), sorted.end(),
             [](const pair<string, double>& a, const pair<string, double>& b) { return a.second > b.second; });

        cout << "   Total spent      : " << UI::RED << Util::money(sum) << UI::RESET << "\n"
             << "   Payments made    : " << count << "\n"
             << "   Average payment  : " << Util::money(sum / count) << "\n"
             << "   Biggest payment  : " << Util::money(biggest) << " (" << biggestCategory << ")\n\n";

        const int BAR = 28;
        for (size_t i = 0; i < sorted.size(); i++) {
            double percent = sorted[i].second * 100.0 / sum;
            int filled = (int)(percent * BAR / 100.0 + 0.5);
            cout << "   " << left << setw(14) << sorted[i].first
                 << UI::CYAN << string(filled, '#') << UI::DIM << string(BAR - filled, '.') << UI::RESET
                 << right << setw(8) << fixed << setprecision(1) << percent << "%"
                 << setw(14) << Util::money(sorted[i].second) << "\n";
        }
        cout << "\n   Top category: " << UI::BOLD << sorted[0].first << UI::RESET << "\n";
    }
};

// ============================================================
//  BANK  -  holds all accounts (AGGREGATION) + business logic
// ============================================================
class Bank {
private:
    vector<unique_ptr<Account>> accounts;   // base-class pointers -> POLYMORPHISM
    FraudDetector detector;                 // the bank owns one detector

    unique_ptr<Account> makeAccount(const string& type, int no, const string& name,
                                    const string& hash, double bal) {
        if (type == "Savings") return unique_ptr<Account>(new SavingsAccount(no, name, hash, bal));
        return unique_ptr<Account>(new CurrentAccount(no, name, hash, bal));
    }

    void load() {
        ifstream in(Config::DATA_FILE.c_str());
        if (!in) return;                                   // first run: no file yet
        string ln;
        Account* last = nullptr;
        int maxNo = 1000;
        try {
            while (getline(in, ln)) {
                vector<string> p = Util::split(ln, '|');
                if (p.empty()) continue;
                if (p[0] == "A" && p.size() == 6) {
                    int no = stoi(p[2]);
                    unique_ptr<Account> a = makeAccount(p[1], no, p[3], p[4], stod(p[5]));
                    last = a.get();
                    accounts.push_back(move(a));
                    maxNo = max(maxNo, no);
                } else if (p[0] == "T" && last && p.size() == 5) {
                    // older record format (no time / category): keep it, mark as "Other"
                    last->loadTransaction(Transaction(p[1], stod(p[2]), stod(p[3]), 0, "Other", ""));
                } else if (p[0] == "T" && last && p.size() >= 6) {
                    string flag = p.size() >= 7 ? p[6] : "";
                    last->loadTransaction(Transaction(p[1], stod(p[2]), stod(p[3]),
                                                      (time_t)stoll(p[4]), p[5], flag));
                }
            }
        } catch (...) {
            UI::error("Data file is corrupted; some records could not be loaded.");
        }
        Account::setNextAccNo(maxNo + 1);
    }

public:
    Bank()  { load(); }
    ~Bank() { save(); }                                    // destructor saves data (RAII idea)

    void save() const {
        ofstream out(Config::DATA_FILE.c_str());
        for (size_t i = 0; i < accounts.size(); i++) {
            out << accounts[i]->serialize() << "\n";
            const vector<Transaction>& h = accounts[i]->getHistory();
            for (size_t j = 0; j < h.size(); j++) out << h[j].serialize() << "\n";
        }
    }

    int createAccount(int typeChoice, string name, const string& pin, double initialDeposit) {
        replace(name.begin(), name.end(), '|', ' ');       // '|' is our file delimiter
        double minOpen = (typeChoice == 1) ? Config::SAVINGS_MIN_BALANCE : Config::CURRENT_MIN_OPENING;
        if (initialDeposit < minOpen)
            throw BankException("Minimum opening deposit for this account is " + Util::money(minOpen) + ".");

        int no = Account::generateAccNo();
        unique_ptr<Account> acc = makeAccount(typeChoice == 1 ? "Savings" : "Current",
                                              no, name, Util::hashPin(pin), 0);
        acc->deposit(initialDeposit, "Opening Deposit");
        accounts.push_back(move(acc));
        save();
        return no;
    }

    // Sample account with 30 days of history, so insights and alerts can be demonstrated.
    // Login: PIN 1234
    int createDemoAccount() {
        const time_t DAY = 24 * 60 * 60;
        time_t now = time(nullptr);
        int no = Account::generateAccNo();
        unique_ptr<Account> acc(new SavingsAccount(no, "Demo User", Util::hashPin("1234"), 0));
        acc->deposit(80000, "Opening Deposit", now - 30 * DAY);
        acc->withdraw(450,  "Withdrawal", "Food",          "", now - 20 * DAY);
        acc->withdraw(1200, "Withdrawal", "Bills",         "", now - 18 * DAY);
        acc->withdraw(2200, "Withdrawal", "Shopping",      "", now - 15 * DAY);
        acc->withdraw(600,  "Withdrawal", "Travel",        "", now - 12 * DAY);
        acc->withdraw(380,  "Withdrawal", "Food",          "", now - 9 * DAY);
        acc->withdraw(799,  "Withdrawal", "Entertainment", "", now - 6 * DAY);
        acc->withdraw(1500, "Withdrawal", "Bills",         "", now - 4 * DAY);
        acc->withdraw(520,  "Withdrawal", "Food",          "", now - 2 * DAY);
        accounts.push_back(move(acc));
        save();
        return no;
    }

    Account* find(int accNo) const {
        for (size_t i = 0; i < accounts.size(); i++)
            if (accounts[i]->getAccNo() == accNo) return accounts[i].get();
        return nullptr;
    }

    // ask the detector about a payment before it is made
    vector<string> checkPayment(const Account& acc, double amount) const {
        return detector.scan(acc, amount);
    }

    void transfer(Account& from, int toNo, double amount, const string& flagReason = "") {
        Account* to = find(toNo);
        if (!to) throw BankException("Recipient account not found.");
        if (to == &from) throw BankException("You cannot transfer to your own account.");
        from.withdraw(amount, "Transfer to #" + to_string(toNo), "Transfer", flagReason);  // may throw -> nothing changes
        to->deposit(amount, "Transfer from #" + to_string(from.getAccNo()));
        save();
    }

    double closeAccount(int accNo) {
        for (size_t i = 0; i < accounts.size(); i++) {
            if (accounts[i]->getAccNo() == accNo) {
                double payout = accounts[i]->getBalance();
                accounts.erase(accounts.begin() + i);                    // unique_ptr deletes it
                save();
                return payout;
            }
        }
        throw BankException("Account not found.");
    }

    void applyInterestToAll() {
        for (size_t i = 0; i < accounts.size(); i++)
            accounts[i]->applyInterest();                                // polymorphic call
        save();
    }

    const vector<unique_ptr<Account> >& all() const { return accounts; }
};

// ============================================================
//  BANK APP  -  menus and screens (separate from logic)
// ============================================================
class BankApp {
private:
    Bank bank;
    SpendingAnalyzer analyzer;

    string rulesText(int type) {
        if (type == 1) return SavingsAccount(0, "", "", 0).rulesInfo();
        return CurrentAccount(0, "", "", 0).rulesInfo();
    }

    // ---------- fraud check shown to the customer ----------
    // returns true if the payment may go ahead; flagReason is stored with the transaction
    bool fraudCheck(const Account& acc, double amount, string& flagReason) {
        flagReason = "";
        vector<string> reasons = bank.checkPayment(acc, amount);
        if (reasons.empty()) return true;

        cout << "\n " << UI::RED << UI::BOLD << "!! SECURITY ALERT - this payment looks suspicious !!"
             << UI::RESET << "\n";
        for (size_t i = 0; i < reasons.size(); i++) {
            cout << UI::RED << "   - " << reasons[i] << UI::RESET << "\n";
            flagReason += (i ? " " : "") + reasons[i];
        }
        cout << "\n";
        return Input::confirm(" Is this payment really you? Approve anyway?");
    }

    string chooseCategory() {
        cout << "\n What is this payment for?\n";
        for (int i = 0; i < Config::CATEGORY_COUNT; i++) UI::menuItem(i + 1, Config::CATEGORIES[i]);
        int c = Input::integer("\n Category: ", 1, Config::CATEGORY_COUNT);
        return Config::CATEGORIES[c - 1];
    }

    void showInsights(const Account& acc) {
        UI::clear();
        UI::title("SPENDING INSIGHTS");
        cout << " Account #" << acc.getAccNo() << "  |  " << acc.getName() << "\n\n";
        analyzer.print(acc);
    }

    void showAlerts(const Account& acc) {
        UI::clear();
        UI::title("SECURITY ALERTS");
        int found = 0;
        const vector<Transaction>& h = acc.getHistory();
        for (size_t i = h.size(); i > 0; i--) {                         // newest first
            const Transaction& t = h[i - 1];
            if (!t.isFlagged()) continue;
            found++;
            cout << " " << UI::BOLD << Util::formatTime(t.getTime()) << UI::RESET << "  "
                 << Util::money(t.spent()) << " (" << t.getCategory() << ")\n"
                 << UI::RED << "   " << t.getFlagReason() << UI::RESET << "\n\n";
        }
        if (found == 0) UI::success("No suspicious activity on this account.");
        else cout << " " << found << " flagged payment(s). These were approved by you after a warning.\n";
    }

    void printStatement(const Account& acc) {
        UI::clear();
        UI::title("MINI STATEMENT");
        cout << " Account #" << acc.getAccNo() << "  |  " << acc.getName() << "\n\n";
        cout << UI::BOLD << " " << left << setw(18) << "Date" << setw(26) << "Description"
             << right << setw(10) << "Amount" << setw(10) << "Balance" << UI::RESET << "\n";
        UI::rule();
        const vector<Transaction>& h = acc.getHistory();
        size_t start = h.size() > 10 ? h.size() - 10 : 0;                // last 10 only
        for (size_t i = start; i < h.size(); i++) {
            bool credit = h[i].getAmount() >= 0;
            string desc = h[i].getType();
            if (h[i].isDebit() && h[i].getCategory() != "Transfer" && h[i].getCategory() != "Other")
                desc += " - " + h[i].getCategory();
            if (h[i].isFlagged()) desc = "! " + desc;                    // "!" marks flagged payments
            if (desc.size() > 25) desc = desc.substr(0, 25);
            cout << " " << left << setw(18) << Util::formatTime(h[i].getTime())
                 << (h[i].isFlagged() ? UI::RED : "") << setw(26) << desc << UI::RESET
                 << (credit ? UI::GREEN : UI::RED) << right << setw(10)
                 << ((credit ? "+" : "") + Util::money(h[i].getAmount()).substr(4)) << UI::RESET
                 << setw(10) << Util::money(h[i].getBalanceAfter()).substr(4) << "\n";
        }
        UI::rule();
        cout << " (Amounts in Rs., last " << (h.size() - start) << " transaction(s). '!' = flagged payment)\n";
    }

    void showDetails(const Account& acc) {
        UI::clear();
        UI::title("ACCOUNT DETAILS");
        cout << "   Account No   : " << acc.getAccNo() << "\n"
             << "   Holder       : " << acc.getName() << "\n"
             << "   Type         : " << acc.getType() << "\n"
             << "   Balance      : " << UI::GREEN << Util::money(acc.getBalance()) << UI::RESET << "\n"
             << "   Can withdraw : " << Util::money(acc.availableToWithdraw()) << "\n"
             << "   Rules        : " << acc.rulesInfo() << "\n";
    }

    // ---------- Open account ----------
    void openAccount() {
        UI::clear();
        UI::title("OPEN NEW ACCOUNT");
        UI::menuItem(1, "Savings Account  (" + rulesText(1) + ")");
        UI::menuItem(2, "Current Account  (" + rulesText(2) + ")");
        cout << "\n";
        int type = Input::integer(" Choose account type: ", 1, 2);
        string name = Input::text(" Full name: ");
        string pin = Input::pin(" Set a 4-digit PIN: ");
        if (Input::pin(" Confirm PIN: ") != pin) { UI::error("PINs do not match."); Input::pause(); return; }
        double dep = Input::amount(" Opening deposit (Rs.): ");
        try {
            int no = bank.createAccount(type, name, pin, dep);
            UI::success("Account created! Your account number is " + to_string(no));
            UI::info("Remember it - you need it to log in.");
        } catch (const BankException& e) {
            UI::error(e.what());
        }
        Input::pause();
    }

    // ---------- Login ----------
    void login() {
        UI::clear();
        UI::title("CUSTOMER LOGIN");
        int no = Input::integer(" Account number: ", 1, 999999);
        Account* acc = bank.find(no);
        if (!acc) { UI::error("Account not found."); Input::pause(); return; }

        for (int attempt = 1; attempt <= Config::MAX_PIN_ATTEMPTS; attempt++) {
            string pin = Input::pin(" Enter PIN: ");
            if (acc->verifyPin(pin)) { customerMenu(acc); return; }
            UI::error("Wrong PIN. Attempts left: " + to_string(Config::MAX_PIN_ATTEMPTS - attempt));
        }
        UI::error("Too many wrong attempts. Returning to main menu.");
        Input::pause();
    }

    // ---------- Customer session ----------
    void customerMenu(Account* acc) {
        while (true) {
            UI::clear();
            UI::title("WELCOME, " + Util::upper(acc->getName()));
            cout << "   Account : #" << acc->getAccNo() << " (" << acc->getType() << ")\n"
                 << "   Balance : " << UI::GREEN << Util::money(acc->getBalance()) << UI::RESET << "\n\n";
            UI::menuItem(1, "Deposit");
            UI::menuItem(2, "Withdraw");
            UI::menuItem(3, "Transfer to another account");
            UI::menuItem(4, "Account details");
            UI::menuItem(5, "Mini statement");
            UI::menuItem(6, "Spending insights");
            UI::menuItem(7, "Security alerts");
            UI::menuItem(8, "Change PIN");
            UI::menuItem(9, "Close account");
            UI::menuItem(10, "Logout");
            cout << "\n";
            int ch = Input::integer(" Choice: ", 1, 10);

            try {
                switch (ch) {
                case 1: {
                    double a = Input::amount(" Amount to deposit: ");
                    acc->deposit(a);
                    bank.save();
                    UI::success(Util::money(a) + " deposited. New balance: " + Util::money(acc->getBalance()));
                    Input::pause();
                    break;
                }
                case 2: {
                    double a = Input::amount(" Amount to withdraw: ");
                    acc->ensureCanWithdraw(a);                       // stop early if not allowed
                    string category = chooseCategory();
                    string flagReason;
                    if (!fraudCheck(*acc, a, flagReason)) {
                        UI::info("Payment cancelled. Nothing was withdrawn.");
                        Input::pause();
                        break;
                    }
                    acc->withdraw(a, "Withdrawal", category, flagReason);
                    bank.save();
                    UI::success(Util::money(a) + " withdrawn (" + category + "). New balance: "
                                + Util::money(acc->getBalance()));
                    Input::pause();
                    break;
                }
                case 3: {
                    int to = Input::integer(" Recipient account number: ", 1, 999999);
                    Account* r = bank.find(to);
                    if (!r) throw BankException("Recipient account not found.");
                    double a = Input::amount(" Amount to transfer: ");
                    acc->ensureCanWithdraw(a);
                    if (!Input::confirm(" Send " + Util::money(a) + " to " + r->getName() + " (#" + to_string(to) + ")?")) {
                        UI::info("Transfer cancelled.");
                        Input::pause();
                        break;
                    }
                    string flagReason;
                    if (!fraudCheck(*acc, a, flagReason)) {
                        UI::info("Transfer cancelled. Nothing was sent.");
                        Input::pause();
                        break;
                    }
                    bank.transfer(*acc, to, a, flagReason);
                    UI::success("Transfer complete. New balance: " + Util::money(acc->getBalance()));
                    Input::pause();
                    break;
                }
                case 4: showDetails(*acc); Input::pause(); break;
                case 5: printStatement(*acc); Input::pause(); break;
                case 6: showInsights(*acc); Input::pause(); break;
                case 7: showAlerts(*acc); Input::pause(); break;
                case 8: {
                    if (!acc->verifyPin(Input::pin(" Current PIN: "))) throw BankException("Wrong PIN.");
                    string np = Input::pin(" New PIN: ");
                    if (Input::pin(" Confirm new PIN: ") != np) throw BankException("PINs do not match.");
                    acc->changePin(np);
                    bank.save();
                    UI::success("PIN changed successfully.");
                    Input::pause();
                    break;
                }
                case 9: {
                    if (!acc->verifyPin(Input::pin(" Enter PIN to confirm: "))) throw BankException("Wrong PIN.");
                    if (acc->getBalance() < 0) throw BankException("Clear your overdraft before closing the account.");
                    if (Input::confirm(" Close account permanently?")) {
                        double payout = bank.closeAccount(acc->getAccNo());   // acc is invalid after this!
                        UI::success("Account closed. Please collect " + Util::money(payout) + " in cash.");
                        Input::pause();
                        return;
                    }
                    break;
                }
                case 10:
                    return;
                }
            } catch (const BankException& e) {             // one catch handles every bank error
                UI::error(e.what());
                Input::pause();
            }
        }
    }

    // ---------- Admin ----------
    void fraudReport() {
        UI::clear();
        UI::title("FRAUD ALERT REPORT");
        int found = 0;
        const vector<unique_ptr<Account> >& all = bank.all();
        for (size_t i = 0; i < all.size(); i++) {
            const vector<Transaction>& h = all[i]->getHistory();
            for (size_t j = 0; j < h.size(); j++) {
                if (!h[j].isFlagged()) continue;
                found++;
                cout << " Acc #" << all[i]->getAccNo() << " (" << all[i]->getName() << ")  "
                     << Util::formatTime(h[j].getTime()) << "  " << Util::money(h[j].spent())
                     << " [" << h[j].getCategory() << "]\n"
                     << UI::RED << "   " << h[j].getFlagReason() << UI::RESET << "\n\n";
            }
        }
        if (found == 0) UI::success("No flagged payments in the whole bank.");
        else cout << " Total flagged payments: " << found << "\n";
    }

    void adminPanel() {
        UI::clear();
        UI::title("ADMIN PANEL");
        string pw = Input::line(" Admin password: ");
        if (pw != Config::ADMIN_PASSWORD) { UI::error("Access denied."); Input::pause(); return; }

        while (true) {
            UI::clear();
            UI::title("ADMIN PANEL");
            UI::menuItem(1, "View all accounts");
            UI::menuItem(2, "Apply monthly interest to all accounts");
            UI::menuItem(3, "Bank summary");
            UI::menuItem(4, "Fraud alert report");
            UI::menuItem(5, "Create demo account       (PIN 1234)");
            UI::menuItem(6, "Back");
            cout << "\n";
            int ch = Input::integer(" Choice: ", 1, 6);

            if (ch == 1) {
                UI::clear();
                UI::title("ALL ACCOUNTS");
                cout << UI::BOLD << "| " << left << setw(6) << "No" << "| " << setw(9) << "Type"
                     << "| " << setw(22) << "Holder" << "| " << right << setw(16) << "Balance" << " |"
                     << UI::RESET << "\n";
                UI::rule();
                const vector<unique_ptr<Account> >& all = bank.all();
                if (all.empty()) cout << " (no accounts yet)\n";
                for (size_t i = 0; i < all.size(); i++) cout << *all[i] << "\n";   // operator<<
                UI::rule();
                Input::pause();
            } else if (ch == 2) {
                bank.applyInterestToAll();
                UI::success("Monthly interest credited to all eligible accounts.");
                Input::pause();
            } else if (ch == 3) {
                double total = 0;
                int sav = 0, cur = 0;
                const vector<unique_ptr<Account> >& all = bank.all();
                for (size_t i = 0; i < all.size(); i++) {
                    total += all[i]->getBalance();
                    if (all[i]->getType() == "Savings") sav++; else cur++;
                }
                UI::clear();
                UI::title("BANK SUMMARY");
                cout << "   Total accounts   : " << all.size() << "\n"
                     << "   Savings accounts : " << sav << "\n"
                     << "   Current accounts : " << cur << "\n"
                     << "   Total deposits   : " << UI::GREEN << Util::money(total) << UI::RESET << "\n";
                Input::pause();
            } else if (ch == 4) {
                fraudReport();
                Input::pause();
            } else if (ch == 5) {
                int no = bank.createDemoAccount();
                UI::success("Demo account created. Account number " + to_string(no) + ", PIN 1234.");
                UI::info("It has 30 days of sample spending. Try a Rs. 25000 withdrawal to see an alert.");
                Input::pause();
            } else return;
        }
    }

public:
    void run() {
        while (true) {
            UI::clear();
            UI::title("BANK MANAGEMENT SYSTEM");
            UI::menuItem(1, "Open a new account");
            UI::menuItem(2, "Customer login");
            UI::menuItem(3, "Admin panel");
            UI::menuItem(4, "Exit");
            cout << "\n";
            int ch = Input::integer(" Choice: ", 1, 4);
            switch (ch) {
                case 1: openAccount(); break;
                case 2: login(); break;
                case 3: adminPanel(); break;
                case 4:
                    bank.save();
                    UI::clear();
                    UI::info("Thank you for banking with us. Goodbye!\n");
                    return;
            }
        }
    }
};

// ============================================================
int main() {
    UI::init();
    BankApp app;
    app.run();
    return 0;
}
