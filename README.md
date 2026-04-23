# 🔐 Firewall Rule Testing Simulator (Cyber Range v2.0)

A GUI-based firewall simulation tool built using Python and Tkinter.
This project allows users to create, test, and analyze firewall rules against simulated network traffic in real time.

---

## 💡 Why I Built This

While studying firewall systems and network security, I found that most concepts remain theoretical unless you can actually see them in action.
So I built this simulator as a small “cyber range” where I could experiment with rules and observe how traffic is filtered.

The goal was simple:

* Make firewall behavior easy to understand
* Provide a hands-on way to test rule configurations
* Simulate both normal and suspicious network traffic

---

## ⚙️ Features

* Rule-based firewall engine (first-match logic)
* Default deny policy (secure by design)
* Interactive GUI with modern dark theme
* Toggle-based inputs (ANY or specific values)
* Protocol support:

  * TCP, UDP, ICMP, HTTP, HTTPS, FTP, DNS
* Real-time packet simulation
* Attack-like traffic generation (common vulnerable ports)
* Live packet logging with timestamps
* Rule priority system (top = highest priority)
* Remove selected rule / clear all rules
* Adjustable simulation speed

---

## 🧠 How It Works

1. The user creates firewall rules using the GUI
2. The simulator generates network packets (both normal and suspicious traffic)
3. Each packet is evaluated against the rule list:

   * First matching rule is applied
   * If no rule matches → default action is **DENY**
4. Results are displayed in real-time logs along with the matched rule number

---

## 🖥️ Example Rules

```text
ANY      ANY      ANY     HTTPS   ALLOW
ANY      ANY      22      TCP     DENY
ANY      ANY      ANY     ANY     DENY
```

This means:

* Allow HTTPS traffic
* Block SSH (port 22)
* Deny everything else

---

## ▶️ How to Run

```bash
git clone https://github.com/your-username/firewall-rule-testing-simulator.git
cd firewall-rule-testing-simulator
python main.py
```

---


---

## 🔐 Concepts Used

* First-match firewall rule evaluation
* Default deny security model
* Protocol-based filtering
* Port-based access control
* Basic traffic simulation

---

## 🚀 Future Improvements

Some ideas to extend this project further:

* Rule conflict detection
* Attack pattern detection (port scanning, brute force)
* Traffic visualization (charts/graphs)
* Save and load rule configurations
* Integration with real packet capture tools

---

## 🎓 Academic Context

This project was developed as part of a cybersecurity coursework focused on:

* Firewall systems
* Network traffic filtering
* Cyber Range simulations

---

## 🤝 Notes

This project was built for learning and experimentation.
Feedback and suggestions are always welcome.

---
