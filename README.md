# 🛰️ Proxy Performance Monitor for RagnaTales

Welcome to the **Proxy Performance Monitor**, a tool designed to help you find the best proxy for a smoother gaming experience on **RagnaTales**! This script continuously tests multiple proxies to determine which one offers the best connection based on various network metrics.

## 🚀 Features

- **Real-Time Monitoring**: Continuously pings multiple proxies and displays live performance metrics.
- **Composite Scoring**: Calculates a composite score based on ping, jitter, packet loss, number of hops, and jitter variation over time.
- **Asynchronous Traceroute**: Performs continuous traceroute monitoring to provide detailed hop statistics similar to WinMTR.
- **Dynamic UI**: Provides a rich and interactive console interface using the `rich` library.
- **Automatic Proxy Discovery**: Dynamically discovers available proxies up to `proxy20`.
- **Connection Type Detection**: Identifies if you're connected via Ethernet or Wi-Fi.
- **User-Friendly Output**: Saves detailed results to a file upon user request.
- **Countdown Timer**: Displays a countdown during initial analysis to ensure accurate results.

## 📸 Screenshot

![image](https://i.imgur.com/wTkt7EW.png)

## 🛠️ Installation

1. **Prerequisites**:
   - Python 3.6 or higher.
   - Windows operating system (full functionality on Windows; limited support on Unix/Linux).

2. **Clone the Repository**:

   To clone the repository, run the following commands:

       git clone https://github.com/yourusername/proxy-performance-monitor.git
       cd proxy-performance-monitor

3. **Install Required Packages**:

   Install the required packages using:

       pip install -r requirements.txt

   *Note: The script requires the `rich` library for the console UI.*

## ▶️ Usage

Run the script using Python:

    python proxy_performance_monitor.py

**Controls**:

- Press **`s`** to save the current results to a file.
- Press **`q`** to quit the program.

**Note**: For accurate results, allow the program to run for at least **30 seconds**. The best proxy will be selected after the initial countdown.

## 📝 Metrics Explained

- **Ping**: Time taken for a packet to travel to the proxy and back. Lower values are better.
- **Packet Loss**: Percentage of packets lost during transmission. Indicates instability; lower is better.
- **Jitter**: Variation in ping over time. High jitter can cause lag; lower values are preferable.
- **Jitter Variation**: Fluctuation of jitter over a longer period. Helps identify inconsistent connections.
- **Number of Hops**: The number of routers between you and the proxy. Fewer hops can mean a more stable connection.
- **Score**: A composite metric that evaluates overall proxy performance. Lower scores are better.

## 🌐 Connection Type Detection

The tool detects your connection type and provides a warning if you're connected via Wi-Fi:

- **Cabo**: You're connected via Ethernet. Optimal for gaming.
- **Wi-Fi**: You're connected via Wi-Fi. For the best gaming experience on RagnaTales, it's recommended to use a wired connection.

## 🔄 Asynchronous Traceroute

The tool performs asynchronous traceroute tests to each proxy, ensuring that hops information is updated in real-time without affecting the performance of other tests.

## 💾 Saving Results

Press **`s`** at any time to save the current results to a timestamped text file for later analysis.

## 📊 Understanding the UI

The console interface displays:

- **Individual Proxy Panels**: Show detailed metrics for each proxy, including ping statistics, packet loss, jitter, and number of hops.
- **Summary Table**: Provides a quick comparison of all proxies based on key metrics.
- **Best Proxy Panel**: Highlights the proxy with the lowest composite score after the initial 30-second analysis.
- **Information Panel**: Explains the metrics and provides helpful tips.
- **Countdown Timer**: During the initial analysis, a countdown is displayed to indicate when the best proxy will be selected.

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch:

       git checkout -b feature/your-feature-name

3. Commit your changes:

       git commit -m 'Add some feature'

4. Push to the branch:

       git push origin feature/your-feature-name

5. Open a pull request.

## 📄 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Thanks to the **RagnaTales** community for inspiring this tool.
- Special thanks to the developers of the [`rich`](https://github.com/Textualize/rich) library for the awesome console UI components.

## 📧 Contact

For any questions or suggestions, feel free to reach out:

- **Email**: your.email@example.com
- **Discord**: YourDiscordUsername#1234

---

*Happy gaming and may you always have the best connection!*

# 📌 Additional Notes

- **Network Traffic**: Be cautious when running this tool, as it generates continuous network traffic through ping and traceroute commands.
- **Windows Compatibility**: The script is optimized for Windows due to the use of `msvcrt` for capturing key presses and `netsh` for detecting the connection type.
- **Dependencies**: Ensure all dependencies are installed properly to avoid any runtime errors.

# ⭐ Star the Repository

If you find this tool helpful, please give the repository a ⭐ star ⭐ to show your support!

---

*This README was generated to provide a comprehensive overview of the Proxy Performance Monitor. Enjoy a lag-free gaming experience!*
