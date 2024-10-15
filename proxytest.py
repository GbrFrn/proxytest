import subprocess
import threading
import re
import time
import statistics
import sys
import socket
import msvcrt  # For key capture on Windows
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich import box
from rich.columns import Columns
from rich.align import Align
from collections import defaultdict, deque
from rich.spinner import Spinner
from rich import print as rprint

console = Console()

# Hardcoded descriptions for specific proxies
proxy_descriptions = {
    "proxy0.ragnatales.com.br": {
        "display_name": "Proxy 0 - Brasil",
        "description": "Rota Principal, mais próximo do servidor dedicado."
    },
    "proxy1.ragnatales.com.br": {
        "display_name": "Proxy 1 - Global",
        "description": "Rede Anycast protegida contra DDoS."
    },
    "proxy2.ragnatales.com.br": {
        "display_name": "Proxy 2 - Brasil",
        "description": "Rota alternativa, VPS hospedado em São Paulo."
    },
    "proxy3.ragnatales.com.br": {
        "display_name": "Proxy 3 - Brasil",
        "description": "Rota alternativa, VPS hospedado em São Paulo."
    },
    "proxy4.ragnatales.com.br": {
        "display_name": "Proxy 4 - EUA Miami",
        "description": "Rota Internacional, VPS hospedado em Miami."
    },
    "proxy5.ragnatales.com.br": {
        "display_name": "Proxy 5 - Canadá",
        "description": "Rota Internacional, VPS hospedado no Canadá."
    },
    "proxy6.ragnatales.com.br": {
        "display_name": "Proxy 6 - Brasil",
        "description": "Rota alternativa, VPS hospedado em São Paulo."
    }
}

# Function to dynamically discover proxies up to proxy20, filtering out those with less than 2ms ping
def get_proxies():
    proxies = []
    for i in range(0, 21):
        hostname = f"proxy{i}.ragnatales.com.br"
        try:
            # Attempt to resolve the hostname
            addr = socket.gethostbyname(hostname)
            # Ping once to check response time
            if sys.platform == 'win32':
                cmd = ['ping', '-n', '1', '-w', '1000', hostname]
            else:
                cmd = ['ping', '-c', '1', '-W', '1', hostname]
            result = subprocess.run(cmd, capture_output=True, text=True)
            # Extract ping time
            if sys.platform == 'win32':
                ping_time_match = re.search(r'(?:Tempo|Time)[=<]?\s*([\d\.]+)ms', result.stdout, re.IGNORECASE)
            else:
                ping_time_match = re.search(r'time=([\d\.]+) ms', result.stdout)
            if ping_time_match:
                ping_time = float(ping_time_match.group(1))
                if ping_time >= 2.0:
                    # Add to the proxies list
                    display_name = f"Proxy {i}"
                    description = f"Proxy {i} description"
                    if hostname in proxy_descriptions:
                        display_name = proxy_descriptions[hostname]["display_name"]
                        description = proxy_descriptions[hostname]["description"]
                    proxy = {
                        "hostname": hostname,
                        "display_name": display_name,
                        "description": description
                    }
                    proxies.append(proxy)
                else:
                    continue
            else:
                continue
        except (socket.gaierror, subprocess.CalledProcessError):
            continue
    return proxies

proxies = get_proxies()

# Metrics now store timestamped ping times and results for time window analysis
metrics = defaultdict(lambda: {
    "PingTimes": deque(),       # Deque of (timestamp, ping_time)
    "PingResults": deque(),     # Deque of (timestamp, success)
    "JitterValues": deque(),    # Deque of jitter values over extended period
    "Hops": None
})

# Lock for thread-safe updates
lock = threading.Lock()
traceroute_lock = threading.Lock()

# Event to signal threads to stop
stop_event = threading.Event()

# Global variables
latest_results = []
traceroute_output = ""
best_proxy_hostname = None

# Function to colorize metrics
def colorize_metric(value, thresholds):
    if value is None:
        return "[red]N/A[/red]"
    if value <= thresholds[0]:
        return f"[green]{value:.2f}[/green]"
    elif value <= thresholds[1]:
        return f"[yellow]{value:.2f}[/yellow]"
    else:
        return f"[red]{value:.2f}[/red]"

# Function to create a proxy metrics table
def create_proxy_table(result):
    table = Table(box=None, expand=True, show_header=False)
    if "Error" in result or result['AvgPing'] is None:
        table.add_row(f"[red]Nenhum dado disponível.[/red]")
    else:
        avg_ping = colorize_metric(result['AvgPing'], [50, 100])
        packet_loss = colorize_metric(result['PacketLoss'], [1, 5])
        jitter = colorize_metric(result['Jitter'], [5, 10])
        jitter_var = colorize_metric(result['JitterVariation'], [2, 5])
        hops = result.get('Hops')
        if hops is None:
            hops_text = "[italic](em execução)[/italic]"
        else:
            hops_text = f"{hops}"
        table.add_row("Ping Médio:", f"{avg_ping} ms")
        table.add_row("Ping Mínimo:", f"{result['MinPing']:.2f} ms")
        table.add_row("Ping Máximo:", f"{result['MaxPing']:.2f} ms")
        table.add_row("Perda de Pacotes:", f"{packet_loss}%")
        table.add_row("Jitter:", f"{jitter} ms")
        table.add_row("Var. do Jitter:", f"{jitter_var} ms")
        table.add_row("Número de Saltos:", hops_text)
    return table

# Function to create a summary table
def create_summary_table(results):
    table = Table(box=box.SIMPLE, show_edge=False)
    table.add_column("Proxy", style="bold", width=25)
    table.add_column("Ping Médio (ms)", justify="right")
    table.add_column("Perda de Pacotes (%)", justify="right")
    table.add_column("Jitter (ms)", justify="right")
    table.add_column("Jit.Var. (ms)", justify="right")
    table.add_column("Saltos", justify="right")
    table.add_column("Score", justify="right")

    for result in results:
        if "Error" in result or result['AvgPing'] is None:
            avg_ping = packet_loss = jitter = hops = score = jitter_var = "[red]N/A[/red]"
        else:
            avg_ping = f"{result['AvgPing']:.2f}"
            packet_loss = f"{result['PacketLoss']:.2f}"
            jitter = f"{result['Jitter']:.2f}"
            jitter_var = f"{result['JitterVariation']:.2f}"
            hops = str(result['Hops']) if result['Hops'] is not None else "[italic](em exec.)[/italic]"
            score = f"{result['Score']:.2f}"
        table.add_row(
            result['DisplayName'],
            avg_ping,
            packet_loss,
            jitter,
            jitter_var,
            hops,
            score
        )
    return table

# Function to create the main layout
def create_layout():
    layout = Layout()
    layout.split(
        Layout(name="header", size=4),
        Layout(name="body"),
        Layout(name="footer", size=1),
    )
    layout["body"].split_row(
        Layout(name="main", ratio=3),
        Layout(name="right", ratio=2)
    )
    layout["main"].split_column(
        Layout(name="proxies"),
        Layout(name="summary", size=12)
    )
    layout["right"].split_column(
        Layout(name="best_proxy", ratio=2),
        Layout(name="info", ratio=1)
    )
    return layout

# Function to update the layout with proxy results
def update_layout(layout, results, best_proxy_hostname, connection_type, wifi_detected, elapsed_time):
    header_text = f"[bold magenta]Monitor de Desempenho de Proxies[/bold magenta]\n[cyan]Tipo de Conexão: {connection_type}[/cyan]"
    if wifi_detected:
        header_text += "\n[bold red]Conexão via Wi-Fi detectada, por favor, utilize sempre uma conexão via cabo para jogar no RagnaTales[/bold red]"
    layout["header"].update(Align.center(header_text, vertical="middle"))
    layout["footer"].update(Align.center(f"Pressione 's' para salvar os resultados | Pressione 'q' para sair", vertical="middle"))

    # Create a panel for each proxy
    proxy_panels = []
    for proxy in proxies:
        hostname = proxy['hostname']
        display_name = proxy['display_name']
        description = proxy['description']
        result = next((r for r in results if r["Proxy"] == hostname), None)
        if result:
            proxy_table = create_proxy_table(result)
            panel_content = proxy_table
            # Include description in panel content
            description_text = Text(description, style="italic")
            panel_content = Table.grid(expand=True)
            panel_content.add_row(proxy_table)
            panel_content.add_row(description_text)
        else:
            spinner = Spinner("dots", text=" Testando...")
            panel_content = Align.center(spinner, vertical="middle")

        panel = Panel(
            panel_content,
            title=f"[bold]{display_name}[/bold]",
            border_style="green" if best_proxy_hostname == hostname else "white",
            padding=(0, 1),
            expand=True
        )
        proxy_panels.append(panel)

    # Display proxies in columns
    proxies_columns = Columns(proxy_panels, equal=True, expand=True)
    layout["proxies"].update(proxies_columns)

    # Update summary panel
    summary_table = create_summary_table(results)
    layout["summary"].update(Panel(summary_table, title="[bold]Resumo[/bold]", border_style="cyan", expand=True))

    # Update best proxy panel
    if elapsed_time < 30:
        seconds_left = int(30 - elapsed_time)
        spinner = Spinner("dots", text=f" Testando sua conexão, aguarde {seconds_left} segundos...")
        best_panel_content = Align.center(spinner, vertical="middle")
        layout["best_proxy"].update(Panel(
            best_panel_content,
            title=f"[bold yellow]Analisando Proxies[/bold yellow]",
            border_style="yellow",
            padding=(1, 2),
            expand=True
        ))
    else:
        if best_proxy_hostname:
            result = next(r for r in results if r["Proxy"] == best_proxy_hostname)
            best_proxy_table = create_proxy_table(result)
            best_proxy_display_name = result['DisplayName']
            best_proxy_description = result['Description']
            # Include description and traceroute output in panel content
            best_panel_content = Table.grid(expand=True)
            best_panel_content.add_row(best_proxy_table)
            best_panel_content.add_row(Text(best_proxy_description, style="italic"))

            # Get traceroute output
            with traceroute_lock:
                traceroute_text = traceroute_output.strip()

            if traceroute_text:
                # Traceroute statistics
                traceroute_table = Table(box=box.MINIMAL_DOUBLE_HEAD)
                traceroute_table.add_column("Hop", justify="right")
                traceroute_table.add_column("IP", justify="left")
                traceroute_table.add_column("AvgPing (ms)", justify="right")
                traceroute_table.add_column("Perda (%)", justify="right")
                for line in traceroute_text.splitlines():
                    parts = line.split('\t')
                    if len(parts) == 4:
                        hop, ip, avg_ping_str, packet_loss_str = parts
                        traceroute_table.add_row(hop, ip, avg_ping_str.split(': ')[1], packet_loss_str.split(': ')[1])
                traceroute_section = traceroute_table
            else:
                spinner = Spinner("dots", text=" Traceroute em execução...")
                traceroute_section = Align.center(spinner, vertical="middle")

            best_panel_content.add_row(Text("\nResultado do Traceroute:", style="bold underline"))
            best_panel_content.add_row(traceroute_section)

            layout["best_proxy"].update(Panel(
                best_panel_content,
                title=f"[bold green]Melhor Proxy: {best_proxy_display_name}[/bold green]",
                border_style="bright_green",
                padding=(1, 2),
                expand=True
            ))
        else:
            layout["best_proxy"].update(Panel(
                "[red]Nenhum dado de proxy válido disponível[/red]",
                title="[bold red]Melhor Proxy[/bold red]",
                border_style="red",
                padding=(1, 2),
                expand=True
            ))

    # Update info panel with explanations
    info_text = Text()
    info_text.append("Explicação das métricas:\n", style="bold underline")
    info_text.append("- Ping: Tempo para enviar e receber um pacote. Quanto menor, melhor.\n")
    info_text.append("- Perda de Pacotes: Indica instabilidade ou perda de conexão.\n")
    info_text.append("- Jitter: Variação no tempo de resposta. Valores altos podem indicar instabilidade.\n")
    info_text.append("- Var. do Jitter: Variação do jitter ao longo do tempo. Valores altos indicam instabilidade prolongada.\n")
    info_text.append("- Número de Saltos: Quantidade de roteadores entre você e o servidor.\n")
    info_text.append("- Score: Métrica composta que avalia o desempenho geral do proxy. Quanto menor, melhor.\n")
    info_text.append("- Traceroute: Roteadores pelos quais os pacotes passaram até o destino.\n")

    layout["info"].update(Panel(info_text, title="[bold]Informações[/bold]", border_style="blue", padding=(1, 2), expand=True))

# Function to save results to a file, including the winner proxy and traceroute
def save_results(results, best_proxy_hostname, traceroute_output):
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = f"resultados_proxies_{timestamp}.txt"
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("===== Resultados dos Proxies =====\n\n")
        for result in results:
            f.write(f"Proxy: {result['DisplayName']}\n")
            if "Error" in result or result['AvgPing'] is None:
                f.write(f"  Erro: Nenhum dado disponível.\n")
            else:
                f.write(f"  Ping Médio: {result['AvgPing']:.2f} ms\n")
                f.write(f"  Ping Mínimo: {result['MinPing']:.2f} ms\n")
                f.write(f"  Ping Máximo: {result['MaxPing']:.2f} ms\n")
                f.write(f"  Perda de Pacotes: {result['PacketLoss']:.2f}%\n")
                f.write(f"  Jitter: {result['Jitter']:.2f} ms\n")
                f.write(f"  Var. do Jitter: {result['JitterVariation']:.2f} ms\n")
                f.write(f"  Número de Saltos: {result['Hops']}\n")
                f.write(f"  Score: {result['Score']:.2f}\n")
            f.write("\n")
        if best_proxy_hostname:
            best_result = next(r for r in results if r["Proxy"] == best_proxy_hostname)
            f.write("===== Melhor Proxy =====\n\n")
            f.write(f"Proxy: {best_result['DisplayName']}\n")
            f.write(f"Descrição: {best_result['Description']}\n")
            f.write(f"Ping Médio: {best_result['AvgPing']:.2f} ms\n")
            f.write(f"Perda de Pacotes: {best_result['PacketLoss']:.2f}%\n")
            f.write(f"Jitter: {best_result['Jitter']:.2f} ms\n")
            f.write(f"Var. do Jitter: {best_result['JitterVariation']:.2f} ms\n")
            f.write(f"Número de Saltos: {best_result['Hops']}\n")
            f.write(f"Score: {best_result['Score']:.2f}\n\n")
            f.write("===== Traceroute do Melhor Proxy =====\n\n")
            f.write(traceroute_output)
        else:
            f.write("Nenhum melhor proxy determinado.\n")
    console.print(f"[green]Resultados salvos em {filename}[/green]")

# Function to check user input
def check_user_input():
    if sys.platform == 'win32':
        if msvcrt.kbhit():
            key = msvcrt.getch().decode('utf-8', errors='ignore').lower()
            if key == 'q':
                stop_event.set()
            elif key == 's':
                with lock, traceroute_lock:
                    current_results = list(latest_results)
                    current_best_proxy_hostname = best_proxy_hostname
                    current_traceroute_output = traceroute_output
                save_results(current_results, current_best_proxy_hostname, current_traceroute_output)
    else:
        # Implement for Unix/Linux if necessary
        pass

# Function to get number of hops from traceroute
def get_number_of_hops(hostname):
    if sys.platform == 'win32':
        cmd = ['tracert', '-d', '-h', '30', '-w', '1000', hostname]
    else:
        cmd = ['traceroute', '-n', '-m', '30', '-w', '1', hostname]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout
        hops = 0
        for line in output.splitlines():
            if re.match(r'^\s*\d+', line):
                hops += 1
        return hops if hops > 0 else None
    except Exception as e:
        return None

# Function to update hops for a single proxy asynchronously
def update_hops_for_proxy(proxy):
    hostname = proxy['hostname']
    while not stop_event.is_set():
        hops = get_number_of_hops(hostname)
        with lock:
            metrics[hostname]['Hops'] = hops
        time.sleep(60)  # Update every 60 seconds

# Function to start hops update threads for each proxy
def start_hops_update_threads():
    for proxy in proxies:
        t = threading.Thread(target=update_hops_for_proxy, args=(proxy,), daemon=True)
        t.start()

# Function to get the connection type
def get_connection_type():
    if sys.platform != 'win32':
        return 'Tipo de conexão desconhecido', False  # Second value indicates whether Wi-Fi is detected

    try:
        result = subprocess.run(['netsh', 'interface', 'show', 'interface'], capture_output=True, text=True)
        output = result.stdout
        lines = output.strip().split('\n')
        # Skip lines until we reach the separator line
        start_index = None
        for i, line in enumerate(lines):
            if re.match(r'^-+$', line.strip()):
                start_index = i + 1
                break
        if start_index is None:
            return 'Tipo de conexão desconhecido', False

        ethernet_connected = False
        wifi_connected = False

        for line in lines[start_index:]:
            columns = re.split(r'\s{2,}', line.strip())
            if len(columns) >= 4:
                admin_state, state, interface_type, interface_name = columns
                state = state.strip().lower()
                interface_type = interface_type.strip().lower()
                interface_name = interface_name.strip().lower()
                if state == 'conectado' or state == 'connected':
                    if 'ethernet' in interface_name:
                        ethernet_connected = True
                    elif 'wi-fi' in interface_name or 'wireless' in interface_name:
                        wifi_connected = True

        if ethernet_connected:
            return 'Cabo', False
        elif wifi_connected:
            return 'Wi-Fi', True
        else:
            return 'Tipo de conexão desconhecido', False
    except Exception as e:
        return 'Tipo de conexão desconhecido', False

# Function for continuous pinging
def continuous_ping(proxy):
    hostname = proxy['hostname']
    while not stop_event.is_set():
        try:
            # Adjust 'ping' command for Windows or Unix-like systems
            if sys.platform == 'win32':
                cmd = ['ping', '-n', '1', '-w', '1000', hostname]
            else:
                cmd = ['ping', '-c', '1', '-W', '1', hostname]
            result = subprocess.run(cmd, capture_output=True, text=True)

            # Extract ping time
            if sys.platform == 'win32':
                # Match 'Time=' in English or 'Tempo=' in Portuguese
                ping_time_match = re.search(r'(?:Tempo|Time)[=<]?\s*([\d\.]+)ms', result.stdout, re.IGNORECASE)
            else:
                ping_time_match = re.search(r'time=([\d\.]+) ms', result.stdout)

            timestamp = time.time()

            with lock:
                if ping_time_match:
                    ping_time = float(ping_time_match.group(1))
                    metrics[hostname]["PingTimes"].append((timestamp, ping_time))
                    metrics[hostname]["PingResults"].append((timestamp, True))
                else:
                    metrics[hostname]["PingResults"].append((timestamp, False))

                # Remove old entries beyond maximum history duration
                remove_old_entries(metrics[hostname]["PingTimes"], 300)  # 5 minutes for ping times
                remove_old_entries(metrics[hostname]["PingResults"], 300)  # 5 minutes for results

        except Exception as e:
            timestamp = time.time()
            with lock:
                metrics[hostname]["PingResults"].append((timestamp, False))
                # Remove old entries
                remove_old_entries(metrics[hostname]["PingResults"], 300)
        time.sleep(0.5)  # Adjust the sleep time as needed

def remove_old_entries(deque_obj, max_duration):
    current_time = time.time()
    while deque_obj and (current_time - deque_obj[0][0] > max_duration):
        deque_obj.popleft()

# Class to monitor traceroute continuously like WinMTR
class TracerouteMonitor:
    def __init__(self, hostname):
        self.hostname = hostname
        self.hops = []  # List of hops, each hop is a dict with 'ip' and 'metrics'
        self.ping_threads = []
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.run_traceroute()
        self.start_monitoring()

    def run_traceroute(self):
        # Run traceroute and parse the output to get the list of hops
        if sys.platform == 'win32':
            cmd = ['tracert', '-d', '-h', '30', '-w', '1000', self.hostname]
        else:
            cmd = ['traceroute', '-n', '-m', '30', '-w', '1', self.hostname]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = result.stdout
            hops = []
            for line in output.splitlines():
                if sys.platform == 'win32':
                    # Windows tracert output parsing
                    # Example line: 1     2 ms     1 ms     1 ms  192.168.0.1
                    match = re.match(r'^\s*(\d+)\s+(?:\d+ ms|\*)\s+(?:\d+ ms|\*)\s+(?:\d+ ms|\*)\s+([\d\.]+)', line)
                    if match:
                        ip = match.group(2)
                        hops.append({'ip': ip, 'metrics': {'PingTimes': deque(), 'PingResults': deque()}})
                else:
                    # Unix traceroute output parsing
                    # Example line: 1  192.168.0.1  1.123 ms  0.987 ms  0.876 ms
                    match = re.match(r'^\s*(\d+)\s+([\d\.]+)\s+.*', line)
                    if match:
                        ip = match.group(2)
                        hops.append({'ip': ip, 'metrics': {'PingTimes': deque(), 'PingResults': deque()}})
            self.hops = hops
        except Exception as e:
            print(f"Error running traceroute: {e}")

    def start_monitoring(self):
        for hop in self.hops:
            t = threading.Thread(target=self.continuous_ping, args=(hop,), daemon=True)
            t.start()
            self.ping_threads.append(t)

    def continuous_ping(self, hop):
        ip = hop['ip']
        while not self.stop_event.is_set():
            try:
                if sys.platform == 'win32':
                    cmd = ['ping', '-n', '1', '-w', '1000', ip]
                else:
                    cmd = ['ping', '-c', '1', '-W', '1', ip]
                result = subprocess.run(cmd, capture_output=True, text=True)

                # Extract ping time
                if sys.platform == 'win32':
                    ping_time_match = re.search(r'(?:Tempo|Time)[=<]?\s*([\d\.]+)ms', result.stdout, re.IGNORECASE)
                else:
                    ping_time_match = re.search(r'time=([\d\.]+) ms', result.stdout)

                timestamp = time.time()

                with self.lock:
                    if ping_time_match:
                        ping_time = float(ping_time_match.group(1))
                        hop['metrics']['PingTimes'].append((timestamp, ping_time))
                        hop['metrics']['PingResults'].append((timestamp, True))
                    else:
                        hop['metrics']['PingResults'].append((timestamp, False))

                    # Remove old entries
                    remove_old_entries(hop['metrics']['PingTimes'], 30)  # 30 seconds for traceroute hops
                    remove_old_entries(hop['metrics']['PingResults'], 30)

            except Exception as e:
                timestamp = time.time()
                with self.lock:
                    hop['metrics']['PingResults'].append((timestamp, False))
                    remove_old_entries(hop['metrics']['PingResults'], 30)
            time.sleep(1)  # Adjust the sleep time as needed

    def stop(self):
        self.stop_event.set()
        for t in self.ping_threads:
            t.join()

    def get_statistics(self):
        # Returns the current statistics for each hop
        current_time = time.time()
        time_window = 30  # seconds
        stats = []
        with self.lock:
            for idx, hop in enumerate(self.hops):
                ip = hop['ip']
                ping_times = [(t, pt) for t, pt in hop['metrics']['PingTimes'] if current_time - t <= time_window]
                ping_results = [(t, success) for t, success in hop['metrics']['PingResults'] if current_time - t <= time_window]

                total_pings = len(ping_results)
                if total_pings == 0:
                    continue  # Skip hops with no data yet

                lost_pings = sum(1 for t, success in ping_results if not success)
                successful_pings = total_pings - lost_pings

                packet_loss = (lost_pings / total_pings) * 100

                ping_values = [pt for t, pt in ping_times]
                if successful_pings == 0:
                    avg_ping = None
                else:
                    avg_ping = statistics.mean(ping_values)

                hop_stats = {
                    'Hop': idx + 1,
                    'IP': ip,
                    'AvgPing': avg_ping,
                    'PacketLoss': packet_loss,
                }
                stats.append(hop_stats)
        return stats

# Function to manage traceroute execution
def traceroute_manager():
    global traceroute_output
    last_best_proxy_hostname = None
    traceroute_monitor = None
    while not stop_event.is_set():
        if best_proxy_hostname != last_best_proxy_hostname:
            if traceroute_monitor:
                traceroute_monitor.stop()
            if best_proxy_hostname:
                traceroute_monitor = TracerouteMonitor(best_proxy_hostname)
            last_best_proxy_hostname = best_proxy_hostname
        else:
            if traceroute_monitor:
                stats = traceroute_monitor.get_statistics()
                # Format the stats into traceroute_output
                output_lines = []
                for hop_stats in stats:
                    hop = hop_stats['Hop']
                    ip = hop_stats['IP']
                    avg_ping = f"{hop_stats['AvgPing']:.2f} ms" if hop_stats['AvgPing'] is not None else '*'
                    packet_loss = f"{hop_stats['PacketLoss']:.2f}%" if hop_stats['PacketLoss'] is not None else '*'
                    output_lines.append(f"{hop}\t{ip}\tAvgPing: {avg_ping}\tPacketLoss: {packet_loss}")
                with traceroute_lock:
                    traceroute_output = '\n'.join(output_lines)
        time.sleep(1)

# Function to run tests continuously
def run_tests_continuously():
    global latest_results
    global traceroute_output
    global best_proxy_hostname
    latest_results = []
    traceroute_output = ""
    best_proxy_hostname = None
    layout = create_layout()
    connection_type, wifi_detected = get_connection_type()

    start_time = time.time()

    # Start continuous ping threads for each proxy
    threads = []
    for proxy in proxies:
        t = threading.Thread(target=continuous_ping, args=(proxy,), daemon=True)
        t.start()
        threads.append(t)

    # Start hops update threads for each proxy
    start_hops_update_threads()

    # Start traceroute manager thread
    traceroute_thread = threading.Thread(target=traceroute_manager, daemon=True)
    traceroute_thread.start()

    with Live(layout, refresh_per_second=1, screen=True) as live:
        while not stop_event.is_set():
            results = []
            current_time = time.time()
            elapsed_time = current_time - start_time
            time_window = 30  # seconds
            jitter_variation_window = 300  # 5 minutes
            with lock:
                for proxy in proxies:
                    hostname = proxy['hostname']
                    display_name = proxy['display_name']
                    description = proxy['description']
                    metric = metrics[hostname]
                    ping_times = [(t, pt) for t, pt in metric["PingTimes"] if current_time - t <= time_window]
                    ping_results = [(t, success) for t, success in metric["PingResults"] if current_time - t <= time_window]
                    hops = metric.get('Hops', None)

                    total_pings = len(ping_results)
                    if total_pings == 0:
                        continue  # Skip proxies with no data yet

                    lost_pings = sum(1 for t, success in ping_results if not success)
                    successful_pings = total_pings - lost_pings

                    packet_loss = (lost_pings / total_pings) * 100

                    ping_values = [pt for t, pt in ping_times]
                    if successful_pings == 0:
                        avg_ping = None
                        min_ping = None
                        max_ping = None
                        jitter = None
                        jitter_variation = None
                        score = None
                    else:
                        avg_ping = statistics.mean(ping_values)
                        min_ping = min(ping_values)
                        max_ping = max(ping_values)
                        jitter = statistics.stdev(ping_values) if len(ping_values) > 1 else 0

                        # Calculate jitter variation over extended period
                        jitter_values = metric['JitterValues']
                        # Update jitter_values with current jitter
                        jitter_values.append((current_time, jitter))
                        # Remove old entries
                        remove_old_entries(jitter_values, jitter_variation_window)
                        jitter_values_list = [j for t, j in jitter_values]
                        if len(jitter_values_list) > 1:
                            jitter_variation = statistics.stdev(jitter_values_list)
                        else:
                            jitter_variation = 0

                        hops_value = hops if hops is not None else 30  # Assume max hops if unknown
                        packet_loss_value = packet_loss

                        # Compute the score, including jitter variation
                        score = avg_ping + jitter + (hops_value * 5) + (packet_loss_value * 500) + (jitter_variation * 10)

                    result_data = {
                        "Proxy": hostname,
                        "AvgPing": avg_ping,
                        "MinPing": min_ping,
                        "MaxPing": max_ping,
                        "PacketLoss": packet_loss,
                        "Jitter": jitter,
                        "JitterVariation": jitter_variation,
                        "DisplayName": display_name,
                        "Description": description,
                        "Hops": hops,
                        "Score": score
                    }
                    results.append(result_data)

                latest_results = results.copy()

            if elapsed_time >= 30:
                valid_results = [r for r in results if r.get('Score') is not None]
                if valid_results:
                    new_best_proxy = min(valid_results, key=lambda x: x['Score'])
                    new_best_proxy_hostname = new_best_proxy['Proxy']
                else:
                    new_best_proxy = None
                    new_best_proxy_hostname = None

                if new_best_proxy_hostname != best_proxy_hostname:
                    best_proxy_hostname = new_best_proxy_hostname
            else:
                best_proxy_hostname = None

            update_layout(layout, results, best_proxy_hostname, connection_type, wifi_detected, elapsed_time)
            live.refresh()

            # Check user input
            check_user_input()
            time.sleep(1)

    console.print("[bold red]Programa terminado pelo usuário.[/bold red]")

if __name__ == "__main__":
    try:
        run_tests_continuously()
    except KeyboardInterrupt:
        stop_event.set()
        console.print("[bold red]Programa terminado pelo usuário.[/bold red]")
