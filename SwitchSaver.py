import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import paramiko
import os
import re
import csv
import threading
import queue  # Used for thread-safe communication with the GUI
import time
import base64  # NEW: Needed for host key fingerprinting
import socket


# NEW: Custom host key policy to interact with the GUI
class GUIMissingHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """
    A custom policy that prompts the user via the GUI when a host key is unknown.
    """

    def __init__(self, app_instance):
        self.app = app_instance

    def missing_host_key(self, client, hostname, key):
        # If user has already selected "Accept All", don't prompt again.
        if self.app.accept_all_keys_session:
            return

        # Get a human-readable fingerprint for the key
        fingerprint = base64.b64encode(key.get_fingerprint()).decode('utf-8')

        # Clear the event and response holder before making a new request
        self.app.host_key_event.clear()
        self.app.host_key_response = None

        # Send the verification request to the main GUI thread via the queue
        self.app.q.put(('host_key_verification', hostname, fingerprint))

        # Wait here until the main thread signals that the user has made a choice
        self.app.host_key_event.wait()

        # Process the user's choice
        if self.app.host_key_response == 'accept_all':
            self.app.accept_all_keys_session = True  # Set the flag for the rest of the session
            print(f"Accepted and caching decision for all subsequent hosts in this session.")
            return  # Accept the key
        elif self.app.host_key_response == 'accept_once':
            print(f"Accepted host key for {hostname} for this connection only.")
            return  # Accept the key
        else:  # 'reject' or None
            print(f"Rejected host key for {hostname}.")
            # Raising an exception is how we tell paramiko to reject the connection
            raise paramiko.SSHException(f"Host key for {hostname} not accepted by user.")


class SwitchSaverApp:
    """
    An object-oriented approach to the Switch Saver application.
    This encapsulates all GUI elements and logic, avoiding global variables.
    """

    def __init__(self, root):
        self.root = root
        self.file_path = None
        self.output_directory = tk.StringVar(value=os.path.join(os.path.expanduser('~'), 'Desktop', 'Switch_Backups'))

        # NEW: Threading and state management for host key verification
        self.host_key_event = threading.Event()
        self.host_key_response = None  # Will be 'accept_once', 'accept_all', or 'reject'
        self.accept_all_keys_session = False

        # Check if the default output directory exists, if not, create it
        if not os.path.exists(self.output_directory.get()):
            os.makedirs(self.output_directory.get())

        self.main_menu()

    def main_menu(self):
        self.root.title("Switch Saver 2.0 - Cisco Switches")
        self.root.minsize(400, 300)

        # Clear any existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()

        menu_frame = ttk.Frame(self.root, padding="30")
        menu_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        ttk.Button(menu_frame, text="Run SSH Bot", command=self.run_ssh_bot_ui).pack(pady=15, fill=tk.X)
        ttk.Button(menu_frame, text="Generate CDP Neighbors CSV",
                   command=lambda: self._generate_csv_from_folder(self.extract_cdp_info, "CDP Neighbor")).pack(pady=15,
                                                                                                               fill=tk.X)
        ttk.Button(menu_frame, text="Generate Serial Number CSV",
                   command=lambda: self._generate_csv_from_folder(self.extract_serial_info, "Serial Number")).pack(
            pady=15, fill=tk.X)

        # Add a small spacer
        ttk.Label(menu_frame, text="").pack(pady=5)  # Adds a bit of vertical space
        # Add the author label
        author_label = ttk.Label(menu_frame, text="Created by: Cristian Pardo Pardostech.com", font=("Helvetica", 10, "italic"))
        author_label.pack(pady=(10, 0), fill=tk.X)  # pady=(top, bottom)
        # --- END OF NAME ADDITION ---

    def run_ssh_bot_ui(self):
        # Clear any existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()

        self.root.title("Switch Saver (SSH Mode)")

        ssh_frame = ttk.Frame(self.root, padding="10 10 10 10")
        ssh_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # --- IP Input Method Selection ---
        self.ip_input_method = tk.StringVar(value="file")
        ip_method_frame = ttk.LabelFrame(ssh_frame, text="IP Input Method", padding="5")
        ip_method_frame.grid(row=0, column=0, columnspan=3, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        ttk.Radiobutton(ip_method_frame, text="IP File", variable=self.ip_input_method, 
                       value="file", command=self._toggle_ip_input).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(ip_method_frame, text="Single IP", variable=self.ip_input_method,
                       value="single", command=self._toggle_ip_input).pack(side=tk.LEFT, padx=5)

        # --- File Input Frame ---
        self.file_frame = ttk.Frame(ssh_frame)
        self.file_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E))
        
        self.file_label = ttk.Label(self.file_frame, text="No IP file chosen")
        ttk.Button(self.file_frame, text="Choose IP Address File", command=self._open_file).pack(side=tk.LEFT, padx=5, pady=5)
        self.file_label.pack(side=tk.LEFT, padx=5, pady=5)

        # --- Single IP Input Frame ---
        self.single_ip_frame = ttk.Frame(ssh_frame)
        self.single_ip_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E))
        self.single_ip_frame.grid_remove()  # Initially hidden
        
        ttk.Label(self.single_ip_frame, text="IP Address:").pack(side=tk.LEFT, padx=5, pady=5)
        self.single_ip_entry = ttk.Entry(self.single_ip_frame, width=20)
        self.single_ip_entry.pack(side=tk.LEFT, padx=5, pady=5)

        # --- Rest of the UI Elements ---
        self.output_folder_entry = ttk.Entry(ssh_frame, textvariable=self.output_directory, width=40)
        ttk.Button(ssh_frame, text="Choose Output Folder", command=self._choose_output_folder).grid(row=2, column=0,
                                                                                                    padx=5, pady=5,
                                                                                                    sticky=tk.W)
        self.output_folder_entry.grid(row=2, column=1, columnspan=2, padx=5, pady=5, sticky=(tk.W, tk.E))

        self.user_entry = ttk.Entry(ssh_frame)
        self.password_entry = ttk.Entry(ssh_frame, show="*")
        ttk.Label(ssh_frame, text="Username:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.E)
        self.user_entry.grid(row=3, column=1, padx=5, pady=5, sticky=(tk.W, tk.E))
        ttk.Label(ssh_frame, text="Password:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.E)
        self.password_entry.grid(row=4, column=1, padx=5, pady=5, sticky=(tk.W, tk.E))

        command_options = ["show running-config", "show cdp neighbors detail", "show version", "Custom Command"]
        self.command_combobox = ttk.Combobox(ssh_frame, values=command_options, state="readonly")
        self.command_combobox.set(command_options[0])
        self.command_combobox.bind("<<ComboboxSelected>>", self._on_command_selected)
        ttk.Label(ssh_frame, text="Command:").grid(row=5, column=0, padx=5, pady=5, sticky=tk.E)
        self.command_combobox.grid(row=5, column=1, padx=5, pady=5, sticky=(tk.W, tk.E))

        self.custom_command_label = ttk.Label(ssh_frame, text="Custom Commands (one per line):")
        self.custom_command_text = tk.Text(ssh_frame, height=5, width=40)

        self.execute_button = ttk.Button(ssh_frame, text="Execute SSH", command=self._start_ssh_thread)
        self.execute_button.grid(row=7, column=0, columnspan=2, pady=10)

        self.notebook = ttk.Notebook(ssh_frame)
        self.notebook.grid(row=8, column=0, columnspan=3, pady=5, padx=5, sticky='nsew')
        ssh_frame.rowconfigure(8, weight=1)
        ssh_frame.columnconfigure(1, weight=1)

        self.status_bar = ttk.Label(ssh_frame, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.grid(row=9, column=0, columnspan=3, sticky='ew')

        ttk.Button(ssh_frame, text="Return to Menu", command=self.main_menu).grid(row=10, column=0, columnspan=2,
                                                                                  pady=10)
        
        # Initialize the IP input method
        self._toggle_ip_input()

    def _toggle_ip_input(self):
        """Toggle between file input and single IP input frames."""
        if self.ip_input_method.get() == "file":
            self.file_frame.grid()
            self.single_ip_frame.grid_remove()
        else:
            self.file_frame.grid_remove()
            self.single_ip_frame.grid()

    def _open_file(self):
        self.file_path = filedialog.askopenfilename(title="Select IP Address File", filetypes=[("Text files", "*.txt")])
        if self.file_path:
            self.file_label.config(text=os.path.basename(self.file_path))

    def _choose_output_folder(self):
        folder_path = filedialog.askdirectory(title="Select Output Folder")
        if folder_path:
            self.output_directory.set(folder_path)

    def _on_command_selected(self, event=None):
        if self.command_combobox.get() == "Custom Command":
            self.custom_command_label.grid(row=6, column=0, padx=5, pady=5, sticky=tk.W)
            self.custom_command_text.grid(row=6, column=1, padx=5, pady=(5, 0), sticky=(tk.W, tk.E))
        else:
            self.custom_command_label.grid_forget()
            self.custom_command_text.grid_forget()

    def _start_ssh_thread(self):
        if self.ip_input_method.get() == "file":
            if not self.file_path:
                messagebox.showerror("Error", "Please choose an IP address file.")
                return
        else:
            ip = self.single_ip_entry.get().strip()
            if not ip:
                messagebox.showerror("Error", "Please enter an IP address.")
                return
            # Create a temporary file with the single IP
            self.file_path = os.path.join(self.output_directory.get(), "temp_ip.txt")
            with open(self.file_path, 'w') as f:
                f.write(ip)

        if not self.user_entry.get() or not self.password_entry.get():
            messagebox.showerror("Error", "Please enter a username and password.")
            return

        self.execute_button.config(state=tk.DISABLED)
        self.status_bar.config(text="Starting SSH process...")

        for tab in self.notebook.tabs():
            self.notebook.forget(tab)

        # NEW: Reset the session-wide "accept all" flag each time the process is started
        self.accept_all_keys_session = False

        self.q = queue.Queue()
        self.thread = threading.Thread(target=self._ssh_worker)
        self.thread.daemon = True
        self.thread.start()

        self.root.after_idle(self._process_queue)

    def _ssh_worker(self):
        """This function runs in a separate thread to avoid freezing the GUI."""
        user = self.user_entry.get()
        pwd = self.password_entry.get()
        selected_command_option = self.command_combobox.get()
        custom_commands_input = self.custom_command_text.get("1.0", tk.END).strip().splitlines()
        commands_to_run = custom_commands_input if selected_command_option == "Custom Command" else [
            selected_command_option]

        # MODIFIED: Instantiate our custom GUI policy handler
        gui_policy = GUIMissingHostKeyPolicy(self)

        with open(self.file_path, 'r') as file:
            ip_addresses = [line.strip() for line in file if line.strip()]

        for ip in ip_addresses:
            self.q.put(('status', f"Connecting to {ip}..."))
            ssh_client = None
            try:
                ssh_client = paramiko.SSHClient()
                # MODIFIED: Use our custom policy instead of AutoAddPolicy
                ssh_client.set_missing_host_key_policy(gui_policy)
                ssh_client.connect(ip, username=user, password=pwd, timeout=10, look_for_keys=False)

                shell = ssh_client.invoke_shell()
                shell.settimeout(6)  # Set a timeout for shell operations
                aggregated_output = ""
                self.q.put(('status', f"Setting terminal length on {ip}..."))
                shell.send("terminal length 0\n")
                time.sleep(0.5)
                initial_buffer = ""
                start_time = time.time()
                while time.time() - start_time < 6:  # 6 second timeout for initial setup
                    if shell.recv_ready():
                        initial_buffer += shell.recv(65535).decode('utf-8', 'ignore')
                        if initial_buffer.strip().endswith(('#', '>')):
                            break
                    elif not shell.active:
                        raise paramiko.SSHException("Shell became inactive during initial setup.")
                    time.sleep(0.1)
                else:
                    raise paramiko.SSHException("Timeout waiting for initial prompt")

                for cmd_index, current_cmd in enumerate(commands_to_run):
                    if not current_cmd.strip():
                        continue
                    self.q.put(('status', f"Executing on {ip}: {current_cmd[:30]}..."))
                    shell.send(current_cmd + "\n")
                    command_output_this_iteration = ""
                    start_time = time.time()
                    is_reload_command = current_cmd.strip().lower() == "reload"
                    
                    while time.time() - start_time < 6:  # 6 second timeout per command
                        if shell.recv_ready():
                            chunk = shell.recv(65535).decode('utf-8', 'ignore')
                            command_output_this_iteration += chunk
                            stripped_output = command_output_this_iteration.strip()
                            if stripped_output.endswith(('#', '>')):
                                last_line = stripped_output.split('\n')[-1].strip()
                                if (last_line.endswith('#') or last_line.endswith('>')) and \
                                        (len(stripped_output) > len(current_cmd) + 5 or current_cmd not in last_line):
                                    break
                        elif not shell.active:
                            self.q.put(('error', ip, f"Shell became inactive while executing: {current_cmd}"))
                            raise paramiko.SSHException("Shell inactive")
                        time.sleep(0.1)
                    else:
                        if is_reload_command:
                            # For reload command, just log the timeout but continue
                            self.q.put(('status', f"Device {ip} is reloading..."))
                        else:
                            self.q.put(('error', ip, f"Timeout executing command: {current_cmd}"))
                            raise paramiko.SSHException(f"Timeout executing command: {current_cmd}")

                    aggregated_output += command_output_this_iteration
                    if cmd_index < len(commands_to_run) - 1 and len(commands_to_run) > 1:
                        aggregated_output += f"\n--- End of output for '{current_cmd}' ---\n\n"

                final_output_for_ip = aggregated_output.strip()
                filename_command_part = selected_command_option.replace(' ', '_').replace('/', '_')
                filename = f"{ip}_{filename_command_part}.txt"
                filepath = os.path.join(self.output_directory.get(), filename)
                os.makedirs(self.output_directory.get(), exist_ok=True)
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(final_output_for_ip)
                self.q.put(('result', ip, final_output_for_ip))

            except paramiko.AuthenticationException:
                self.q.put(('error', ip, "Authentication failed. Please check credentials."))
            except paramiko.SSHException as e:
                self.q.put(('error', ip, f"SSH Error: {e}"))
            except socket.timeout:
                self.q.put(('error', ip, "Connection timed out. Please check network connectivity."))
            except Exception as e:
                self.q.put(('error', ip, f"An error occurred with {ip}: {e}"))
            finally:
                if ssh_client:
                    try:
                        ssh_client.close()
                    except:
                        pass

        self.q.put(('done', None))

    # NEW: A method to create the host key verification dialog
    def _prompt_for_host_key(self, hostname, fingerprint):
        dialog = tk.Toplevel(self.root)
        dialog.title("Host Key Verification")

        # Make the dialog modal
        dialog.transient(self.root)
        dialog.grab_set()

        # Center the dialog
        self.root.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (dialog.winfo_reqwidth() // 2)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (dialog.winfo_reqheight() // 2)
        dialog.geometry(f"+{x}+{y}")

        dialog.protocol("WM_DELETE_WINDOW", lambda: self._handle_host_key_response('reject', dialog))

        frame = ttk.Frame(dialog, padding="20")
        frame.pack(expand=True, fill=tk.BOTH)

        message = (f"The authenticity of host '{hostname}' can't be established.\n"
                   f"The host key fingerprint (sha256) is:\n{fingerprint}\n\n"
                   f"Are you sure you want to continue connecting?")
        ttk.Label(frame, text=message).pack(pady=10)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)

        # Define button commands to set response and signal the event
        ttk.Button(btn_frame, text="Accept All (Session)",
                   command=lambda: self._handle_host_key_response('accept_all', dialog)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Accept Once",
                   command=lambda: self._handle_host_key_response('accept_once', dialog)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Reject", command=lambda: self._handle_host_key_response('reject', dialog)).pack(
            side=tk.LEFT, padx=5)

        # Wait for the user to close the dialog
        self.root.wait_window(dialog)

    # NEW: A handler to process the dialog choice and unblock the worker thread
    def _handle_host_key_response(self, response, dialog):
        self.host_key_response = response
        self.host_key_event.set()  # Signal the worker thread to continue
        dialog.destroy()

    def _process_queue(self):
        """Processes messages from the worker thread's queue to update the GUI."""
        try:
            message = self.q.get_nowait()
            message_type = message[0]

            if message_type == 'status':
                self.status_bar.config(text=message[1])

            # MODIFIED: Handle the new host key verification message type
            elif message_type == 'host_key_verification':
                hostname, fingerprint = message[1], message[2]
                self.status_bar.config(text=f"Verifying host key for {hostname}...")
                self._prompt_for_host_key(hostname, fingerprint)

            elif message_type in ('result', 'error'):
                ip, content = message[1], message[2]
                frame = ttk.Frame(self.notebook)
                self.notebook.add(frame, text=ip)
                text_widget = tk.Text(frame, wrap=tk.WORD, height=20, width=80)
                text_widget.pack(padx=5, pady=5, expand=True, fill=tk.BOTH)
                text_widget.insert(tk.END, content)
                text_widget.config(state=tk.DISABLED)
                if message_type == 'error':
                    tab_id = self.notebook.tabs()[-1]
                    self.notebook.tab(tab_id, text=f"{ip} (Error)")

            elif message_type == 'done':
                self.status_bar.config(text="Process finished.")
                self.execute_button.config(state=tk.NORMAL)
                # Avoid showing this if the process was just rejecting a key
                if self.host_key_response != 'reject':
                    messagebox.showinfo("Finished", "All SSH operations have completed.")
                return

        except queue.Empty:
            pass
        except Exception as e:
            print(f"Error processing queue message: {e}")
            self.status_bar.config(text=f"GUI Error: {e}")

        self.root.after(100, self._process_queue)

    # --- CSV Generation Methods (Unchanged) ---
    # ... (the rest of your CSV methods remain here) ...
    def _generate_csv_from_folder(self, extractor_func, data_type):
        """
        REFACTORED: A single function to handle CSV generation.
        It takes a data extraction function and a data type name as arguments.
        """
        folder_path = filedialog.askdirectory(title=f"Select Folder with '{data_type}' Files")
        if not folder_path:
            messagebox.showwarning("Cancelled", "No folder selected.")
            return

        all_data = []
        for filename in os.listdir(folder_path):
            if filename.endswith('.txt'):
                file_path = os.path.join(folder_path, filename)
                data = extractor_func(file_path)
                if data:
                    all_data.extend(data)

        if not all_data:
            messagebox.showwarning("No Data", f"No valid {data_type} data found in the selected folder.")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
            title=f"Save {data_type} Data as CSV",
            initialfile=f"{data_type.replace(' ', '_')}_export.csv"
        )
        if not save_path:
            return

        try:
            with open(save_path, 'w', newline='') as csvfile:
                csv_writer = csv.writer(csvfile)
                # Write header based on the data type
                if extractor_func == self.extract_cdp_info:
                    csv_writer.writerow(
                        ['SourceHostname', 'SourceIP', 'SourcePort', 'DestinationHostname', 'DestinationPort',
                         'Platform'])
                elif extractor_func == self.extract_serial_info:
                    csv_writer.writerow(['Hostname', 'IP', 'SerialNumber'])
                csv_writer.writerows(all_data)
            messagebox.showinfo("Success", f"CSV file successfully generated: {save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while saving the CSV file: {e}")

    def extract_cdp_info(self, file_path):
        """Extracts CDP neighbor details from a 'show cdp neighbors detail' output file."""
        with open(file_path, 'r') as file:
            content = file.read()

        source_ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", os.path.basename(file_path))
        source_ip = source_ip_match.group(0) if source_ip_match else "N/A"

        # Get source hostname from the prompt at the end of the file
        source_hostname_match = re.search(r'\n([\w\d.-]+)#\s*$', content)
        source_hostname = source_hostname_match.group(1) if source_hostname_match else "N/A"

        neighbors = []
        # Split the output by '-------------------------' which separates neighbors
        blocks = content.split('-------------------------')
        for block in blocks:
            device_id_match = re.search(r"Device ID:\s*([^\n]+)", block)
            platform_match = re.search(r"Platform:\s*([^,]+),", block)
            interface_match = re.search(r"Interface:\s*([^\s]+),", block)  # Local interface
            port_id_match = re.search(r"Port ID \(outgoing port\):\s*([^\n]+)", block)  # Remote interface

            if device_id_match and platform_match and interface_match and port_id_match:
                neighbors.append([
                    source_hostname,
                    source_ip,
                    interface_match.group(1).strip(),
                    device_id_match.group(1).strip(),
                    port_id_match.group(1).strip(),
                    platform_match.group(1).strip()
                ])
        return neighbors

    def extract_serial_info(self, file_path):
        """Extracts serial number from a 'show version' output file."""
        with open(file_path, 'r') as file:
            content = file.read()

        source_ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", os.path.basename(file_path))
        source_ip = source_ip_match.group(0) if source_ip_match else "N/A"

        source_hostname_match = re.search(r'\n([\w\d.-]+)#\s*$', content)
        source_hostname = source_hostname_match.group(1) if source_hostname_match else "N/A"

        # Regex to find different variations of serial numbers
        serial_match = re.search(r"(?:System|Processor board ID)\s+([A-Z0-9]+)", content, re.IGNORECASE)

        if serial_match:
            serial_number = serial_match.group(1)
            return [[source_hostname, source_ip, serial_number]]
        return []


if __name__ == "__main__":
    root = tk.Tk()
    app = SwitchSaverApp(root)
    root.mainloop()