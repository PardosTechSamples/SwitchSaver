import paramiko
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import time
import os
import re
import csv

password_entry = None

app_title = "Switch Saver 1.0 - Cisco Switches"
app_ssh_title = "Switch Saver (SSH Mode)"


def main_menu():
    menu_root = tk.Tk()
    menu_root.title(app_title)
    menu_root.minsize(400, 300)
    menu_frame = ttk.Frame(menu_root, padding="30")
    menu_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

    ssh_button = ttk.Button(menu_frame, text="Run SSH Bot", command=lambda: go_to_ssh(menu_root))
    ssh_button.pack(pady=20)

    # Add Generate CSV button
    generateCDP_csv_button = ttk.Button(menu_frame, text="Generate CDP Neighbors CSV", command=lambda: generateCDP_csv(menu_root))
    generateCDP_csv_button.pack(pady=20)

    generateVersion_csv_button = ttk.Button(menu_frame, text="Generate CDP Neighbors CSV", command=lambda: generateVERSION_csv(menu_root))
    generateVersion_csv_button.pack(pady=20)

    menu_root.mainloop()

def run_ssh_bot():
    # Initialize main window
    global output_folder_entry, file_label, user_entry, password_entry, command_combobox, custom_command_text, custom_command_label, notebook

    root = tk.Tk()
    root.title(app_ssh_title)
    root.minsize(400, 300)
    # File input button and label
    file_button = ttk.Button(root, text="Choose IP Address File", command=open_file)
    file_button.grid(row=0, column=0, pady=20, padx=20)
    file_label = ttk.Label(root, text="No file chosen")
    file_label.grid(row=0, column=1, pady=20, padx=20)

    # User input
    user_label = ttk.Label(root, text="Username:")
    user_label.grid(row=2, column=0, padx=20, pady=10, sticky='e')
    user_entry = ttk.Entry(root)
    user_entry.grid(row=2, column=1, padx=20)

    # Password input
    password_label = ttk.Label(root, text="Password:")
    password_label.grid(row=3, column=0, padx=20, pady=10, sticky='e')
    password_entry = ttk.Entry(root, show="*")
    password_entry.grid(row=3, column=1, padx=20)

    # Output folder input
    output_folder_button = ttk.Button(root, text="Choose Output Folder", command=choose_output_folder)
    output_folder_button.grid(row=1, column=0, padx=20)
    output_folder_entry = ttk.Entry(root)
    output_folder_entry.grid(row=1, column=1, padx=20)

    # Command selection
    command_label = ttk.Label(root, text="Command:")
    command_label.grid(row=4, column=0, padx=20, sticky='e')
    command_options = ["show config", "show interfaces", "write", "show version | include Motherboard Serial", "Custom Command"]
    command_combobox = ttk.Combobox(root, values=command_options, state="readonly")
    command_combobox.grid(row=4, column=1, padx=20)
    command_combobox.set(command_options[0])  # Set default value to "show config"

    custom_command_label = ttk.Label(root, text="Custom Commands:")
    custom_command_text = tk.Text(root, height=10, width=40)  # Adjusted height and width
    command_combobox.bind("<<ComboboxSelected>>", on_command_selected)

    # Generate Notebook

    notebook = ttk.Notebook(root)
    notebook.grid(row=7, column=0, columnspan=2, pady=20, padx=20, sticky='ew')

    # Execute button
    execute_button = ttk.Button(root, text="Execute SSH", command=execute_ssh)
    execute_button.grid(row=5, column=0, columnspan=2, pady=20)

    # Return to Menu button
    return_button = ttk.Button(root, text="Return to Menu", command=lambda: return_to_menu(root))
    return_button.grid(row=8, column=0, columnspan=2, pady=20)


    root.mainloop()


def return_to_menu(current_root):
    current_root.destroy()  # Close the current window
    main_menu()  # Open the main menu


def go_to_ssh(current_root):
    current_root.destroy()
    run_ssh_bot()

def generateVersion_csv(menu_root):
    # Open a folder dialog to select the folder containing the .txt files
    folder_path = filedialog.askdirectory(title="Select Folder with CDP Neighbor Files")

    if folder_path:
        all_data = []

        # Iterate through the .txt files in the selected folder
        for filename in os.listdir(folder_path):
            if filename.endswith('.txt'):
                file_path = os.path.join(folder_path, filename)
                data = extractVersion_info(file_path)
                all_data.extend(data)

        # If there is data to save
        if all_data:
            save_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
            if save_path:
                try:
                    with open(save_path, 'w', newline='') as csvfile:
                        csv_writer = csv.writer(csvfile)
                        csv_writer.writerow(
                            ['sourcehostname', 'sourceip', 'sourceport', 'destinationhostname', 'destinationport',
                             'Device Model'])  # Write header
                        csv_writer.writerows(all_data)
                    messagebox.showinfo("Success", f"CSV file successfully generated: {save_path}")
                except Exception as e:
                    messagebox.showerror("Error", f"An error occurred while saving the CSV file: {str(e)}")
        else:
            messagebox.showwarning("No Data", "No CDP neighbor data found in the selected folder.")
    else:
        messagebox.showwarning("No Folder Selected", "You must select a folder to generate the CSV.")

# Extract Version data from a given .txt file
def extractVersion_info(file_path):
    with open(file_path, 'r') as file:
        content = file.readlines()

    # Extract source IP from the filename (assuming it is embedded in the filename)
    source_ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", file_path).group(0)  # Extract IP from filename

    # Extract the source hostname (last line of the file, ends with #)
    source_hostname = content[-1].strip()
    if source_hostname.endswith("#"):
        source_hostname = source_hostname[:-1]  # Remove the trailing '#'

    # Regular expression to capture neighbor data
    neighbor_info = []

    # Define the regex to capture neighbor data, including device model and port (handle multiple spaces)
    neighbor_pattern = re.compile(
        r"^([^\n\s]+(?:\.[^\n\s]+)*)\s+(\S+\s*\d+/\d+/\d*|po\d+)\s+\d+\s+[A-Z\s]+\s+([^\s]+(?:\s+[^\s]+)*)\s+(\S+\s+\S+)$")

    # Initialize the neighbor hostname to None to handle multi-line hostnames
    neighbor_hostname = None

    # Scan for all matching lines with the neighbor info (ignores the first line and non-data lines)
    for line in content:
        line = line.strip()

        if line == '':
            continue

        # If the line starts with a device ID, capture the hostname (handle multiline hostnames)
        if not re.match(r"\s{0,2}[A-Za-z0-9\.\-]+\s{0,2}", line):  # It's a continuation of the previous line
            if neighbor_hostname:
                neighbor_hostname += ' ' + line.strip()  # Add the rest of the multi-line hostname
        else:
            # Match with the regex for valid neighbor data
            match = neighbor_pattern.match(line)
            if match:
                # If we found a match, extract the data
                destination_hostname = match.group(1).strip()
                source_port = match.group(2).strip()
                destination_port = match.group(3).strip()
                device_model = match.group(4).strip()

                # If we have a valid neighbor hostname from the previous line, update it
                if neighbor_hostname:
                    destination_hostname = neighbor_hostname.strip()

                # Add the neighbor data in the required format
                neighbor_info.append(
                    [source_hostname, source_ip, source_port, destination_hostname, destination_port, device_model])

                # Reset neighbor_hostname to None after processing
                neighbor_hostname = None

            # If the line doesn't match the pattern but contains a valid hostname
            # (i.e., single-line hostnames like "BB" or multi-line device names)
            else:
                if re.match(r"^[A-Za-z0-9\.\-]+\s*$", line):  # This is part of a multi-line hostname
                    if neighbor_hostname:
                        neighbor_hostname += ' ' + line.strip()  # Continue the previous hostname line
                else:
                    neighbor_info.append(
                        [source_hostname, source_ip, '', '', '', ''])  # If missing info, still append empty columns

    return neighbor_info


def generateCDP_csv(menu_root):
    # Open a folder dialog to select the folder containing the .txt files
    folder_path = filedialog.askdirectory(title="Select Folder with CDP Neighbor Files")

    if folder_path:
        all_data = []

        # Iterate through the .txt files in the selected folder
        for filename in os.listdir(folder_path):
            if filename.endswith('.txt'):
                file_path = os.path.join(folder_path, filename)
                data = extractCDP_info(file_path)
                all_data.extend(data)

        # If there is data to save
        if all_data:
            save_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
            if save_path:
                try:
                    with open(save_path, 'w', newline='') as csvfile:
                        csv_writer = csv.writer(csvfile)
                        csv_writer.writerow(
                            ['sourcehostname', 'sourceip', 'sourceport', 'destinationhostname', 'destinationport',
                             'Device Model'])  # Write header
                        csv_writer.writerows(all_data)
                    messagebox.showinfo("Success", f"CSV file successfully generated: {save_path}")
                except Exception as e:
                    messagebox.showerror("Error", f"An error occurred while saving the CSV file: {str(e)}")
        else:
            messagebox.showwarning("No Data", "No CDP neighbor data found in the selected folder.")
    else:
        messagebox.showwarning("No Folder Selected", "You must select a folder to generate the CSV.")



# Extract CDP data from a given .txt file
def extractCDP_info(file_path):
    with open(file_path, 'r') as file:
        content = file.readlines()

    # Extract source IP from the filename (assuming it is embedded in the filename)
    source_ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", file_path).group(0)  # Extract IP from filename

    # Extract the source hostname (last line of the file, ends with #)
    source_hostname = content[-1].strip()
    if source_hostname.endswith("#"):
        source_hostname = source_hostname[:-1]  # Remove the trailing '#'

    # Regular expression to capture neighbor data
    neighbor_info = []

    # Define the regex to capture neighbor data, including device model and port (handle multiple spaces)
    neighbor_pattern = re.compile(
        r"^([^\n\s]+(?:\.[^\n\s]+)*)\s+(\S+\s*\d+/\d+/\d*|po\d+)\s+\d+\s+[A-Z\s]+\s+([^\s]+(?:\s+[^\s]+)*)\s+(\S+\s+\S+)$")

    # Initialize the neighbor hostname to None to handle multi-line hostnames
    neighbor_hostname = None

    # Scan for all matching lines with the neighbor info (ignores the first line and non-data lines)
    for line in content:
        line = line.strip()

        if line == '':
            continue

        # If the line starts with a device ID, capture the hostname (handle multiline hostnames)
        if not re.match(r"\s{0,2}[A-Za-z0-9\.\-]+\s{0,2}", line):  # It's a continuation of the previous line
            if neighbor_hostname:
                neighbor_hostname += ' ' + line.strip()  # Add the rest of the multi-line hostname
        else:
            # Match with the regex for valid neighbor data
            match = neighbor_pattern.match(line)
            if match:
                # If we found a match, extract the data
                destination_hostname = match.group(1).strip()
                source_port = match.group(2).strip()
                destination_port = match.group(3).strip()
                device_model = match.group(4).strip()

                # If we have a valid neighbor hostname from the previous line, update it
                if neighbor_hostname:
                    destination_hostname = neighbor_hostname.strip()

                # Add the neighbor data in the required format
                neighbor_info.append(
                    [source_hostname, source_ip, source_port, destination_hostname, destination_port, device_model])

                # Reset neighbor_hostname to None after processing
                neighbor_hostname = None

            # If the line doesn't match the pattern but contains a valid hostname
            # (i.e., single-line hostnames like "BB" or multi-line device names)
            else:
                if re.match(r"^[A-Za-z0-9\.\-]+\s*$", line):  # This is part of a multi-line hostname
                    if neighbor_hostname:
                        neighbor_hostname += ' ' + line.strip()  # Continue the previous hostname line
                else:
                    neighbor_info.append(
                        [source_hostname, source_ip, '', '', '', ''])  # If missing info, still append empty columns

    return neighbor_info

def ssh_to_switch(ip, user, pwd, output_directory, command) -> bool:
    global custom_command_text
    success = False
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(ip, username=user, password=pwd)

        remote_conn = ssh_client.invoke_shell()
        remote_conn.send("enable\n")

        success = True
        output = ""


        if command == "Custom Command":
            # Get the commands from the Text widget
            custom_cmds = custom_command_text.get("1.0", tk.END).strip().split("\n")
            for cmd in custom_cmds:
                chunk = remote_conn.recv(4096).decode('utf-8')
                if '--More--' in chunk:
                    remote_conn.send("               ")  # Send space to continue
                    chunk = chunk.replace('--More--', '').replace('\x08','')  # '\x08' is the escape code for backspace
                    #update_gui(ip, chunk)
                    output += chunk
                    time.sleep(1.5)  # Wait for more data to be rendered
                else:
                    #update_gui(ip, chunk)
                    output += chunk
                remote_conn.send(cmd + "\n")
                time.sleep(1)
        else:
            remote_conn.send(command + "\n")

        time.sleep(.5)

        while True:
            if remote_conn.recv_ready():
                chunk = remote_conn.recv(4096).decode('utf-8')

                # If "--More--" is in the chunk, send a space to fetch more data
                if '--More--' in chunk:
                    remote_conn.send("               ")  # Send space to continue
                    chunk = chunk.replace('--More--', '').replace('\x08','')  # '\x08' is the escape code for backspace
                    #update_gui(ip, chunk)
                    output += chunk
                    time.sleep(1.5)  # Wait for more data to be rendered
                else:
                    #update_gui(ip, chunk)
                    output += chunk
                    break
            else:
                time.sleep(1.5)  # If not ready to receive, wait and check again




        # Save the output to a file
        filename = ip + ".txt"
        filepath = output_directory + '/' + filename
        with open(filepath, 'w') as outfile:
            outfile.write(output)

        # Update the GUI with the output
        update_gui(ip, output)

        ssh_client.close()

    except Exception as e:
        success = False
    return success


def update_gui(ip, output):
    # Check if a tab for the IP already exists
    global  notebook
    tab_exists = False
    for tab in notebook.tabs():
        if notebook.tab(tab, "text") == ip:
            frame = tab
            tab_exists = True
            break

    if not tab_exists:
        # Create a new tab for the IP
        frame = ttk.Frame(notebook)
        notebook.add(frame, text=ip)
        text_widget = tk.Text(frame, wrap=tk.WORD, height=20, width=60)  # Adjusted height and width
        text_widget.pack(padx=10, pady=10, expand=True, fill=tk.BOTH)
    else:
        # Fetch the Text widget from the existing tab
        text_widget = frame.winfo_children()[0]

    text_widget.insert(tk.END, output + "\n\n")  # Append new output
    text_widget.config(state=tk.DISABLED)  # Make the text read-only


def execute_ssh():
    global user_entry, password_entry, command_combobox
    user = user_entry.get()
    pwd = password_entry.get()
    output_directory = output_folder_entry.get()
    command_selected = command_combobox.get()

    with open(file_path, 'r') as file:
        ip_addresses = [line.strip() for line in file.readlines()]

    success_ips = []
    failed_ips = []

    for ip in ip_addresses:
        if ssh_to_switch(ip, user, pwd, output_directory, command_selected):
            success_ips.append(ip)
        else:
            failed_ips.append(ip)

    success_msg = f"Successfully connected to: {', '.join(success_ips)}" if success_ips else ""
    failed_msg = f"Failed to connect to: {', '.join(failed_ips)}" if failed_ips else ""

    messagebox.showinfo("Results", success_msg + "\n" + failed_msg)
def open_file():
    global file_path, file_label
    file_path = filedialog.askopenfilename()
    file_label.config(text=file_path.split("/")[-1])

def choose_output_folder():
    global output_folder_entry

    folder_path = filedialog.askdirectory()
    output_folder_entry.delete(0, tk.END)
    output_folder_entry.insert(tk.END, folder_path)


def on_command_selected(event):
    global custom_command_label
    selected_command = command_combobox.get()
    if selected_command == "Custom Command":
        custom_command_label.grid(row=6, column=0, padx=20, sticky='e')
        custom_command_text.grid(row=6, column=1, padx=20)
    else:
        custom_command_label.grid_forget()
        custom_command_text.grid_forget()


main_menu()
