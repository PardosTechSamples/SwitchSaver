import paramiko
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import time, telnetlib
password_entry = None



app_title = "Switch Saver 1.0 - Cisco Switches"
app_ssh_title = "Switch Saver (SSH Mode)"
app_telnet_title = "Switch Saver (Telnet Mode)"


def main_menu():
    menu_root = tk.Tk()
    menu_root.title(app_title) 
    menu_root.minsize(400,300)
    menu_frame = ttk.Frame(menu_root, padding="30")
    menu_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

    ssh_button = ttk.Button(menu_frame, text="Run SSH Bot", command=lambda: go_to_ssh(menu_root))

    ssh_button.pack(pady=20)

    telnet_button = ttk.Button(menu_frame, text="Run Telnet Bot", command=lambda: go_to_telnet(menu_root))
    telnet_button.pack(pady=20)

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
    command_options = ["show config", "show interfaces", "Custom Command"]
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


def run_telnet_bot():
    global output_folder_entry, file_label, password_label, password_entry, en_password_entry, command_combobox, custom_command_text, custom_command_label, notebook

    # Initialize main window
    root = tk.Tk()
    root.title("Telnet Bot (Cisco Switches)")
    root.minsize(400, 300)
    # File input button and label
    file_button = ttk.Button(root, text="Choose IP Address File", command=open_file)
    file_button.grid(row=0, column=0, pady=20, padx=20)
    file_label = ttk.Label(root, text="No file chosen")
    file_label.grid(row=0, column=1, pady=20, padx=20)

    # User input
    password_label = ttk.Label(root, text="Switch Password:")
    password_label.grid(row=2, column=0, padx=20, pady=10, sticky='e')
    password_entry = ttk.Entry(root)
    password_entry.grid(row=2, column=1, padx=20)

    # Password input
    en_password_label = ttk.Label(root, text="Enable Password:")
    en_password_label.grid(row=3, column=0, padx=20, pady=10, sticky='e')
    en_password_entry = ttk.Entry(root, show="*")
    en_password_entry.grid(row=3, column=1, padx=20)

    # Output folder input
    output_folder_button = ttk.Button(root, text="Choose Output Folder", command=choose_output_folder)
    output_folder_button.grid(row=1, column=0, padx=20)
    output_folder_entry = ttk.Entry(root)
    output_folder_entry.grid(row=1, column=1, padx=20)

    # Command selection
    command_label = ttk.Label(root, text="Command:")
    command_label.grid(row=4, column=0, padx=20, sticky='e')
    command_options = ["show config", "show interfaces", "Custom Command"]
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
    execute_button = ttk.Button(root, text="Execute Telnet", command=execute_telnet)
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

def go_to_telnet(current_root):
    current_root.destroy()
    run_telnet_bot()

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
                chunk = remote_conn.recv(65535).decode('utf-8')
                if '--More--' in chunk:
                    remote_conn.send("               ")  # Send space to continue
                    chunk = chunk.replace('--More--', '').replace('\x08','')  # '\x08' is the escape code for backspace
                    #update_gui(ip, chunk)
                    output += chunk
                    time.sleep(1)  # Wait for more data to be rendered
                else:
                    #update_gui(ip, chunk)
                    output += chunk
                remote_conn.send(cmd + "\n")
                time.sleep(1)
        else:
            remote_conn.send(command + "\n")

        time.sleep(1)

        while True:
            if remote_conn.recv_ready():
                chunk = remote_conn.recv(65535).decode('utf-8')

                # If "--More--" is in the chunk, send a space to fetch more data
                if '--More--' in chunk:
                    remote_conn.send(" ")  # Send space to continue
                    chunk = chunk.replace('--More--', '').replace('\x08','')  # '\x08' is the escape code for backspace
                    #update_gui(ip, chunk)
                    output += chunk
                    time.sleep(.5)  # Wait for more data to be rendered
                else:
                    #update_gui(ip, chunk)
                    output += chunk
                    break
            else:
                time.sleep(.5)  # If not ready to receive, wait and check again




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


def telnet_to_switch(ip, password, en_password, output_directory, command) -> bool:
    success = False

    try:
        tn = telnetlib.Telnet(ip)
        time.sleep(1)
        output = ""

        chunk = tn.read_very_eager().decode('utf-8')
        #print(chunk)
        output += chunk

        #print("Password Entered")
        tn.write(password.encode('utf-8'))
        time.sleep(.5)
        chunk = tn.read_very_eager().decode('utf-8')
        output += chunk

        tn.write("enable\n".encode('utf-8'))
        chunk = tn.read_very_eager().decode('utf-8')
        output += chunk

        tn.write(en_password.encode('utf-8'))
        time.sleep(.5)
        #print("Enable Password Entered")
        chunk = tn.read_very_eager().decode('utf-8')
        output += chunk

        #tn.write("show config\n".encode('utf-8'))
        if command == "Custom Command":
            # Get the commands from the Text widget
            custom_cmds = custom_command_text.get("1.0", tk.END).strip().split("\n")
            for cmd in custom_cmds:
                tn.write((cmd + "\n").encode('utf-8'))
                time.sleep(.5)
                chunk = tn.read_very_eager().decode('utf-8')
                if '--More--' in chunk:
                    tn.write("               ".encode('utf-8'))  # Send spaces to continue
                    time.sleep(0.5)  # Wait for more data to be rendered
                    chunk = chunk.replace('--More--', '').replace('\x08', '')  # '\x08' is the escape code for backspace
                output += chunk

        else:
            tn.write((command + "\n").encode('utf-8'))

        while True:
            time.sleep(1)
            chunk = tn.read_very_eager().decode('utf-8')

            if '--More--' in chunk:
                tn.write("               ".encode('utf-8'))  # Send spaces to continue
                time.sleep(0.5)  # Wait for more data to be rendered
                chunk = chunk.replace('--More--', '').replace('\x08', '')  # '\x08' is the escape code for backspace
            else:
                break
            # update_gui(ip, chunk)

            output += chunk

        update_gui(ip, output)
        # Save the output to a file
        filename = ip + ".txt"
        filepath = output_directory + '/' + filename
        with open(filepath, 'w') as outfile:
            outfile.write(output)

        #print(output)
        success = True
    except Exception as e:
        print(f"Error: {e}")
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
def execute_telnet():
    global password_entry, en_password_entry, output_folder_entry, command_combobox
    pwd1 = password_entry.get() + "\n"
    pwd2 = en_password_entry.get() + "\n"
    output_directory = output_folder_entry.get()
    command_selected = command_combobox.get()

    with open(file_path, 'r') as file:
        ip_addresses = [line.strip() for line in file.readlines()]

    success_ips = []
    failed_ips = []

    for ip in ip_addresses:
        if telnet_to_switch(ip, pwd1, pwd2, output_directory, command_selected):
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
