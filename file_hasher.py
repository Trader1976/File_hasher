import tkinter as tk
from tkinter import ttk
import sqlite3
from tkinter import *
from tkinter import messagebox
import hashlib
from database_handler import *
from tkinter import filedialog as fd
import os
import sys
import pyAesCrypt
#o                     __...__     *
#              *   .--'    __.=-.             o
#     |          ./     .-'
#    -O-        /      /
#     |        /    '"/               *                     File hasher / encryptor v0.1beta
#             |     (@)                                         Use at your own risk
#            |        \                         .           O N L Y   F O R    T E S T I N G
#            |         \                                        P  U  R  P  O  S  E  S
# *          |       ___\                  |                     _.~< Trader1976 >~._
#             |  .   /  `                 -O-
#              \  `~~\                     |
#         o     \     \            *
#                `\    `-.__           .
#    .             `--._    `--'jgs
#                       `---~~`                *
#            *                   o
#
def encrypt(key,source):
    output = source+".enc"
    pyAesCrypt.encryptFile(source,output,key)
    return output

def decrypt(key,source):
    dfile = source.split(".")
    output = dfile[0]+"dec."+dfile[1]
    pyAesCrypt.decryptFile(source,output,key)
    return

def do_it(filename):
    database = r"config.db"
    con = create_connection(database)
    cur = con.cursor()
    with con:
        # get the default settings for file open
        query = """SELECT secret_key FROM {table} WHERE id=1""".format(table="configuration")
        cur.execute(query)
        my_secret_key, = cur.fetchone()
    encrypt(my_secret_key,filename)


def unhash_file(filename):
    database = r"config.db"
    con = create_connection(database)
    cur = con.cursor()
    with con:
        # get the default settings for file open
        query = """SELECT secret_key FROM {table} WHERE id=1""".format(table="configuration")
        cur.execute(query)
        my_secret_key, = cur.fetchone()
    decrypt(my_secret_key,filename)


def hash_file(filename,mode,encrypt_also):
   """"This function returns the chosen chash for the given filename
   mode 1 = MD5
   mode 2 = SHA256
   mode 3 = SHA512
   mode 4 = Dilithium
   encrypt_also = On (File will also be AES encrypted
   encrypy_also = Off (No encryption will be done)
   """
   if mode == 1:
        # make a hash object
        h = hashlib.md5()
        print("MD5 hash")

   if mode == 2:
        # make a hash object
        h = hashlib.sha256()
        print("SHA256 hash")

   if mode == 3:
        # make a hash object
        h = hashlib.sha512()
        print("SHA512 hash")

   if mode == 4:
        # make a hash object
        h = hashlib.sha512()
        print("Dilithium hash")

   BUFFER_SIZE = 65536  # lets read stuff in 64kb chunks!

   with open(filename, 'rb') as f:
       while True:
           data = f.read(BUFFER_SIZE)
           if not data:
               break
           h.update(data)

   if encrypt_also == "On":
       print("Encrypting...")
       do_it(filename)

   return h.hexdigest()


def MyGUI():
        """Creates the initial graphical user interphase screen
        """
        database = r"config.db"
        con = create_connection(database)
        cur = con.cursor()
        with con:
            # get the default settings for file open
            query = """SELECT default_save, default_open, wallet, secret_key FROM {table} WHERE id=1""".format(table="configuration")
            cur.execute(query)
            default_save, default_open, default_wallet,my_secret_key = cur.fetchone()


            root = tk.Tk()
            root.title("Cellframe File Encryptor")


            print("Default open directory is ", default_open)
            frame1 = LabelFrame(root, text="Choose file to encrypt", padx=5, pady=5)
            frame1.pack(padx=10, pady=10)
            default_open = default_open
            open_file = StringVar(root, value = default_open)

            def choose_file():
                database = r"config.db"
                con = create_connection(database)
                cur = con.cursor()
                with con:
                    # get the default settings for file open
                    query = """SELECT default_save, default_open, wallet FROM {table} WHERE id=1""".format(
                        table="configuration")
                    cur.execute(query)
                    default_save, default_open, default_wallet, = cur.fetchone()

                    filename = fd.askopenfilename(initialdir = default_open)
                    print(filename)
                    file_location.delete(0, END)  # deletes the current value
                    file_location.insert(0, filename)  # inserts new value assigned by 2nd parameter


            file_location = Entry(frame1, width=70, textvariable = open_file)
            file_location.pack(padx=10,pady=10)
            button = tk.Button(frame1, text="Open", font=("Arial", 10), command = choose_file)
            button.pack(padx=10,pady=10)

            var = StringVar()

            check = tk.Checkbutton(root, text="Also encrypt the file", font=("Arial", 10), variable = var, onvalue="On", offvalue="Off")
            check.deselect()
            check.pack(padx=10, pady=10)

            mode = IntVar(value=1) #set default value
            Radiobutton(root, text="MD5", variable=mode, value=1).pack()
            Radiobutton(root, text="SHA256", variable=mode, value=2).pack()
            Radiobutton(root, text="SHA512", variable=mode, value=3).pack()
            Radiobutton(root, text="Dilithium", variable=mode, value=4).pack()

            # create top menu
            menubar = tk.Menu(root)

            filemenu = tk.Menu(menubar, tearoff=0)
            filemenu.add_command(label="Settings", command=settings)
            filemenu.add_separator()
            filemenu.add_command(label="Close", command=exit)



            aboutmenu = tk.Menu(menubar, tearoff=0)
            menubar.add_cascade(menu = filemenu, label="File")
            menubar.add_cascade(menu = aboutmenu, label="Help")
            aboutmenu.add_command(label="Help",command = help_window)
            aboutmenu.add_command(label="About...",command = about_us)
            root.config(menu = menubar)


            def encrypt_file(value, mode, file_path):
                hash = hash_file(file_path, mode, value)
                print(hash)
                if value == "Off":
                    additional_message = ""
                if value == "On":
                    additional_message = "and was also AES encrypted."
                if mode == 1:
                    hash_method = "BD5"
                if mode == 2:
                    hash_method = "SHA256"
                if mode == 3:
                    hash_method = "SHA512"
                if mode == 4:
                    hash_method = "dilithium"

                message = "\nFile" + file_path + " was "+ hash_method + " hashed successfully" + additional_message
                statusbox.insert(INSERT, message)
                status2 = "\n" + "Hash : " + hash
                statusbox.insert(INSERT, status2)
                statusbox.see("end")  #scroll to the bottom


            def decrypt_file(file_path):
                try:
                    unhash_file(file_path)
                    message = "\nFile" + file_path + " was decrypted successfully"
                    statusbox.insert(INSERT, message)
                    statusbox.see("end")  #scroll to the bottom

                except Exception as ex:
                    message = "\nFile" + file_path + " decryption failed."
                    statusbox.insert(INSERT, message)
                    statusbox.see("end")  # scroll to the bottom
                    messagebox.showwarning("Error", ex)


            button = tk.Button(root, text="Hash / encrypt", font=("Arial",10), command = lambda: encrypt_file(var.get(),mode.get(),open_file.get()))
            button.pack(padx=10, pady=10)

            button2 = tk.Button(root, text="Decrypt", font=("Arial",10), command = lambda: decrypt_file(open_file.get()))
            button2.pack(padx=10, pady=10)

            statusbox = tk.Text(root, height=5, font=("Arial", 10), bg="light gray")

            statusbox.insert(INSERT, "Program ready...")
            statusbox.pack(padx=10, pady=10)

            root.mainloop()



def settings():
    """Opens new window where user can update diffrerent settings
    """
    database = r"config.db"
    con = create_connection(database)
    cur = con.cursor()
    with con:
        query = """SELECT default_save, default_open, wallet, secret_key FROM {table} WHERE id=1""".format(table="configuration")
        cur.execute(query)
        default_save, default_open, default_wallet, my_secret_key = cur.fetchone()

    def choose_directory():
        filename = fd.askdirectory()
        print(filename)
        file_location.delete(0, END)  # deletes the current value
        file_location.insert(0, filename)  # inserts new value assigned by 2nd parameter

    def choose_saving_directory():
        filename2 = fd.askdirectory()
        print(filename2)
        save_file_location.delete(0, END)  # deletes the current value
        save_file_location.insert(0, filename2)  # inserts new value assigned by 2nd parameter

    def save_settings(my_wallet, file_location, save_file_location, my_secret_key):
        print(my_wallet)
        print(file_location)
        print(save_file_location)

        database = r"config.db"
        con = create_connection(database)
        cur = con.cursor()
        with con:
            query = """ UPDATE {table} SET wallet=? WHERE id=1""".format(table="configuration")
            cur.execute(query, [my_wallet])
            con.commit()

            query = """ UPDATE {table} SET default_open=? WHERE id=1""".format(table="configuration")
            cur.execute(query, [file_location])
            con.commit()

            query = """ UPDATE {table} SET default_save=? WHERE id=1""".format(table="configuration")
            cur.execute(query, [save_file_location])
            con.commit()

            query = """ UPDATE {table} SET secret_key=? WHERE id=1""".format(table="configuration")
            cur.execute(query, [my_secret_key])
            con.commit()

            top.destroy()

    top = Toplevel()
    top.geometry("600x450+500+500")
    top.title("Settings")

    frame1 = LabelFrame(top,text="Default file open locations", padx=5, pady=5)
    frame1.grid(row=0, column=0, columnspan=20,padx=10, pady=10)

    o = StringVar(top, value=default_open)

    file_location = Entry(frame1, width=70,textvariable=o)
    file_location.grid(row=1, column=0)

    button = tk.Button(frame1, text="Change", font=("Arial", 10), command=choose_directory)
    button.grid(row=2, column=0, pady=5,sticky=E)

    frame2 = LabelFrame(top,text="Default path for saving encrypted filed", padx=5, pady=5)
    frame2.grid(row=3, column=0, columnspan=20,padx=10, pady=10)

    s = StringVar(top, value=default_save)
    save_file_location = Entry(frame2, width=70,textvariable=s)
    save_file_location.grid(row=1, column=0)

    button2 = tk.Button(frame2, text="Change", font=("Arial", 10), command=choose_saving_directory)
    button2.grid(row=2, column=0, pady=5,sticky=E)

    my_wallet = StringVar(top, value=default_wallet)

    frame3 = LabelFrame(top,text="Wallet address", padx=5, pady=5)
    frame3.grid(row=4, column=0, columnspan=20,padx=10, pady=10)

    wallet = Entry(frame3, width=70,textvariable=my_wallet)
    wallet.grid(row=4, column=0)

    frame4 = LabelFrame(top,text="Your secret key", padx=5, pady=5)
    frame4.grid(row=5, column=0, columnspan=20,padx=10, pady=10)
    key = StringVar(top, value=my_secret_key)
    secret_key = Entry(frame4, width=70,textvariable=key)
    secret_key.grid(row=6, column=0)


    close_button = tk.Button(top, text="Cancel", padx=10, pady=5, font=("Arial", 10), command=top.destroy)
    close_button.grid(row=8, column=17)

    save_button = tk.Button(top, text="Apply", padx=10, pady=5,font=("Arial", 10), command=lambda: save_settings(my_wallet.get(),file_location.get(),save_file_location.get(),key.get()))
    save_button.grid(row=8, column=18)


def about_us():
    top = Toplevel()
    top.geometry("600x450+500+500")
    top.title("About us")

    canvas = Canvas(top, width=650, height=350)
    canvas.pack()
    img = tk.PhotoImage(file='about_us.png')
    canvas.image = img
    canvas.create_image(180, 150, image=img)

    close_button = tk.Button(top, text="Ok", padx=40, pady=10, font=("Arial", 10), command=top.destroy)
    close_button.pack(padx=30, pady=10)

def save_settings(my_wallet,file_location,save_file_location):

    print(my_wallet)
    print(file_location)
    print(save_file_location)

    database = r"config.db"
    con = create_connection(database)
    cur = con.cursor()
    with con:
        query = """ UPDATE {table} SET wallet=? WHERE id=1""".format(table="configuration")
        cur.execute(query,[my_wallet])
        con.commit()

        query = """ UPDATE {table} SET default_open=? WHERE id=1""".format(table="configuration")
        cur.execute(query,[file_location])
        con.commit()

        query = """ UPDATE {table} SET default_save=? WHERE id=1""".format(table="configuration")
        cur.execute(query,[save_file_location])
        con.commit()


def help_window2():
    top = Toplevel()
    top.geometry("800x700+500+300")
    top.title("Help")

    textbox = tk.Text(top, height=39,width=130, font=("Arial", 10), bg="light gray")
    word_text = Text(top, wrap='word', padx=10, pady=10,bg="light gray")
    word_text.pack(fill='both', padx=10, pady=10)

    word = 'mountain'
    word_class = 'noun'

    # Insert text sections
    word_text.insert('end', "here is something" + '\n')
    word_text.insert('end', word_class + '\n')


    # Tag and style text sections
    word_text.tag_add('word', '1.0', '1.end')
    word_text.tag_config('word', font='arial 10 bold')  # Set font, size and style

    word_text.insert('end', "and here is something more" + '\n')

    word_text.tag_add('word_class', '3.0', '3.end')
    word_text.tag_config('word_class', font='arial 10 normal', lmargin1=30,
                         spacing1=10, spacing3=15)  # Set margin and spacing

    word_text.insert('end', "here is something" + '\n')
    word_text.insert('end', "here is something" + '\n')

    word_text.tag_add('word', '1.0', '1.end')
    word_text.tag_config('word', font='arial 10 bold')  # Set font, size and style

    word_text.insert('end', "Encryption" + '\n')




    close_button = tk.Button(top, text="Ok", padx=40, pady=10, font=("Arial", 10), command=top.destroy)
    close_button.pack(padx=30, pady=10)


def help_window():
    top = Toplevel()
    top.geometry("800x700+500+300")
    top.title("Help")

    textbox = tk.Text(top, height=39,width=130, font=("Arial", 10), bg="light gray")

    textbox.insert(INSERT, "Cellframe file hasher / encryptor 0.1 Beta\n\n")
    textbox.insert(INSERT, "Settings\n\n")

    textbox.insert(INSERT, "From settings menu, select default file locations for opening and saving encrypted files. \n\n")

    textbox.insert(INSERT, "Wallet \n\n")

    textbox.insert(INSERT, "If you want to use CF20 dilithium time signature, then you also need to set up your wallet and type it's address into wallet field.\n")

    textbox.insert(INSERT, "This wallet is then used to mint file hash into Cellframe block which will then create your time signature.\n\n")

    textbox.insert(INSERT, "Your secret key\n\n")

    textbox.insert(INSERT, "Here write your secret passphrase or password. It will be then used to encrypt files and also is required for decrypting.\n")

    textbox.insert(INSERT, "Note that secret key must be 100% same as was used when file was encrypted. Otherwise you will get error.\n\n")

    textbox.insert(INSERT, "Using the program\n\n")

    textbox.insert(INSERT, "This program can be used to create hash from any type of file. There are several hashing functions to choose from and they all give\n")

    textbox.insert(INSERT, "different level of security. Usually the longer the hash, the more secure it is. \n")

    textbox.insert(INSERT, "By choosing dilithium hashing function, then Cellframe wallet has to be set up correctly and node has to be online for it to work.\n\n")

    textbox.insert(INSERT, "Also encrypt the file\n\n")

    textbox.insert(INSERT, "If this box is selected, then the file you choose will also be encrypted with your secret key and will be saved into your default\n")

    textbox.insert(INSERT, "save location. Filename will show .enc at the end meaning it is encrypted file.\n\n")

    textbox.insert(INSERT, "Decrypt button\n\n")

    textbox.insert(INSERT, "This will decrypt the file your choose from above. Note that the file has to be encrypted with the same secret key or otherwise it\n")

    textbox.insert(INSERT, "will not work and results in error.\n")

    textbox.insert(INSERT, "Successfully decrypting file it will be saved into your default file save location and it's name will get additional .dec mark on\n")

    textbox.insert(INSERT, "it's name.\n")
    textbox.pack(padx=10, pady=10)
    close_button = tk.Button(top, text="Ok", padx=40, pady=10, font=("Arial", 10), command=top.destroy)
    close_button.pack(padx=30, pady=10)


if __name__ == "__main__":

    MyGUI()
