"""
This script contains the functions which build the GUI.
First imports the necessary libraries and the backend.py script.
After that there are the definitions of all the functions are used to build the applications GUI.
"""

from tkinter import *
import backend
from tkinter.messagebox import showinfo, showerror, showwarning
from tkinter import filedialog
import time


def start_page():
    """
    This function constructs the Start Page of the Password Manager Application.
    Contains two buttons, 'Sign up' and 'Log In' for the user to choose.
    :return: None
    """

    global first

    first = Tk()
    first.geometry("400x150")
    first.title("Password Manager")

    fir_frame = Frame(first)
    fir_frame.pack()

    welcome = Label(fir_frame, text="Welcome to the Password Manager!\n")
    welcome.grid(row=1, column=0, sticky=E)

    message = Label(fir_frame, text="Create a new account or if you have already one login\n")
    message.grid(row=2, column=0, sticky=E)

    signup_button = Button(fir_frame, text='Sign Up', command=goto_signup)
    signup_button.grid(row=9, column=0, columnspan=2, sticky=W)

    login_button = Button(fir_frame, text='Log In', command=goto_login)
    login_button.grid(row=9, column=2, columnspan=2, sticky=W)

    first.mainloop()


def signup_page():
    """
    This function constructs the Sign Up Page.
    The Sign Up Page registers the user in the Password Manager Application.
    The user have to enter his/her Name, e-mail address, username and a password in order to register in the application.
    There is also the choice to Cancel the registration and go back to the Start Page.
    :return: None
    """

    global pwordE  # These globals just make the variables global to the entire script, meaning any definition can use them
    global nameE
    global emailE
    global usernameE
    global roots

    roots = Tk()  # This creates the window, just a blank one.
    roots.geometry("450x150")
    roots.title('Password Manager: Registration')  # This renames the title of the window
    instruction = Label(roots, text='Please Enter your Credentials\n')  # This puts a label
    instruction.grid(row=0, column=0,sticky=E)  # This just puts it in the window, on row 0, col 0

    nameL = Label(roots, text='Name: ')
    emailL = Label(roots, text='E-mail address: ')
    usernameL = Label(roots, text='Username: ')
    pwordL = Label(roots, text='Password: ')

    nameL.grid(row=1, column=0, sticky=W)
    emailL.grid(row=2, column=0, sticky=W)
    usernameL.grid(row=3, column=0, sticky=W)
    pwordL.grid(row=4, column=0, sticky=W)

    nameE = Entry(roots)  # This now puts a text box waiting for input.
    emailE = Entry(roots)
    usernameE = Entry(roots)
    pwordE = Entry(roots, show='*')  # Same as above, yet 'show="*"' What this does is replace the text with *, like a password box

    nameE.grid(row=1, column=1)
    emailE.grid(row=2, column=1)
    usernameE.grid(row=3, column=1)
    pwordE.grid(row=4, column=1)

    signupButton = Button(roots, text='Signup', command=take_credentials)  # When click this button it calls the take_credentials() function
    signupButton.grid(row=5, column=0, columnspan=2, sticky=W)

    signupButton = Button(roots, text='Cancel', fg='red', command=goto_start) # When click this button it calls the take_goto_start() function
    signupButton.grid(row=5, column=3, columnspan=2, sticky=W)

    roots.mainloop()  # This just makes the window keep open, we will destroy it soon


def login_page():
    """
     This function constructs the Log In Page.
     The Log In Page signs in the user in the Password Manager Application.
     The user have to enter his/her username and the password that typed in the Sign Up Page and load his Certificate,
     in order to access his Password Manager account.
     There is also the choice to Cancel the login and go back to the Start Page.
     :return: None
     """

    global rootA
    global uNameEL
    global pwdEL
    global tries, delay
    delay = 10
    tries = 10

    rootA = Tk()  # This now makes a new window.
    rootA.geometry("350x150")
    rootA.title('Password Manager: Login')  # This makes the window title 'login'

    instruction = Label(rootA, text='Load your Certificate\n and enter your credentials\n')
    instruction.grid(sticky=E)

    uNameL = Label(rootA, text='Username: ')  # Labels
    pwdL = Label(rootA, text='Password: ')
    uNameL.grid(row=1, sticky=W)
    pwdL.grid(row=2, sticky=W)

    uNameEL = Entry(rootA)  # The entry input
    pwdEL = Entry(rootA, show='*')
    uNameEL.grid(row=1, column=1)
    pwdEL.grid(row=2, column=1)

    loginB = Button(rootA, text='Login', fg='green', command=get_user)  # This makes the login button, which will go to the get_user() function
    loginB.grid(row=4, column=0, columnspan=2, sticky=W)

    cancel = Button(rootA, text='Cancel', fg='red', command=goto_start2)  # This makes the deluser button and goes to the goto_start2() function
    cancel.grid(row=4, column=1, columnspan=2, sticky=W)

    load_cert = Button(rootA, text='Load certificate', command=window_explorer)  # This makes the deluser button.and goes to the windows_explorer function
    load_cert.grid(row=3, column=0, columnspan=2, sticky=W)

    rootA.mainloop()


def window_explorer():
    """
    This function prompts a pop up windows in order the user choose his certificate to load on the Application
    :return: None
    """
    global filename
    filename = filedialog.askopenfilename(initialdir="/home/michael/Επιφάνεια εργασίας", title="Select certificate",
                                          filetypes=(("crt files", "*.crt"), ("all files", "*.*")))


def take_credentials():
    """
    When the user clicks on the Sign Up button in the Sign Up Page this function takes his/her credentials,
    and calls the registration() function in the backend.py script, in order to create a certificate and register
    the user in the Application. Also, it informs the user about the successful registration and takes him/her to
    the Start Page. However, if there is a user with the same username the Application doesn't allow the registration and
    informs the user.
    :return: None
    """

    name = nameE.get()
    email = emailE.get()
    username = usernameE.get()
    password = pwordE.get()

    status = backend.registration(name, email, username, password)
    if status == 1:
        showwarning("Registration", "This username already exists!")
    else:
        showinfo("Registration", "You have been registered to the Password Manager! Enjoy it!")
        goto_start()


def get_user():
    """
    When the user clicks on the Log In button in the Log In Page this function takes the username and the password
    he/she typed and the os path of his/her chosen certificate. Calls the login() function in the backend.py script,
    in order to check if the typed username and password are correct and if the chosen certificate has been issued by
    the Password Manager Application. If these are correct then the user can access his/her account.
    If not, he/she has 9 tries more to log in with time delay, else the Application will close.
    Also,the user is being informed about the errors and the remaining tries to login.
    Finally, the user will be informed if his/her account is safe or his/her saved passwords has been unauthorized changed
    :return: None
    """

    global tries, delay
    uName = uNameEL.get()
    usPswd = pwdEL.get()
    try:
        cert_path = filename
        status = backend.login(uName, usPswd, cert_path)

        if status != 1 and tries > 0:
            answer = backend.connect(uName)
            if answer == 1:
                showwarning("WARNING", "Non authorized password modification!!")
            elif answer == 0:
                showinfo("Password Integrity", "Everything seems to be as you left!")
            enter_app()
        elif tries == 0:
            showwarning("Login", "Can't authenticate!\nClosing application!")
            rootA.destroy()

        else:
            tries -= 1
            showwarning("Login", "Can't login! Tries left " + str(tries) + "\nDelaying your entry..")
            time.sleep(delay)
            delay += 5

    except NameError:
        showinfo("Login", "Load your certificate!")


def goto_start():
    """
    When the user clicks on the Cancel button in the Sign Up page, it calls this function which simply closes the
    Sign Up page and opens the Start Page.
    :return: None
    """

    roots.destroy()
    start_page()


def goto_start2():
    """
    When the user clicks on the Cancel button in the Log In page, it calls this function which simply closes the
    Log In page and opens the Start Page.
    :return: None
    """

    rootA.destroy()
    start_page()


def goto_signup():
    """
    When the user clicks on the Sign Up button in the Start page, it calls this function which simply closes the
    Start page and opens the Sign Up Page.
    :return: None
    """

    first.destroy()
    signup_page()


def goto_login():
    """
    When the user clicks on the Log In button in the Start page, it calls this function which simply closes the
    Start page and opens the Log In Page.
    :return: None
    """

    first.destroy()
    login_page()


def enter_app():
    """
    When the user clicks on the Log In button in the Log In page, it calls this function which simply closes the
    Log In page and opens the Entries Page.
    :return: None
    """
    rootA.destroy()
    entries_page()


def entries_page():
    """
    This function construct the main window of the Application, where the user can use the services of the Password Manager.
    The user has the ability to add an entry (Domain, Username, Password, Comment), edit or delete an  entry.
    Also the passwords of each entry are saved encrypted, so in order to read (decrypt) a password the user can click on the 'Show Password'
    button.
    :return:
    """

    global e1, e2, e3, e4
    global list1
    global domain_text, username_text, password_text, comment_text
    global window

    window = Tk()

    window.wm_title("Password Manager")

    l1 = Label(window, text="Domain")
    l1.grid(row=0, column=0)

    l2 = Label(window, text="Username")
    l2.grid(row=0, column=2)

    l3 = Label(window, text="Password")
    l3.grid(row=1, column=0)

    l4 = Label(window, text="Comment")
    l4.grid(row=1, column=2)

    l5 = Label(window, text="The password's length must be 16!")
    l5.grid(row=8, column=1)

    domain_text = StringVar()
    e1 = Entry(window, textvariable=domain_text)
    e1.grid(row=0, column=1)

    username_text = StringVar()
    e2 = Entry(window, textvariable=username_text)
    e2.grid(row=0, column=3)

    password_text = StringVar()
    e3 = Entry(window, textvariable=password_text, show='*')
    e3.grid(row=1, column=1)

    comment_text = StringVar()
    e4 = Entry(window, textvariable=comment_text)
    e4.grid(row=1, column=3)

    list1 = Listbox(window, height=6, width=35)
    list1.grid(row=2, column=0, rowspan=6, columnspan=2)

    sb1 = Scrollbar(window)
    sb1.grid(row=2, column=2, rowspan=6)

    list1.configure(yscrollcommand=sb1.set)
    sb1.configure(command=list1.yview)

    list1.bind('<<ListboxSelect>>', get_selected_row)

    b1 = Button(window, text="View all", width=12, command=view_command)
    b1.grid(row=2, column=3)

    b2 = Button(window, text="Show password", width=12, command=decrypt_command)
    b2.grid(row=3, column=3)

    b3 = Button(window, text="Add entry", width=12, command=add_command)
    b3.grid(row=4, column=3)

    b4 = Button(window, text="Update selected", width=12, command=update_command)
    b4.grid(row=5, column=3)

    b5 = Button(window, text="Delete selected", width=12, command=delete_command)
    b5.grid(row=6, column=3)

    b6 = Button(window, text="Close", width=12, command=close_app)
    b6.grid(row=7, column=3)

    window.mainloop()


def close_app():
    """
    This function is called when the user clicks on the Close button in the Entries Page.
    The function calls the close function to calculate and save the encrypted signatures of the domain passwords.
    Then, it terminates the Application.
    :return: None
    """
    backend.close()
    window.destroy()


def get_selected_row(event):
    """
    This function shows in the textboxes the selected entry.
    """
    global selected_tuple
    index = list1.curselection()[0]
    selected_tuple = list1.get(index)
    e1.delete(0, END)
    e1.insert(END, selected_tuple[1])
    e2.delete(0, END)
    e2.insert(END, selected_tuple[2])
    e3.delete(0, END)
    e3.insert(END, selected_tuple[3])
    e4.delete(0, END)
    e4.insert(END, selected_tuple[4])


def view_command():
    """
    When the user clicks on the 'View All' button it calls this function, which shows in the listbox all the
    entries of the user.
    """

    list1.delete(0, END)
    for row in backend.view():
        list1.insert(END, row)


def decrypt_command():
    """
    When the user clicks on the 'Show Password' button it calls this function, which shows the decrypted password
     in a pop-up window.
    """

    decr_msg = backend.decryption(password_text.get())
    showinfo("Your password is:", decr_msg)


def add_command():
    """
    When the user clicks on the 'Add Entry' button it calls this function, which takes the entered data
    (Domain, Username, Password, Comment) and stores them in a database.
    """

    status = backend.insert(domain_text.get(), username_text.get(), password_text.get(), comment_text.get())
    if status == 1:
        showerror("Invalid password","The password must be 16 bit length!")
    else:
        list1.delete(0, END)
        list1.insert(END, (domain_text.get(), username_text.get(), password_text.get(), comment_text.get()))


def update_command():
    """
    When the user clicks on the 'Update selected' button it calls this function, which stores the edited data of the
    selected entry.
    """

    backend.update(selected_tuple[0], domain_text.get(), username_text.get(), password_text.get(), comment_text.get())


def delete_command():
    """
    When the user clicks on the 'Delete selected' button it calls this function, which deletes the selected entry.
    """

    backend.delete(selected_tuple[0])


start_page()  # Starts the Application
