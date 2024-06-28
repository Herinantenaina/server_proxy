from tkinter import *
import tkinter as tk
from ttkbootstrap import Style
import ttkbootstrap as ttk
import subprocess
import sys
import os

python_exe = sys.executable
python_path = os.path.dirname(python_exe)
os.environ['PATH'] += os.pathsep + python_path

def start():
    global connected
    connected = not connected
    
    if connected:
        launch_script()
        state.config(text='Connecté')
        lancer.config(text='Arrêter')
    else:
        stop_script()
        state.config(text='Non connecté')
        lancer.config(text='Lancer')

def center_window(window:Tk):
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width - window.winfo_reqwidth()-500) // 2
    y = (screen_height - window.winfo_reqheight()-500) // 2
    window.geometry("+{}+{}".format(x, y))

python_path = sys.executable
def launch_script():
    global process
    process = subprocess.Popen([python_path, "https_server.py"])

def stop_script():
    print('[SERVEUR]  Arrêt du serveur')
    process.terminate()

def list_bloque():
    subprocess.Popen(["python", 'list.py'])
    val = state.cget("text")
    if val == 'Connecté':
        stop_script()
        state.config(text='Non connecté')
        lancer.config(text='Lancer')

    print('Modification de la liste des sités bloqués')

root = tk.Tk()
root.overrideredirect(True)
root.attributes('-topmost', True)
root.geometry('700x550')
center_window(root)
style = Style("cyborg")
root.configure(background='#24282A')

def minim():
    root.overrideredirect(0)
    root.wm_state("iconic")
    root.overrideredirect(1)

#-----------------------------
#---Title bar configuration---
#-----------------------------
style.configure('titleBar.TFrame',  background ='#145E02')
title_bar = ttk.Frame(root, padding="20 0 0 0",style= 'titleBar.TFrame')
title_bar.pack(fill=X)

# Title
style.configure('title.Label', font=('Transitional', 15),foreground='#FFFFFF', background='#145E02')
title = ttk.Label(title_bar, text="Serveur proxy", style='title.Label')
title.pack(side = LEFT)

# Close button
CloseImage = tk.PhotoImage(file='img/Close.png')
style.configure('Close.TButton', image=CloseImage, borderwidth=0, background='#145E02',focuscolor='')
closeButton = ttk.Button(title_bar, command=(root.destroy), style='Close.TButton', padding='10 10 10 10')
closeButton.pack( side = RIGHT,anchor= NE, fill=Y)

# Minimize button
minimImage = tk.PhotoImage(file="img/Minimize.png")
style.configure('min.TButton', image=minimImage, background='#145E02', borderwidth=0,focuscolor='')
minButton = ttk.Button(title_bar, command=minim, padding='10 10 10 10', style='min.TButton')
minButton.pack(side= RIGHT,anchor= NE)

#title bar get position.
def get_pos(event):
    global xwin
    global ywin
    xwin = event.x
    ywin = event.y

#title bar drag functon.
def drag(event):
    root.geometry(f"+{event.x_root - xwin}+{event.y_root - ywin}")

title_bar.bind("<B1-Motion>", drag)
title_bar.bind("<Button-1>", get_pos)
title.bind("<Button-1>", get_pos)


#----------------------------
#-----Body configuration-----
#----------------------------
style.configure('body.TFrame', background='#24282A')##24282A
body = ttk.Frame(root, style='body.TFrame')
body.pack(fill=BOTH, expand=TRUE)


# #Title
style.configure('title.TLabel', font=("Comic Sans MS", 20), foreground='#FFFFFF', background='#24282A', anchor='center', justify='center', padding='0 20 0 0')
title = ttk.Label(body, text= "Naviguer en toute sécurité.", style='title.TLabel')
title.pack(pady=10)

# #Icon shield
shieldImage = tk.PhotoImage(file='img/Shield.png')
style.configure('shield.TLabel', image= shieldImage, background='#24282A', anchor='center', justify='center', padding='0 10 0 0')
shield = ttk.Label(body, style= 'shield.TLabel')
shield.pack(pady=30)

# State
style.configure("state.TLabel", background='#24282A',padding='0 50 0 0')
state = ttk.Label(body, text='Non connecté', style='state.TLabel')
state.pack()

connected = False

#Button lancer
style.configure('_.TFrame', background='#24282A')
frame_lancer = ttk.Frame(body, style='_.TFrame')
frame_lancer.pack()
style.configure('lancer.TButton', bordercolor='#145E02', background= '#2C302C', relief='solid', foreground='#FFFFFF', focuscolor='',font=("Arial",20), width=12, height=5)
lancer = ttk.Button(frame_lancer, text='Lancer', bootstyle="success", style='lancer.TButton', command=start)
lancer.pack()

# Button blocked website
style.configure('block.TButton', foreground='white', background='#24282A', borderwidth=0,activebackground="#24282A")
bloque = ttk.Button(root, text='Liste des sites bloqués', style='block.TButton', command= list_bloque)
bloque.pack(side=tk.LEFT)
root.mainloop()