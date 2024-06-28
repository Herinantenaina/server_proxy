import subprocess
import sys
import os
from tkinter import *
import tkinter as tk
from PIL import Image, ImageTk

def center_window(window:Tk):
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()

    x = (screen_width - window.winfo_reqwidth()+50) // 2
    y = (screen_height - window.winfo_reqheight()-50) // 2

    window.geometry("+{}+{}".format(x, y))

loading_window = Tk()
loading_window.overrideredirect(True)
loading_window.geometry("300x131")
center_window(loading_window)


frame = Frame(loading_window, highlightbackground='#145E02', highlightthickness=1)
frame.pack()
image = tk.PhotoImage(file='img/loading.png')
splash_label = Label(frame, font=18, image=image, compound='center',highlightcolor="red")
splash_label.pack(fill=X)
 


python_path = sys.executable
def main():
    python_exe = sys.executable
    python_path = os.path.dirname(python_exe)
    os.environ['PATH'] += os.pathsep + python_path
    loading_window.destroy()
    subprocess.Popen(['python', 'proxy_server.py'])
  
loading_window.after(1500, main)
mainloop()