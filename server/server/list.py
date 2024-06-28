import tkinter as tk
from ttkbootstrap import Style

def list():
    with open('sites_bloqués.txt','r+') as site:
        content= site.readlines()
        if '\n' in content:
            content.remove('\n')
        site.seek(0)
        site.writelines(content)
        site.truncate()
    return content


# Mise à jour de la liste des sites bloqués
def update(blocked):
    listbox.delete(0,tk.END)
    blocked = list()
    for item in blocked:
        listbox.insert(tk.END, item)


# Suppression d'un site du liste
def remove_selected_item():
    choice = listbox.curselection()
    if choice:
        position = choice[0]
        listbox.delete(position)
        blocked[position] = ''
    with open('sites_bloqués.txt', 'w') as site:
        for element in blocked:
            site.write(element)
    update(blocked)

# Ajout d'un site en utilisant 'Enter'
def _input(Event:None):
    txt = input.get()
    txt = '\n' + txt
    with open('sites_bloqués.txt','a') as site:
        site.write(txt)
    update(blocked)

# Ajout d'un site utilisant un bouton
def Input():
    txt = input.get()
    txt = '\n' + txt
    with open('sites_bloqués.txt','a') as site:
        site.write(txt)
    update(blocked)

#-----------Fenêtre---------
root = tk.Tk()
root.title("Sites bloqués")
root.config(bg='#24282A')
root.geometry('300x287')
frame = tk.Frame(
    master=root,
    bg="#24282A"
)
frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

# Liste des site bloqués
listbox = tk.Listbox(master=frame, 
                     width=30, 
                     height=10, 
                     bg='#2C302C', 
                     fg='white', 
                     bd=0, 
                     highlightbackground='#145E02', 
                     highlightcolor='#145E02',
                     selectbackground='#145E02')
listbox.pack(fill=tk.Y)

blocked = list()
for item in blocked:
    listbox.insert(tk.END, item)

# Input pour ajout
input = tk.Entry(frame, width=20)
input.pack(padx=10, pady=10)
input.bind('<Return>', _input)

Button_Ajout = tk.Button(
    master=frame,
    text="Ajouter",
    height=1,
    width=20,
    bg='#145E02',
    fg='white',
    bd=0,
    activebackground="#24282A",
    activeforeground='white',
    command= Input
)
Button_Ajout.pack(side=tk.LEFT)

Button_Supprimer = tk.Button(
    master=frame,
    text="Supprimer",
    height=1,
    width=20,
    bg='#145E02',
    fg= 'white',
    bd=0,
    activebackground='#24282A',
    activeforeground='white',
    command=remove_selected_item
)
Button_Supprimer.pack(side=tk.RIGHT)

root.mainloop()