import tkinter as tk
import re
import math

# Function to calculate entropy
def calculate_entropy(password):
    length = len(password)
    possible_characters = 0

    if re.search(r'[a-z]', password):
        possible_characters += 26
    if re.search(r'[A-Z]', password):
        possible_characters += 26
    if re.search(r'\d', password):
        possible_characters += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        possible_characters += 33  # Approx common special characters

    if possible_characters == 0:
        return 0

    entropy = length * math.log2(possible_characters)
    return entropy

# Function to check strength
def check_strength(password):
    entropy = calculate_entropy(password)

    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
    length_ok = len(password) >= 8

    # Determine rating
    if entropy < 28 or not length_ok or sum([has_lower, has_upper, has_digit, has_special]) < 2:
        strength = "Weak"
        color = "red"
    elif 28 <= entropy < 36:
        strength = "Moderate"
        color = "orange"
    else:
        strength = "Strong"
        color = "green"

    return strength, entropy, color

# Event handler for button
def on_check():
    password = entry.get()
    strength, entropy, color = check_strength(password)
    result_label.config(text=f"{strength} (Entropy: {entropy:.2f} bits)", fg=color)

# Tkinter GUI
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("400x200")

tk.Label(root, text="Enter Password:", font=("Arial", 12)).pack(pady=10)
entry = tk.Entry(root, show="*", width=30, font=("Arial", 12))
entry.pack()

tk.Button(root, text="Check Strength", command=on_check, font=("Arial", 12)).pack(pady=10)

result_label = tk.Label(root, text="", font=("Arial", 12, "bold"))
result_label.pack(pady=10)

root.mainloop()
