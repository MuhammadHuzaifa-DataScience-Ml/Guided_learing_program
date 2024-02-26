import re

# Regular expression for a date in the format YYYY-MM-DD|2024-02-20 
date_pattern = re.compile(r'^[0-9]{4}-((0[13578]|(10|12))-(0[1-9]|[1-2][0-9]|3[0-1])|(02-(0[1-9]|[1-2][0-9]))|((0[469]|11)-(0[1-9]|[1-2][0-9]|30)))$')

# Regular expression for a CNIC number in the format 12345-6789012-3
cnic_pattern = re.compile(r'^\d{5}-\d{7}-\d$')

# Regular expression for a password with specific criteria Abc123@sea
password_pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).{8,}$')

# Example usage:
date_input = input("enter date:")
cnic_input = input("enter cnic:")
password_input = input("enter password:")

if date_pattern.match(date_input):
    print(f"{date_input} is a valid date.")
else:
    print(f"{date_input} is not a valid date.")

if cnic_pattern.match(cnic_input):
    print(f"{cnic_input} is a valid CNIC number.")
else:
    print(f"{cnic_input} is not a valid CNIC number.")

if password_pattern.match(password_input):
    print(f"{password_input} is a valid password.")
else:
    print(f"{password_input} is not a valid password.")