def dangerous_eval(user_input):
    # Nguy hiểm vì eval không kiểm soát đầu vào
    return eval(user_input)

def read_file(filename):
    with open(filename, 'r') as f:
        data = f.read()
    return data

def execute_code(code):
    exec(code)

if __name__ == "__main__":
    user_code = "print('Hello from eval')"
    dangerous_eval(user_code)
