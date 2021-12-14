import datetime
def add_log(log):
    now = datetime.datetime.now().strftime("%y%m%d")
    with open(f'logs/{now}.txt', 'a') as file:
        now = datetime.datetime.now().strftime("%y-%m-%d")
        file.write(f"{now} | {log}\n")
