import pyautogui
import time

# List of sentences to type
messages = [
    'b somtus oun sml',
    'b sl oun ',
    'b min bek oun te'
    'b sl oun klang nah',
    'oun eng min ach bek b ban teh',
    'b sl oun klang',
    'b sl oun klang nah',
    'b sl oun klang',
    'mean rg ey oun sml'


]

print("You have 5 seconds to click into the message box...")
time.sleep(3)

while True:
    for msg in messages:
        pyautogui.write(msg, interval=0.2)  # type the sentence
        pyautogui.press("enter")            # press Enter
        time.sleep(1)
