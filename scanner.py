from datetime import date
import time
import os
import sys
import optparse
import scapy.all as scapy


class Mitm:

    def __init__(self):
        self.parser_object = optparse.OptionParser()
        self.target = None
        self.day = None
    def GET_USER_INPUTS(self):

        self.parser_object.add_option("-t","--target",
                                      dest="target",
                                      help="Scanner Ip address")

        return  self.parser_object.parse_args()[0]

    def CONFIG_SCANNER(self):
        try:
            self.target = self.GET_USER_INPUTS().target
            self.scanner_start_time = time.strftime("%d:%m:%Y -- %H:%M:%S")
            self.ARP_REQUEST_PACKET = scapy.ARP(pdst=self.target)
            self.BROADCAST_PACKET = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            self.COMBINED_PACKET = self.BROADCAST_PACKET / self.ARP_REQUEST_PACKET
            self.result = scapy.srp(self.COMBINED_PACKET,verbose= False,timeout=1)[0]
            self.scanner_finish_time = time.strftime("%d:%m:%Y -- %H:%M:%S")
        except KeyboardInterrupt:
            print(" [ CTRL + C ] Detected !!!")
            time.sleep(2)
            sys.exit()
        except Exception as e:
            print(f"Bir Hata oluştu \n Hata Türü : {e}")
            time.sleep(2)
            sys.exit()

        return  self.result

    def SHOW_SCANNER(self):
        self.host_count = len(self.result)
        for i in range(len(self.result)):
            print(self.result[i][1].psrc,end=" : ")
            print(self.result[i][1].hwsrc,end="")
            print()
        if self.host_count == 0:
            print("Aktif Cihaz Bulunamadı...")
            sys.exit()
        else:
            print(f"Ağda {self.host_count} Cihaz Tespit Edildi!")
        print(f"Tarama Başlangıc Süresi : {self.scanner_start_time}")
        print(f"Tarma Bitiş Süresi      : {self.scanner_finish_time}")

    def REPORT_SCANNER(self):
        wkday = date.today().isoweekday()
        if wkday == 1:
            self.day = "Pazartesi"
        elif wkday == 2:
            self.day = "Salı"
        elif wkday == 3:
            self.day = "Çarşamba"
        elif wkday == 4:
            self.day = "Perşembe"
        elif wkday == 5:
            self.day ="Cuma"
        elif wkday == 6:
            self.day = "Cumartesi"
        else:
            self.day = "Pazar"
        file = open("report.txt", "a+",encoding="utf-8")
        file.writelines(f"""Tarama Yapan Cihaz Ip Addresi : {self.result[0][1].pdst} 
Tarama Yapan Cihaz Mac Adresi : {self.result[0][1].hwdst}
Tarama Yapılan Tarih          : {time.strftime("%Y:%m:%d - %H:%M:%S")}  {self.day}
Hedef Ip Adresi               : {self.result[0][1].psrc}
Hedef Mac Adresi              : {self.result[0][1].hwsrc}
Tarama Türü                   : ARP SORGUSU
Tarama Başlanıç Tarihi        : {self.scanner_start_time}  {self.day}
Tarama Bitiş Tarihi           : {self.scanner_finish_time}  {self.day}
                <<<<  Tarama Sonuçları >>>>
[ ID ]     [ IP ADRES ]     [ MAC ADRES ]
""")
        self.host_count = 0
        for i in range(len(self.result)):
            file.writelines(f""" {self.host_count+1} :     {self.result[i][1].psrc} :     {self.result[i][1].hwsrc}\n""")
            self.host_count+=1
        file.close()

    def CLEAR_TERMINAL(self):
        if os.name == 'posix':
            os.system("clear")
        elif os.name == 'nt':
            os.system('cls')
            os.system('color a')
            os.system("title NETWORK SCANNER")
        else:
            pass
if __name__ == '__main__':
    m = Mitm()
    m.CLEAR_TERMINAL()
    m.CONFIG_SCANNER()
    m.SHOW_SCANNER()
    m.REPORT_SCANNER()