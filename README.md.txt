Exercise 0: 

1.) Install VMWare to your machines.

2.) Copy and load the virtual machines (Kali Linux: [kali] and Ubuntu: [mobisec1234]) to VMWare.

3.) Setup environment with following machines:

i.) Client (Victim)

ii.) Server

iii.) Attacker

3.) Develop or copy client-server chat application and test (From our CpE 3151 exercise).

4.) Assume that the victim is compromised with a worm that operates as a sniffer and forward data packets to the Attacker PC. Accordingly, create an socket application that will receive the forwarded data packet and  display it on the terminal.

Exercise 1:

DNS Spoofing:  04. Advanced Network and System Security - lab - Network attacks - DNS spoofing-1.pdfDownload 04. Advanced Network and System Security - lab - Network attacks - DNS spoofing-1.pdf

Exercise 2:

In our sniffing exercise, we assumed that the target device is compromised with a worm that operates as a sniffer and forwards the sniffed data to the hackers computer. In this current exercise, while using the client-server chat application, sniffer program, and knowledge gained from the spoofing exercise in "Exercise 1", perform an attack such that a man-in-the-middle attacker is present to capture the message exchange between the client-server chat application. In this case, victim computers are no longer compromised with worm that operates as sniffer. 

Hint:
	Use three Virtual Machine, i.e., VM1 [Ubuntu]: client (target PC), VM2 	[Ubuntu]: server (target), VM3 [Kali]: MITM attacker.
	Sniffer program is running directly at the VM3 to view the packet data.
	Spoof the target PCs by initiating arpspoof command at VM3.

Other reference  hereLinks to an external site..

Submit (In PDF) the steps carried out in the conduct of the exercise, reflection and key take-aways. 


