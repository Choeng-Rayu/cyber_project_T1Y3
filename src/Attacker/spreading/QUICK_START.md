# 📋 QUICK DEMO CHEAT SHEET

## 🎯 THE PLAN
1. VM2 (Victim) runs first - waits for infection
2. VM1 (Attacker) launches attack on VM2
3. VM2 shows infection + payload
4. Explain how spreading continues

---

## ⚡ COMMANDS TO RUN

### VM2 (Start First!)
```bash
cd Desktop
python demo_spreading.py --victim
```

### VM1 (Start Second!)
```bash
cd Desktop
python demo_spreading.py --attacker --target 192.168.1.100
```
**☝️ REPLACE 192.168.1.100 WITH YOUR VM2 IP!**

---

## 🗣️ WHAT TO SAY

### Opening (30 sec)
*"I'll demonstrate a network worm spreading from VM1 to VM2. It exploits SMB, executes a payload, and VM2 continues spreading."*

### During VM1 Attack (3 min)
- **Stage 1:** *"Scanning network for targets..."*
- **Stage 2:** *"Found open SMB port on VM2..."*
- **Stage 3:** *"Exploiting SMB to copy worm..."*
- **Stage 4:** *"Creating scheduled task for persistence..."*
- **Stage 5:** *"Executing payload on VM2..."*

### Show VM2 (1 min)
*"VM2 was infected, payload executed 'Hello World', firewall disabled, and now it's scanning for new targets to continue spreading."*

---

## 🎓 KEY CONCEPTS TO MENTION

1. **Exponential Spread** - Each infected machine infects others
2. **SMB Exploitation** - Like WannaCry/NotPetya
3. **Persistence** - Scheduled tasks survive reboots
4. **Payload** - Hello World proves infection
5. **Defense Evasion** - Disables firewall

---

## 🔧 QUICK FIXES

**No color?** Works anyway, just less pretty
**Can't ping VM2?** Check both VMs on same network
**Wrong IP?** Run `ipconfig` on VM2, use that IP
**Script error?** Try `python3` instead of `python`

---

## 💡 BACKUP PLAN

If demo fails technically:
1. Show the code in `demo_spreading.py`
2. Explain each function
3. Draw diagram: VM1 → VM2 → VM3
4. Discuss real worms (WannaCry)
5. Explain defenses

---

## ✅ SUCCESS = Teacher Sees

- ✓ Attacker scanning victim
- ✓ SMB exploitation
- ✓ Worm copying
- ✓ Payload execution ("Hello World")
- ✓ Spreading behavior

---

## 🚀 YOU'VE GOT THIS!

**Remember:**
- Start VM2 FIRST
- Use correct IP address
- Narrate while it runs
- Be confident!

Good luck! 🎉
