# NexShell — Tools Directory

مجلد `tools/` هو المكان المخصص لحفظ **الأدوات والملفات** التي تريد مشاركتها مع الأهداف أثناء العمليات.

## الهيكل المقترح

```
tools/
├── linux/          — أدوات Linux (linpeas, pspy, socat, chisel...)
├── windows/        — أدوات Windows (winpeas, mimikatz, Rubeus...)
├── scripts/        — سكربتات مساعدة
└── loot/           — الملفات المستخرجة من الأهداف (يُكتب تلقائياً)
```

## الاستخدام

```bash
# مشاركة المجلد الافتراضي (tools/)
(NexShell)> plugins run local-file-sharer

# مشاركة قسم محدد
(NexShell)> plugins run local-file-sharer --dir tools/linux
(NexShell)> plugins run local-file-sharer --dir tools/windows

# مشاركة ملف واحد فقط
(NexShell)> plugins run local-file-sharer --file tools/linux/linpeas.sh

# رؤية المشاركات النشطة
(NexShell)> plugins run local-file-sharer --list
```

## أدوات شائعة للتنزيل

| الأداة | النظام | الوصف |
|--------|--------|-------|
| linpeas.sh | Linux | Linux Privilege Escalation |
| pspy | Linux | Process Spying (no root) |
| chisel | Linux/Win | TCP/UDP Tunneling |
| socat | Linux | Relay & Port Forward |
| winpeas.exe | Windows | Windows PrivEsc |
| mimikatz.exe | Windows | Credential Dumping |
| Rubeus.exe | Windows | Kerberos Attacks |
| SharpHound.exe | Windows | AD Enumeration |

## تحميل الأدوات (مثال)

```bash
# من داخل tools/linux/
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64
wget https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz
```

> ⚠️ **ملاحظة OPSEC:** لا تضع أدوات حساسة في `loot/` — هذا المجلد مخصص للبيانات المستخرجة فقط.
